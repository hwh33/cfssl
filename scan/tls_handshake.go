package scan

import (
	"fmt"
	"net"

	"github.com/cloudflare/cfssl/scan/tls"
)

// TLSHandshake contains scanners testing host cipher suite negotiation
var TLSHandshake = &Family{
	Name:        "TLSHandshake",
	Description: "Scans for host's SSL/TLS version and cipher suite negotiation",
	Scanners: []*Scanner{
		{
			"CipherSuiteScanner",
			"Determines host's cipher suites accepted and prefered order",
			cipherSuiteScan,
		},
	},
}

func sayHello(host string, ciphers []uint16, vers uint16) (cipherIndex int, err error) {
	tcpConn, err := net.Dial(Network, host)
	if err != nil {
		return
	}
	conn := tls.Client(tcpConn, &tls.Config{MinVersion: vers, MaxVersion: vers, ServerName: host, CipherSuites: ciphers})
	serverCipher, serverVersion, err := conn.SayHello()
	conn.Close()
	if serverVersion != vers {
		err = fmt.Errorf("Server negotiated protocol version we didn't send: %s.", tls.Versions[vers])
		return
	}
	var cipherID uint16
	for cipherIndex, cipherID = range ciphers {
		if serverCipher == cipherID {
			return
		}
	}
	err = fmt.Errorf("Server negotiated ciphersuite we didn't send: %s.", tls.CipherSuites[serverCipher])
	return
}

type tlsVers uint16

func (v tlsVers) String() string {
	return tls.Versions[uint16(v)]
}

type cipherList []uint16

func (ciphers cipherList) String() (list string) {
	for _, cipher := range ciphers {
		list += fmt.Sprintf("%s(%#04x), ", tls.CipherSuites[cipher], cipher)
	}
	if len(list) > 2 {
		list = list[:len(list)-2]
	}
	return list
}
func (ciphers cipherList) Append(cipher uint16) {
	ciphers = append(ciphers, cipher)
}

type cipherVersionMap map[tlsVers]cipherList

func (m cipherVersionMap) Append(vers tlsVers, cipher uint16) {
	m[vers] = append(m[vers], cipher)
}
func (m cipherVersionMap) String() (list string) {
	for vers, ciphers := range m {
		list += vers.String() + ":\n\t"
		list += ciphers.String() + "\n"
	}
	if len(list) > 0 {
		list = list[:len(list)-1]
	}
	return
}

// cipherSuiteScan returns, by TLS Version, the sort list of cipher suites
// supported by the host
func cipherSuiteScan(host string) (grade Grade, output Output, err error) {
	ciphersByVersion := make(cipherVersionMap)
	var ciphers cipherList
	for cipherID := range tls.CipherSuites {
		ciphers = append(ciphers, cipherID)
	}
	var vers uint16
	for vers = tls.VersionSSL30; vers <= tls.VersionTLS12; vers++ {
		for {
			cipherIndex, err := sayHello(host, ciphers, vers)
			if err != nil {
				ciphers = append(ciphers, ciphersByVersion[tlsVers(vers)]...)
				break
			}
			ciphersByVersion.Append(tlsVers(vers), ciphers[cipherIndex])
			ciphers = append(ciphers[:cipherIndex], ciphers[cipherIndex+1:]...)
		}

	}
	if _, ok := ciphersByVersion[tls.VersionSSL30]; ok {
		grade = Legacy
	}
	output = ciphersByVersion
	grade = Good
	return
}
