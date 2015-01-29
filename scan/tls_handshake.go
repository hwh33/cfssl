package scan

import (
	"fmt"
	"net"

	"github.com/cloudflare/cf-tls"
)

// TLSHandshake contains scanners testing host cipher suite negotiation
var TLSHandshake = &Family{
	Name:        "TLSHandshake",
	Description: "Scans for host's SSL/TLS version and cipher suite negotiation",
	Scanners: []*Scanner{
		{
			"CipherSuite",
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
		err = fmt.Errorf("server negotiated protocol version we didn't send: %s", tls.Versions[vers])
		return
	}
	var cipherID uint16
	for cipherIndex, cipherID = range ciphers {
		if serverCipher == cipherID {
			return
		}
	}
	err = fmt.Errorf("server negotiated ciphersuite we didn't send: %s", tls.CipherSuites[serverCipher])
	return
}

type cipherList []uint16

func newCipherList() cipherList {
	ciphers := make(cipherList, 0, len(tls.CipherSuites))
	for cipherID := range tls.CipherSuites {
		ciphers = append(ciphers, cipherID)
	}
	return ciphers
}

func (ciphers cipherList) String() string {
	var list = "{"
	for _, cipherID := range ciphers {
		list += fmt.Sprintf("%s(%#04x), ", tls.CipherSuites[cipherID], cipherID)
	}
	if len(list) > 3 {
		list = list[:len(list)-2]
	}
	list += "}"
	return list
}

type cipherVersionMap map[uint16]cipherList

func (m cipherVersionMap) Append(vers uint16, cipher uint16) {
	m[vers] = append(m[vers], cipher)
}
func (m cipherVersionMap) String() (list string) {
	var vers uint16
	for vers = tls.VersionTLS12; vers >= tls.VersionSSL30; vers-- {
		if ciphers, ok := m[vers]; ok {
			list += tls.Versions[vers] + ": "
			list += ciphers.String() + "\n"
		}
	}
	if len(list) > 0 {
		list = list[:len(list)-1]
	}
	return
}
func (m cipherVersionMap) Describe() string {
	return "Lists of host's supported cipher suites based on SSL/TLS Version"
}

// cipherSuiteScan returns, by TLS Version, the sort list of cipher suites
// supported by the host
func cipherSuiteScan(host string) (grade Grade, output Output, err error) {
	ciphersByVersion := make(cipherVersionMap)
	ciphers := newCipherList()
	var vers uint16
	for vers = tls.VersionSSL30; vers <= tls.VersionTLS12; vers++ {
		for {
			cipherIndex, err := sayHello(host, ciphers, vers)
			if err != nil {
				ciphers = append(ciphers, ciphersByVersion[vers]...)
				break
			}
			ciphersByVersion.Append(vers, ciphers[cipherIndex])
			ciphers = append(ciphers[:cipherIndex], ciphers[cipherIndex+1:]...)
		}

	}
	if _, ok := ciphersByVersion[tls.VersionSSL30]; ok {
		grade = Legacy
	} else {
		grade = Good
	}
	output = ciphersByVersion
	return
}
