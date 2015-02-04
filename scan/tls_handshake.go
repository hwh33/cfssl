package scan

import (
	"fmt"
	"net"
	"strings"

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
	conn := tls.Client(tcpConn, &tls.Config{MinVersion: vers, MaxVersion: vers, ServerName: host, CipherSuites: ciphers, SessionTicketsDisabled: true, ClientSessionCache: nil})
	serverCipher, serverVersion, err := conn.SayHello()
	conn.Close()
	if err != nil {
		return
	}
	if serverVersion != vers {
		err = fmt.Errorf("server negotiated protocol version we didn't send: %s", tls.Versions[serverVersion])
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
func allCiphersIDs() []uint16 {
	ciphers := make([]uint16, 0, len(tls.CipherSuites))
	for cipherID := range tls.CipherSuites {
		ciphers = append(ciphers, cipherID)
	}
	return ciphers
}

type cipherVersions struct {
	cipherID uint16
	versions []uint16
}
type cipherVersionList []cipherVersions

func (cvList cipherVersionList) String() string {
	cvStrings := make([]string, len(cvList))
	for i, c := range cvList {
		versStrings := make([]string, len(c.versions))
		for j, vers := range c.versions {
			versStrings[j] = tls.Versions[vers]
		}
		cvStrings[i] = fmt.Sprintf("%s\t%s", tls.CipherSuites[c.cipherID], strings.Join(versStrings, ", "))
	}
	return strings.Join(cvStrings, "\n")
}
func (cvList cipherVersionList) Describe() string {
	return "Lists of host's supported cipher suites based on SSL/TLS Version"
}

// cipherSuiteScan returns, by TLS Version, the sort list of cipher suites
// supported by the host
func cipherSuiteScan(host string) (grade Grade, output Output, err error) {
	var cvList cipherVersionList
	allCiphers := allCiphersIDs()
	var vers uint16
	for vers = tls.VersionTLS12; vers >= tls.VersionSSL30; vers-- {
		ciphers := make([]uint16, len(allCiphers))
		copy(ciphers, allCiphers)
		for len(ciphers) > 0 {
			cipherIndex, err := sayHello(host, ciphers, vers)
			if err != nil {
				break
			}
			if vers == tls.VersionSSL30 {
				grade = Legacy
			}
			cipherID := ciphers[cipherIndex]
			for i, c := range cvList {
				if cipherID == c.cipherID {
					cvList[i].versions = append(c.versions, vers)
					goto exists
				}
			}
			cvList = append(cvList, cipherVersions{cipherID, []uint16{vers}})
		exists:
			ciphers = append(ciphers[:cipherIndex], ciphers[cipherIndex+1:]...)
		}
	}
	if grade != Legacy && len(cvList) > 0 {
		grade = Good
	}
	output = cvList
	return
}
