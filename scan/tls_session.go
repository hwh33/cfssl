package scan

import (
	"crypto/tls"
	"fmt"
	"net"
)

// TLSSession contains tests of host TLS Session Resumption via
// Session Tickets and Session IDs
var TLSSession = &Family{
	Name:        "TLSSessionScanners",
	Description: "Scans host's implementation of TLS session resumption using session tickets/session IDs",
	Scanners: []*Scanner{
		{
			"SessionResumeScanner",
			"Host is able to resume sessions accross all addresses.",
			sessionResumeScan,
		},
	},
}

// sessionCache is a mock ClientSessionCache used to record all stores (i.e. new session tickets)
type sessionCache struct {
	cache map[string][]*tls.ClientSessionState
}

func newSessionCache() *sessionCache {
	return &sessionCache{make(map[string][]*tls.ClientSessionState)}
}
func (s *sessionCache) Get(sessionKey string) (mostRecent *tls.ClientSessionState, ok bool) {
	states, ok := s.cache[sessionKey]
	if len(states) < 1 {
		return
	}
	mostRecent = states[len(states)-1]
	return
}
func (s *sessionCache) Put(sessionKey string, cs *tls.ClientSessionState) {
	s.cache[sessionKey] = append(s.cache[sessionKey], cs)
}

// SessionResumeScan tests that host is able to resume sessions accross all addresses.
func sessionResumeScan(host string) (grade Grade, output Output, err error) {
	var port string
	host, port, err = net.SplitHostPort(host)
	if err != nil {
		return
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return
	}
	sessions := newSessionCache()
	output = sessions
	config := &tls.Config{ClientSessionCache: sessions, InsecureSkipVerify: true}
	for _, ip := range ips {
		var addr string
		if ip.To4() != nil {
			addr = ip.String()
		} else {
			addr = "[" + ip.String() + "]"
		}
		if len(port) == 0 {
			port = ":443"
		} else if port[0] != ':' {
			port = ":" + port
		}
		fmt.Println()
		var conn *tls.Conn
		conn, err = tls.Dial(Network, addr+port, config)
		if err != nil {
			return
		}
		conn.Close()
		if len(sessions.cache) != 1 {
			return
		}
		for _, states := range sessions.cache {
			if len(states) != 1 {
				return
			}
		}
	}
	grade = Good
	return
}
