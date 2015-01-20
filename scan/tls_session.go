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
	cache        map[string][]*tls.ClientSessionState
	inverseCache map[*tls.ClientSessionState][]string
}

func newSessionCache() *sessionCache {
	return &sessionCache{make(map[string][]*tls.ClientSessionState), make(map[*tls.ClientSessionState][]string)}
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
	s.inverseCache[cs] = append(s.inverseCache[cs], sessionKey)
}
func (s *sessionCache) String() (ret string) {
	for cs, sessionKeys := range s.inverseCache {
		ret += fmt.Sprintf("%p", cs) + ": "
		for _, key := range sessionKeys {
			ret += fmt.Sprint(key) + ", "
		}
	}
	if len(ret) > 2 {
		ret = ret[:len(ret)-2]
	}
	return
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
		if len(port) == 0 {
			port = "443"
		}
		host = net.JoinHostPort(ip.String(), port)
		var conn *tls.Conn
		conn, err = tls.Dial(Network, host, config)
		if err != nil {
			return
		}
		conn.Close()
		if len(sessions.inverseCache) != 1 {
			return
		}
	}
	grade = Good
	return
}
