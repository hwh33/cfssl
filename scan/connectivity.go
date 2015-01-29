package scan

import (
	"crypto/tls"
	"errors"
	"net"
)

// Connectivity contains scanners testing basic connectivity to the host
var Connectivity = &Family{
	Name:        "Connectivity",
	Description: "Scans for basic connectivity with the host through DNS and TCP/TLS dials",
	Scanners: []*Scanner{
		{
			"DNSLookup",
			"Host can be resolved through DNS",
			dnsLookupScan,
		},
		{
			"Dial",
			"Host accepts TCP connection",
			dialScan,
		},
		{
			"TLSDial",
			"Host can perform TLS handshake",
			tlsDialScan,
		},
	},
}

type lookupAddrs []string

func (addrs lookupAddrs) String() (ret string) {
	for _, addr := range addrs {
		ret += addr + ", "
	}
	if len(ret) > 2 {
		ret = ret[:len(ret)-2]
	}
	return
}

// dnsLookupScan tests that DNS resolution of the host returns at least one address
func dnsLookupScan(host string) (grade Grade, output Output, err error) {
	host, _, err = net.SplitHostPort(host)
	if err != nil {
		return
	}
	var addrs lookupAddrs
	addrs, err = net.LookupHost(host)
	if err != nil {
		return
	}
	if len(addrs) == 0 {
		err = errors.New("no addresses found for host")
	}
	grade, output = Good, addrs
	return
}

// TCPDialScan tests that the host can be connected to through TCP.
func dialScan(host string) (grade Grade, output Output, err error) {
	conn, err := Dialer.Dial(Network, host)
	if err != nil {
		return
	}
	conn.Close()
	grade = Good
	return
}

// TLSDialScan tests that the host can perform a TLS Handshake
func tlsDialScan(host string) (grade Grade, output Output, err error) {
	conn, err := tls.DialWithDialer(Dialer, Network, host, nil)
	if err != nil {
		return
	}
	conn.Close()
	grade = Good
	return
}
