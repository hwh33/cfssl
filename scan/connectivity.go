package scan

import "net"

// Connectivity contains scanners testing basic connectivity to the host
var Connectivity = &Family{
	Name:        "Connectivity",
	Description: "Scans for basic connectivity with the host through DNS and TCP/TLS dials",
	Scanners: []*Scanner{
		{
			"DNSLookupScanner",
			"Host can be resolved through DNS",
			dnsLookupScan,
		},
		{
			"TCPDialScanner",
			"Host can be connected to through TCP",
			tcpDialScan,
		},
		{
			"TLSDialScanner",
			"Host can perform a TLS Handshake",
			tlsDialScan,
		},
	},
}

// dnsLookupScan tests that DNS resolution of the host returns at least one address
func dnsLookupScan(host string) (grade Grade, output Output, err error) {
	host, _, err = net.SplitHostPort(host)
	if err != nil {
		return
	}
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return
	}
	grade, output = Good, addrs
	return
}

// TCPDialScan tests that the host can be connected to through TCP.
func tcpDialScan(host string) (grade Grade, output Output, err error) {
	// TODO
	return
}

// TLSDialScan tests that the host can perform a TLS Handshake
func tlsDialScan(host string) (grade Grade, output Output, err error) {
	// TODO
	return
}
