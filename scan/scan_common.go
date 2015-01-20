package scan

import (
	"fmt"
	"net"
)

var (
	// Network is the default network to use.
	Network = "tcp"
	// Short removes long/expensive tests when set.
	Short  bool
	Dialer net.Dialer
)

// Grade gives a subjective rating of the host's success in a scan.
type Grade int

func (g Grade) String() string {
	switch g {
	case Bad:
		return "Bad"
	case Legacy:
		return "Legacy"
	case Good:
		return "Good"
	default:
		return "Invalid"
	}
}

const (
	// Bad describes a host with serious misconfiguration or vulnerability.
	Bad Grade = iota
	// Legacy describes a host with non-ideal configuration that maintains support for legacy clients.
	Legacy
	// Good describes host performing the expected state-of-the-art.
	Good
)

// Output is the result of a Scan, to be stored for potential use by later Scanners.
type Output interface {
	fmt.Stringer
}

// Scanner describes a type of scan to perform on a host.
type Scanner struct {
	Name        string
	Description string
	scan        func(host string) (Grade, Output, error)
}

// Scan defines the scan to be performed on the given host.
func (s *Scanner) Scan(host string) (grade Grade, output Output, err error) {
	grade, output, err = s.scan(host)
	if !Short {
		if err != nil {
			fmt.Printf("Scan failed with error: %s\n", err)
		}
		fmt.Printf("Received grade %s, with output: %v\n", grade, output)
	}
	history.Store(s.Name, host, output)
	return
}
func (s *Scanner) String() string {
	ret := fmt.Sprintf("\t%s", s.Name)
	if !Short {
		ret += fmt.Sprintf(":\n\t\t%s", s.Description)
	}
	return ret
}

type scannerHostPair struct{ scannerName, host string }
type scanHistory struct {
	history map[scannerHostPair][]Output
}

var history = &scanHistory{history: make(map[scannerHostPair][]Output)}

func (h *scanHistory) GetAll(scannerName, host string) (output []Output, ok bool) {
	output, ok = h.history[scannerHostPair{scannerName, host}]
	return
}
func (h *scanHistory) GetLatest(scannerName, host string) (output Output, ok bool) {
	outputs := h.history[scannerHostPair{scannerName, host}]
	if ok = len(outputs) > 0; !ok {
		return
	}
	output = outputs[len(outputs)-1]
	return
}
func (h *scanHistory) Store(scannerName, host string, output Output) {
	key := scannerHostPair{scannerName, host}
	h.history[key] = append(h.history[key], output)
}

// Family defines a set of related scans meant to be run together in sequence
type Family struct {
	// A short name of the Family
	Name string
	// Description gives a short description of the scans performed on the host
	Description string
	// Scanners contains a list of related Scanners to be run in sequence
	Scanners []*Scanner
}

func (f *Family) String() string {
	ret := fmt.Sprintf("%s", f.Name)
	if !Short {
		ret += fmt.Sprintf(":\n\t%s", f.Description)
	}
	return ret
}

// AllScanners contains all ScanFamilies and is intended as a comprehensive suite
var AllFamilies = []*Family{
	Connectivity,
	TLSHandshake,
	TLSSession,
}
