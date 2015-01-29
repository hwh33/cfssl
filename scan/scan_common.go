package scan

import (
	"fmt"
	"log"
	"net"
	"time"
)

var (
	// Network is the default network to use.
	Network = "tcp"
	// Dialer is the default dialer to use, with a 1s timeout.
	Dialer = &net.Dialer{Timeout: time.Second}
	// History contains the output of all scans that have been run.
	History = make(scanHistory)
	// Verbose flag indicates that additional scanner output should be printed.
	Verbose bool
)

// Grade gives a subjective rating of the host's success in a scan.
type Grade int

const (
	// Bad describes a host with serious misconfiguration or vulnerability.
	Bad Grade = iota
	// Legacy describes a host with non-ideal configuration that maintains support for legacy clients.
	Legacy
	// Good describes host performing the expected state-of-the-art.
	Good
)

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

// Output is the result of a scan, to be stored for potential use by later Scanners.
type Output interface {
	fmt.Stringer
}

// Scanner describes a type of scan to perform on a host.
type Scanner struct {
	// Name provides a short name for the Scanner.
	Name string
	// Description describes the nature of the scan to be performed.
	Description string
	// scan is the function that scans the given host and provides a Grade and Output.
	scan func(host string) (Grade, Output, error)
}

// Scan defines the scan to be performed on the given host.
func (s *Scanner) Scan(host string) (Grade, Output, error) {
	grade, output, err := s.scan(host)
	if err != nil {
		log.Printf("%s: %s", s.Name, err)
		return grade, output, err
	}
	History.store(s.Name, host, output)
	return grade, output, err
}
func (s *Scanner) String() string {
	ret := fmt.Sprintf("%s", s.Name)
	if Verbose {
		ret += fmt.Sprintf(": %s", s.Description)
	}
	return ret
}

type historyKey struct{ scanner, host string }

// scanHistory contains scanner outputs indexed by scanner and host.
type scanHistory map[historyKey][]Output

// GetAll returns all outputs associated with the scanner/host pair.
func (h scanHistory) GetAll(scanner, host string) (output []Output, ok bool) {
	output, ok = h[historyKey{scanner, host}]
	return
}

// GetLatest returns the latest output associated with the scanner/host pair.
func (h scanHistory) GetLatest(scanner, host string) (output Output, ok bool) {
	outputs := h[historyKey{scanner, host}]
	if ok = len(outputs) > 0; !ok {
		return
	}
	output = outputs[len(outputs)-1]
	return
}

// store appends a scanner output into the scanner/host pair's history.
func (h scanHistory) store(scanner, host string, output Output) {
	key := historyKey{scanner, host}
	h[key] = append(h[key], output)
}

// Family defines a set of related scans meant to be run together in sequence.
type Family struct {
	// Name is a short name for the Family.
	Name string
	// Description gives a short description of the scans performed on the host.
	Description string
	// Scanners is a list of scanners that are to be run in sequence.
	Scanners []*Scanner
}

func (f *Family) String() string {
	ret := fmt.Sprintf("%s", f.Name)
	if Verbose {
		ret += fmt.Sprintf(": %s", f.Description)
	}
	return ret
}

// AllFamilies contains each scan Family that is defined and is intended as a comprehensive suite.
var AllFamilies = []*Family{
	Connectivity,
	TLSHandshake,
	TLSSession,
}
