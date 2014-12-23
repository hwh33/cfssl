package main

import (
	"encoding/json"
	"fmt"

	"github.com/cloudflare/cfssl/scanner"
)

// Usage text of 'cfssl scan'
var scannerUsageText = `cfssl scan -- scan a remote website with TLS handshakes

Usage of scan:
        cfssl scan [-ca-bundle file] -domain domain_name -ip ip_address -timeout t

Flags:
`

// flags used by 'cfssl scan'
var scannerFlags = []string{"ca-bundle", "domain", "ip", "timeout"}

// scannerMain is the main CLI of scanner functionality.
func scannerMain(args []string) (err error) {
	s, err := scanner.NewScanner(Config.caBundleFile)
	if err != nil {
		return
	}
	report, err := s.Scan(Config.domain, Config.ip, Config.timeout)
	if err != nil {
		return
	}
	marshaled, err := json.Marshal(report)
	if err != nil {
		return
	}
	fmt.Printf("%s", marshaled)
	return
}

var CLIScanner = &Command{scannerUsageText, scannerFlags, scannerMain}
