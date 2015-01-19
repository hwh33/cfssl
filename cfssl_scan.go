package main

import (
	"fmt"
	"regexp"

	"github.com/cloudflare/cfssl/scan"
)

var scanUsageText = `cfssl scan -- scan a host for issues

Usage of scan:
        cfssl scan [-short] [-scanfamily regexp] [-scanner regexp] HOST+
        cfssl scan -list [-short] [-scanfamily regexp] [-scanner regexp]

Arguments:
        HOST:    Host(s) to scan (including port)
Flags:
`

var scanFlags = []string{"short", "list", "scanner"}

var scanFamilyRegexp, scannerRegexp *regexp.Regexp

func init() {
	scan.Short = Config.short
	if Config.scanFamily != "" {
		scanFamilyRegexp = regexp.MustCompile(Config.scanFamily)
	}
	if Config.scanner != "" {
		scannerRegexp = regexp.MustCompile(Config.scanner)
	}
}

func regexpLoop(familyFunc func(*scan.Family) error, scannerFunc func(*scan.Scanner) error) (err error) {
	for _, scanFamily := range scan.AllFamilies {
		isMatch := true
		if Config.scanFamily != "" {
			isMatch = scanFamilyRegexp.MatchString(scanFamily.Name)
		}
		if isMatch {
			err = familyFunc(scanFamily)
			if err != nil {
				return
			}
			for _, scanner := range scanFamily.Scanners {
				if Config.scanFamily == "" || scannerRegexp.MatchString(scanner.Name) {
					err = scannerFunc(scanner)
					if err != nil {
						return
					}
				}
			}
		}
	}
	return
}
func scanMain(args []string) (err error) {
	var host string
	if Config.list {
		err = regexpLoop(
			func(f *scan.Family) error {
				fmt.Println(f)
				return nil
			},
			func(s *scan.Scanner) error {
				fmt.Println(s)
				return nil
			},
		)
		if err != nil {
			return err
		}
	} else {
		for len(args) > 0 {
			host, args, err = popFirstArgument(args)
			if err != nil {
				return
			}
			fmt.Printf("\nScanning %s:\n", host)
			err = regexpLoop(
				func(f *scan.Family) error {
					if !scan.Short {
						fmt.Printf("Scan with %s...\n", f.Name)
					}
					return nil
				},
				func(s *scan.Scanner) error {
					if !scan.Short {
						fmt.Printf("\tRunning Scan: %s...\n", s.Name)
					}
					_, _, err := s.Scan(host)
					return err
				},
			)
			if err != nil {
				return
			}
		}
	}
	return nil
}

// CLIScan is a subcommand for scanning a host to identify any possible
// configuration issues
var CLIScan = &Command{scanUsageText, scanFlags, scanMain}
