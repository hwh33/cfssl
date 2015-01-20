package main

import (
	"fmt"
	"net"
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
var scanFlags = []string{"short", "list", "family", "scanner"}
var scanFamilyRegexp, scannerRegexp *regexp.Regexp

func regexpLoop(familyFunc func(*scan.Family) error, scannerFunc func(*scan.Scanner) error) (err error) {
	if Config.family != "" {
		scanFamilyRegexp = regexp.MustCompile(Config.family)
	}
	if Config.scanner != "" {
		scannerRegexp = regexp.MustCompile(Config.scanner)
	}
	for _, scanFamily := range scan.AllFamilies {
		isMatch := true
		if Config.family != "" {
			isMatch = scanFamilyRegexp.MatchString(scanFamily.Name)
		}
		if isMatch {
			if Config.scanner == "" {
				err = familyFunc(scanFamily)
				if err != nil {
					return
				}
			}
			for _, scanner := range scanFamily.Scanners {
				if Config.scanner == "" || scannerRegexp.MatchString(scanner.Name) {
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
	scan.Short = Config.short
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
			var host string

			host, args, err = popFirstArgument(args)
			if err != nil {
				return
			}
			_, _, err = net.SplitHostPort(host)
			if err != nil {
				host = net.JoinHostPort(host, "443")
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
