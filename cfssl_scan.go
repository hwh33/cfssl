package main

import (
	"fmt"
	"net"
	"regexp"

	"github.com/cloudflare/cfssl/scan"
)

var scanUsageText = `cfssl scan -- scan a host for issues
Usage of scan:
        cfssl scan [-verbose] [-family regexp] [-scanner regexp] HOST+
        cfssl scan -list [-verbose] [-family regexp] [-scanner regexp]

Arguments:
        HOST:    Host(s) to scan (including port)
Flags:
`
var scanFlags = []string{"verbose", "list", "family", "scanner"}

// regexpLoop iterates through each scan Family and Scanner registered in scan.AllFamilies.
// familyFunc is run on each Family with a name matching the family flag's regexp,
// then scannerFunc is run on each Scanner in that Family that matches the scanner flag's regexp
func regexpLoop(familyFunc func(*scan.Family) error, scannerFunc func(*scan.Scanner) error) (err error) {
	familyRegexp := regexp.MustCompile(Config.family)
	scannerRegexp := regexp.MustCompile(Config.scanner)

	for _, family := range scan.AllFamilies {
		if familyRegexp.MatchString(family.Name) {
			err = familyFunc(family)
			if err != nil {
				return
			}
			for _, scanner := range family.Scanners {
				if scannerRegexp.MatchString(scanner.Name) {
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

var lineStart = regexp.MustCompile("(^|\n)")

// indentPrintln prints a multi-line block with the specified indentation.
func indentPrintln(indentation, block string) {
	fmt.Println(lineStart.ReplaceAllString(block, "${1}"+indentation))
}
func scanMain(args []string) (err error) {
	scan.Verbose = Config.verbose
	if Config.list {
		err = regexpLoop(
			func(f *scan.Family) error {
				fmt.Println(f)
				return nil
			},
			func(s *scan.Scanner) error {
				indentPrintln("\t", s.String())
				return nil
			},
		)
		if err != nil {
			return
		}
	} else {
		// Execute for each HOST argument given
		for len(args) > 0 {
			var host string
			host, args, err = popFirstArgument(args)
			if err != nil {
				return
			}
			// If no port is specified, default to 443
			_, _, err = net.SplitHostPort(host)
			if err != nil {
				host = net.JoinHostPort(host, "443")
			}

			fmt.Println("Scanning", host)
			err = regexpLoop(
				func(f *scan.Family) error {
					if scan.Verbose && Config.scanner == "" {
						fmt.Printf("[%s]\n", f.Name)
					}
					return nil
				},
				func(s *scan.Scanner) error {
					grade, output, err := s.Scan(host)
					fmt.Printf("%s: %s\n", s.Name, grade)
					if scan.Verbose && output != nil {
						indentPrintln("\t", output.String())
					}
					return err
				},
			)
			if err != nil {
				return
			}
		}
	}
	return
}

// CLIScan is a subcommand for scanning a host to identify any possible
// configuration issues
var CLIScan = &Command{scanUsageText, scanFlags, scanMain}
