package scanner

import (
	"testing"
)

const (
	testCaBundle = "testdata/ca-bundle.pem"
)

func newScanner(t *testing.T) *Scanner {
	s, _ := NewScanner(testCaBundle)
	return s
}

func TestNewScanner(t *testing.T) {
	_, err := NewScanner(testCaBundle)
	if err != nil {
		t.Fatal(err)
	}
}

func TestScanSite(t *testing.T) {
	s := newScanner(t)
	r, err := s.Scan("google.com", "", 5)
	if err != nil {
		t.Fatal(err)
	}

	if len(r.Errors) != 0 {
		t.Fatalf("Unexpect errors: %v", r.Errors)
	}

	if len(r.Warnings) != 0 {
		t.Fatalf("Unexpect warnings: %v", r.Errors)
	}
}

func TestScanNonHttpsSite(t *testing.T) {
	s := newScanner(t)
	_, err := s.Scan("www.cnn.com", "", 5)
	if err == nil {
		t.Fatal("It should time-out")
	}
	_, err = s.Scan("www.foxnews.com", "", 5)
	if err == nil {
		t.Fatal("It should fail with Hostname verification")
	}
}
