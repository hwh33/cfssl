package api

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/log"
	"github.com/cloudflare/cfssl/scanner"
)

// ScanHandler accepts requests for a TLS scanning of a remote
// server and/or ip, and returns a report (or error)
type ScanHandler struct {
	scanner *scanner.Scanner
}

// NewScannerHandler creates a new scanner that uses the root bundle
// to scan TLS connections with a website.
func NewScanHandler(caBundleFile string) (http.Handler, error) {
	var err error

	h := new(ScanHandler)
	if h.scanner, err = scanner.NewScanner(caBundleFile); err != nil {
		return nil, err
	}

	log.Info("Scanner API ready")
	return HTTPHandler{h, "POST"}, nil
}

type ScanRequest struct {
	Domain  string `json:"domain"`
	Ip      string `json:"ip,omitempty"`
	Timeout int    `json:"timeout,omitempty"`
}

// Handle implements an http.Handler interface for the scan handler.
func (h *ScanHandler) Handle(w http.ResponseWriter, r *http.Request) error {
	log.Info("scan request received")

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return errors.NewBadRequest(err)
	}
	r.Body.Close()

	var req ScanRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
		return errors.NewBadRequest(err)
	}

	if req.Domain == "" {
		return errors.NewBadRequestString("missing required domain parameter")
	}

	result, err := h.scanner.Scan(req.Domain, req.Ip, req.Timeout)
	if err != nil {
		log.Debugf("failed to dial the domain: %v", err)
		return err
	}

	response := NewSuccessResponse(result)
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	err = enc.Encode(response)
	return err
}
