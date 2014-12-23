package scanner

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"time"

	"github.com/cloudflare/cfssl/errors"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
)

type Scanner struct {
	RootPool *x509.CertPool
}

type Report struct {
	Certs    []*x509.Certificate `json:"-"`
	Expires  *time.Time          `json:"expires"`
	Errors   []string            `json:"errors"`
	Warnings []string            `json:"warnings"`
	// TODO(zi): browser ubiquity, more to come
}

func NewScanner(caBundleFile string) (*Scanner, error) {
	log.Debug("Scanner loads CA bundle: ", caBundleFile)
	caBundlePEM, err := ioutil.ReadFile(caBundleFile)
	if err != nil {
		log.Errorf("root bundle failed to load: %v", err)
		return nil, errors.New(errors.RootError, errors.ReadFailed, err)
	}

	s := &Scanner{
		RootPool: x509.NewCertPool(),
	}

	roots, err := helpers.ParseCertificatesPEM(caBundlePEM)
	if err != nil {
		log.Errorf("failed to parse root bundle: %v", err)
		return nil, errors.New(errors.RootError, errors.ParseFailed, err)
	}

	for _, c := range roots {
		s.RootPool.AddCert(c)
	}

	return s, nil
}

// Scan scans the endpoint to produce a TLS status report.
func (s *Scanner) Scan(serverName, ip string, timeout int) (*Report, error) {
	config := &tls.Config{
		RootCAs:    s.RootPool,
		ServerName: serverName,
	}

	// Dial by IP if present
	var dialName string
	if ip != "" {
		dialName = ip + ":443"
	} else {
		dialName = serverName + ":443"
	}

	log.Debugf("Scan %s", dialName)

	// TODO: Replace the dial process with real scanning. :)
	dialer := &net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", dialName, config)
	if err != nil {
		log.Debugf("tls dial failed: %v", err)
		return nil, errors.New(errors.DialError, errors.Unknown, err)
	}

	report := new(Report)

	err = conn.VerifyHostname(serverName)
	if err != nil {
		log.Debugf("failed to verify hostname: %v", err)
		report.Errors = append(report.Errors, err.Error())
	}

	// get the cert chain
	connState := conn.ConnectionState()
	report.Certs = connState.PeerCertificates
	report.Expires = helpers.ExpiryTime(report.Certs)

	return report, nil
}
