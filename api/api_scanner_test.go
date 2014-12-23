package api

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"
)

const (
	testNSSCABundle = "testdata/nss.pem"
)

func newTestScanHandler(t *testing.T) (h http.Handler) {
	h, err := NewScanHandler(testNSSCABundle)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func newScanServer(t *testing.T) *httptest.Server {
	ts := httptest.NewServer(newTestScanHandler(t))
	return ts
}

func TestNewScanHandler(t *testing.T) {
	newTestScanHandler(t)
}

type scanTest struct {
	Domain             string
	Ip                 string
	Timeout            int
	ExpectedHTTPStatus int
	ExpectedSuccess    bool
	ExpectedErrorCode  int
}

var scanTests = []scanTest{
	{
		"google.com",
		"",
		0,
		200,
		true,
		0,
	},
	{
		"www.cnn.com",
		"",
		0,
		400,
		false,
		6000,
	},
}

func testScan(domain, ip string, timeout int, t *testing.T) (resp *http.Response, body []byte) {
	ts := newScanServer(t)
	defer ts.Close()
	req := new(ScanRequest)
	req.Domain = domain
	req.Ip = ip
	req.Timeout = timeout

	blob, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}

	resp, err = http.Post(ts.URL, "application/json", bytes.NewReader(blob))
	if err != nil {
		t.Fatal(err)
	}
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return
}

func TestScan(t *testing.T) {
	for i, test := range scanTests {
		resp, body := testScan(test.Domain, test.Ip, test.Timeout, t)
		if resp.StatusCode != test.ExpectedHTTPStatus {
			t.Errorf("Test %d: expected: %d, have %d", i, test.ExpectedHTTPStatus, resp.StatusCode)
			t.Fatal(resp.Status, test.ExpectedHTTPStatus, string(body))
		}

		message := new(Response)
		err := json.Unmarshal(body, message)
		if err != nil {
			t.Errorf("failed to read response body: %v", err)
			t.Fatal(resp.Status, test.ExpectedHTTPStatus, message)
		}

		if test.ExpectedSuccess != message.Success {
			t.Errorf("Test %d: expected: %v, have %v", i, test.ExpectedSuccess, message.Success)
			t.Fatal(resp.Status, test.ExpectedHTTPStatus, message)
		}
		if test.ExpectedSuccess == true {
			continue
		}

		if test.ExpectedErrorCode != message.Errors[0].Code {
			t.Errorf("Test %d: expected: %v, have %v", i, test.ExpectedErrorCode, message.Errors[0].Code)
			t.Fatal(resp.Status, test.ExpectedHTTPStatus, message)
		}
	}
}
