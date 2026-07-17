package exporter

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Obmondo/vuls-exporter/config"
)

func TestPush_SendsFiles(t *testing.T) {
	var received []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = append(received, string(body))

		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	hostDir := filepath.Join(dir, "host1")
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(hostDir, "result.json"), `{"serverName":"host1"}`)

	cfg := &config.Config{
		ResultsDir: dir,
		Obmondo:    config.Obmondo{URL: srv.URL},
	}

	exp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := exp.Push(); err != nil {
		t.Fatal(err)
	}

	if len(received) != 1 {
		t.Fatalf("expected 1 request, got %d", len(received))
	}
	if received[0] != `{"serverName":"host1"}` {
		t.Errorf("unexpected body: %s", received[0])
	}
}

// TestPush_TrimsPayload verifies the exporter strips the bulky Vuls fields
// (references, CPEs, CWEs, CVSS2, package inventory) and pushes only what the
// API reads: serverName, and per-CVE the ID, affected packages, and the CVSS3
// score/severity/summary of each content source.
func TestPush_TrimsPayload(t *testing.T) {
	var received string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		received = string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	raw := `{
		"serverName": "host1",
		"family": "ubuntu",
		"release": "22.04",
		"packages": {"bash": {"name": "bash", "version": "5.1"}},
		"scannedCves": {
			"CVE-2016-2568": {
				"cveID": "CVE-2016-2568",
				"confidences": [{"score": 100}],
				"affectedPackages": [
					{"name": "util-linux", "notFixedYet": false, "fixState": "fixed", "extra": "drop me"}
				],
				"cveContents": {
					"ubuntu_api": [{"cvss3Score": 0, "cvss3Severity": "low", "summary": "s", "references": [{"link": "x"}], "cpes": ["a"]}],
					"nvd": [{"cvss3Score": 7.8, "cvss3Severity": "HIGH", "cvss2Score": 6.9, "cwes": ["CWE-1"]}]
				}
			}
		}
	}`

	dir := t.TempDir()
	hostDir := filepath.Join(dir, "host1")
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(hostDir, "result.json"), raw)

	exp, err := New(&config.Config{ResultsDir: dir, Obmondo: config.Obmondo{URL: srv.URL}})
	if err != nil {
		t.Fatal(err)
	}
	if err := exp.Push(); err != nil {
		t.Fatal(err)
	}

	// Bulky and redundant fields must be gone. cveID is dropped because it is
	// already the scannedCves map key.
	for _, gone := range []string{"references", "cpes", "cwes", "cvss2Score", "\"packages\"", "confidences", "drop me", "cveID"} {
		if strings.Contains(received, gone) {
			t.Errorf("trimmed payload still contains %q: %s", gone, received)
		}
	}

	// The CVE is still addressable by its map key.
	if !strings.Contains(received, "CVE-2016-2568") {
		t.Errorf("trimmed payload lost the CVE map key: %s", received)
	}

	// Required fields must survive and round-trip to the API's shape.
	var got slimResult
	if err := json.Unmarshal([]byte(received), &got); err != nil {
		t.Fatalf("unmarshal trimmed payload: %v", err)
	}
	if got.ServerName != "host1" {
		t.Errorf("serverName = %q, want host1", got.ServerName)
	}
	if got.Family != "ubuntu" {
		t.Errorf("family = %q, want ubuntu (needed for the API's distro logic)", got.Family)
	}
	cve, ok := got.ScannedCves["CVE-2016-2568"]
	if !ok {
		t.Fatalf("CVE missing from trimmed payload: %s", received)
	}
	if len(cve.AffectedPackages) != 1 || cve.AffectedPackages[0].Name != "util-linux" {
		t.Errorf("affected packages not preserved: %+v", cve.AffectedPackages)
	}
	if s := cve.CveContents["nvd"][0].Cvss3Score; s != 7.8 {
		t.Errorf("nvd cvss3Score = %v, want 7.8", s)
	}
	if sev := cve.CveContents["ubuntu_api"][0].Cvss3Severity; sev != "low" {
		t.Errorf("ubuntu_api severity = %q, want low", sev)
	}
}

func TestPush_NoFiles(t *testing.T) {
	cfg := &config.Config{
		ResultsDir: t.TempDir(),
		Obmondo:    config.Obmondo{URL: "http://unused"},
	}

	exp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := exp.Push(); err != nil {
		t.Fatal("expected no error for empty dir")
	}
}

func TestPush_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	hostDir := filepath.Join(dir, "host1")
	if err := os.MkdirAll(hostDir, 0755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(hostDir, "result.json"), `{}`)

	cfg := &config.Config{
		ResultsDir: dir,
		Obmondo:    config.Obmondo{URL: srv.URL},
	}

	exp, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if err := exp.Push(); err == nil {
		t.Fatal("expected error for 500 response")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
}
