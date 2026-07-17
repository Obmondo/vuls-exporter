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

// TestPush_ResolvesPayload verifies the exporter resolves each CVE to a
// distro-aware score/severity/link and pushes only that — no raw cveContents,
// no bulky Vuls fields — dropping CVEs the host distro never flagged.
func TestPush_ResolvesPayload(t *testing.T) {
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
					"redhat_api": [{"cvss3Score": 6.1, "cvss3Severity": "Moderate"}],
					"nvd": [{"cvss3Score": 7.8, "cvss3Severity": "HIGH", "cvss2Score": 6.9, "cwes": ["CWE-1"]}]
				}
			},
			"CVE-2099-9999": {
				"affectedPackages": [{"name": "util-linux", "notFixedYet": true}],
				"cveContents": {
					"redhat_api": [{"cvss3Score": 8.8, "cvss3Severity": "Important"}]
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

	// Raw vendor data and bulky fields must be gone; the payload is resolved.
	// CVE-2099-9999 is dropped because ubuntu never flagged it; family is no
	// longer sent (the exporter already resolved it).
	for _, gone := range []string{"cveContents", "references", "cpes", "cwes", "cvss2Score", "\"packages\"", "confidences", "drop me", "cveID", "redhat_api", "ubuntu_api", "nvd", "CVE-2099-9999", "family"} {
		if strings.Contains(received, gone) {
			t.Errorf("resolved payload still contains %q: %s", gone, received)
		}
	}

	var got reportResult
	if err := json.Unmarshal([]byte(received), &got); err != nil {
		t.Fatalf("unmarshal resolved payload: %v", err)
	}
	if got.ServerName != "host1" {
		t.Errorf("serverName = %q, want host1", got.ServerName)
	}
	cve, ok := got.ScannedCves["CVE-2016-2568"]
	if !ok {
		t.Fatalf("CVE missing from resolved payload: %s", received)
	}
	// Ubuntu's "low" wins the severity; the score falls back to NVD (ubuntu_api
	// has none); the link points at Ubuntu's advisory.
	if cve.Severity != "low" {
		t.Errorf("severity = %q, want low", cve.Severity)
	}
	if cve.Score != 7.8 {
		t.Errorf("score = %v, want 7.8", cve.Score)
	}
	if cve.Link != "https://ubuntu.com/security/CVE-2016-2568" {
		t.Errorf("link = %q, want ubuntu advisory", cve.Link)
	}
	if len(cve.AffectedPackages) != 1 || cve.AffectedPackages[0].Name != "util-linux" {
		t.Errorf("affected packages not preserved: %+v", cve.AffectedPackages)
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
