package exporter

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Obmondo/vuls-exporter/config"
)

const (
	maxErrorBodySize   = 4096
	defaultHTTPTimeout = 30 * time.Second
)

// Exporter reads Vuls JSON result files and pushes them to the Obmondo API.
type Exporter struct {
	resultsDir string
	apiURL     string
	client     *http.Client
}

// slimResult is the subset of a Vuls scan result the Obmondo API actually
// consumes. A full Vuls result JSON also carries references, CPEs, CWEs, CVSS2
// data, exploits, mitigations and the host's package inventory — megabytes the
// API ignores. Decoding into this struct drops all of it (unknown JSON fields
// are skipped), so we push a fraction of the original payload.
type slimResult struct {
	ServerName  string             `json:"serverName"`
	Family      string             `json:"family,omitempty"`
	ScannedCves map[string]slimCVE `json:"scannedCves,omitempty"`
}

type slimCVE struct {
	// The CVE ID is the map key in scannedCves, so it is not repeated here.
	AffectedPackages []slimAffectedPackage       `json:"affectedPackages,omitempty"`
	CveContents      map[string][]slimCveContent `json:"cveContents,omitempty"`
}

type slimAffectedPackage struct {
	Name        string `json:"name"`
	NotFixedYet bool   `json:"notFixedYet,omitempty"`
	FixState    string `json:"fixState,omitempty"`
}

type slimCveContent struct {
	Cvss3Score    float64 `json:"cvss3Score,omitempty"`
	Cvss3Severity string  `json:"cvss3Severity,omitempty"`
	Summary       string  `json:"summary,omitempty"`
}

// New creates an Exporter with mTLS client if cert files are configured.
func New(cfg *config.Config) (*Exporter, error) {
	client := &http.Client{Timeout: cfg.Obmondo.Timeout.Duration}
	if client.Timeout == 0 {
		client.Timeout = defaultHTTPTimeout
	}

	if cfg.Obmondo.CertFile != "" && cfg.Obmondo.KeyFile != "" {
		tlsCfg, err := buildTLSConfig(cfg.Obmondo)
		if err != nil {
			return nil, err
		}
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}

	return &Exporter{
		resultsDir: cfg.ResultsDir,
		apiURL:     strings.TrimRight(cfg.Obmondo.URL, "/") + "/api/servers/cve-report",
		client:     client,
	}, nil
}

// Push reads JSON result files from today's scan directories and POSTs each to the API.
// Files that have already been pushed (same path+mtime) are skipped.
func (e *Exporter) Push() error {
	files, err := e.collectFiles()
	if err != nil {
		return fmt.Errorf("listing result files: %w", err)
	}

	if len(files) == 0 {
		slog.Info("no result files found", "dir", e.resultsDir)
		return nil
	}

	var errs []error
	for _, file := range files {
		if err := e.PushFile(file); err != nil {
			slog.Error("failed to push result", "file", file, "error", err)
			errs = append(errs, err)

			continue
		}
		slog.Info("pushed result", "file", file)
	}

	return errors.Join(errs...)
}

// collectFiles walks the results directory tree and returns all *.json files.
func (e *Exporter) collectFiles() ([]string, error) {
	var files []string

	err := filepath.WalkDir(e.resultsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".json") {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

// PushFile trims a single Vuls result file down to the fields the API needs and
// POSTs the slim payload.
func (e *Exporter) PushFile(path string) error {
	body, err := trimResultFile(path)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, e.apiURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusBadRequest {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		return fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// trimResultFile decodes a Vuls result file into slimResult (streaming, so the
// full file is never held in memory as one blob) and re-marshals it, yielding a
// payload containing only the fields the API consumes.
func trimResultFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var result slimResult
	if err := json.NewDecoder(f).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}

	body, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("marshaling trimmed result for %s: %w", path, err)
	}

	return body, nil
}

func buildTLSConfig(obmondo config.Obmondo) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(obmondo.CertFile, obmondo.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("loading client certificate: %w", err)
	}

	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if obmondo.CAFile != "" {
		caCert, err := os.ReadFile(obmondo.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsCfg.RootCAs = pool
	}

	return tlsCfg, nil
}
