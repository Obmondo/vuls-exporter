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

// trimResultFile decodes a Vuls result file (streaming, so the full file is
// never held in memory as one blob) and resolves it into the compact,
// distro-aware payload the API stores directly.
func trimResultFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	var result vulsResult
	if err := json.NewDecoder(f).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding %s: %w", path, err)
	}

	body, err := json.Marshal(buildReport(&result))
	if err != nil {
		return nil, fmt.Errorf("marshaling report for %s: %w", path, err)
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
