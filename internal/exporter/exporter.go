package exporter

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/Obmondo/vuls-exporter/config"
)

const httpTimeout = 30 * time.Second

// Exporter reads Vuls JSON result files and pushes them to the Obmondo API.
type Exporter struct {
	resultsDir string
	apiURL     string
	client     *http.Client
}

// New creates an Exporter with mTLS client if cert files are configured.
func New(cfg *config.Config) (*Exporter, error) {
	client := &http.Client{Timeout: httpTimeout}

	if cfg.Obmondo.CertFile != "" && cfg.Obmondo.KeyFile != "" {
		tlsCfg, err := buildTLSConfig(cfg.Obmondo)
		if err != nil {
			return nil, err
		}
		client.Transport = &http.Transport{TLSClientConfig: tlsCfg}
	}

	return &Exporter{
		resultsDir: cfg.ResultsDir,
		apiURL:     cfg.Obmondo.URL,
		client:     client,
	}, nil
}

// Push reads all JSON result files from the results directory and POSTs each to the API.
func (e *Exporter) Push() error {
	files, err := filepath.Glob(filepath.Join(e.resultsDir, "**", "*.json"))
	if err != nil {
		return fmt.Errorf("listing result files: %w", err)
	}

	if len(files) == 0 {
		slog.Info("no result files found", "dir", e.resultsDir)
		return nil
	}

	var pushErr error
	for _, file := range files {
		if err := e.pushFile(file); err != nil {
			slog.Error("failed to push result", "file", file, "error", err)
			pushErr = err

			continue
		}
		slog.Info("pushed result", "file", file)
	}

	return pushErr
}

func (e *Exporter) pushFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening %s: %w", path, err)
	}
	defer f.Close()

	req, err := http.NewRequest(http.MethodPost, e.apiURL, f)
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
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API returned %d: %s", resp.StatusCode, string(body))
	}

	return nil
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
