package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestLoad(t *testing.T) {
	content := `
results_dir: "/vuls/results"
interval: 12h
obmondo:
  url: "https://api.obmondo.com/v1/vuls"
  cert_file: "/etc/ssl/cert.pem"
  key_file: "/etc/ssl/key.pem"
  ca_file: "/etc/ssl/ca.pem"
`
	path := writeTempConfig(t, content)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ResultsDir != "/vuls/results" {
		t.Errorf("expected results_dir /vuls/results, got %s", cfg.ResultsDir)
	}
	if cfg.Interval.Duration != 12*time.Hour {
		t.Errorf("expected interval 12h, got %s", cfg.Interval.Duration)
	}
	if cfg.Obmondo.URL != "https://api.obmondo.com/v1/vuls" {
		t.Errorf("expected URL https://api.obmondo.com/v1/vuls, got %s", cfg.Obmondo.URL)
	}
	if cfg.Obmondo.CertFile != "/etc/ssl/cert.pem" {
		t.Errorf("expected cert_file /etc/ssl/cert.pem, got %s", cfg.Obmondo.CertFile)
	}
	if cfg.Obmondo.KeyFile != "/etc/ssl/key.pem" {
		t.Errorf("expected key_file /etc/ssl/key.pem, got %s", cfg.Obmondo.KeyFile)
	}
	if cfg.Obmondo.CAFile != "/etc/ssl/ca.pem" {
		t.Errorf("expected ca_file /etc/ssl/ca.pem, got %s", cfg.Obmondo.CAFile)
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestLoad_InvalidYAML(t *testing.T) {
	path := writeTempConfig(t, "{{invalid yaml")

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoad_MissingURL(t *testing.T) {
	content := `
results_dir: "/vuls/results"
interval: 12h
obmondo:
  cert_file: "/etc/ssl/cert.pem"
`
	path := writeTempConfig(t, content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for missing obmondo.url")
	}
}

func TestLoad_InvalidDuration(t *testing.T) {
	content := `
results_dir: "/vuls/results"
interval: "bogus"
obmondo:
  url: "https://example.com"
`
	path := writeTempConfig(t, content)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid interval")
	}
}

func TestUnmarshalYAML_ValidDurations(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
	}{
		{"30s", 30 * time.Second},
		{"5m", 5 * time.Minute},
		{"12h", 12 * time.Hour},
		{"1h30m", time.Hour + 30*time.Minute},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var d Duration
			node := &yaml.Node{Kind: yaml.ScalarNode, Value: tt.input}
			if err := d.UnmarshalYAML(node); err != nil {
				t.Fatalf("unexpected error for %q: %v", tt.input, err)
			}
			if d.Duration != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, d.Duration)
			}
		})
	}
}

func writeTempConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}
