package exporter

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
