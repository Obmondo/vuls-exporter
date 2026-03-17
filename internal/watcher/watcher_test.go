package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcher_DetectsNewJSONFile(t *testing.T) {
	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w, err := New(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// Write a JSON file — watcher should detect it.
	path := filepath.Join(dir, "result.json")
	if err := os.WriteFile(path, []byte(`{}`), 0644); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-w.Events():
		if got != path {
			t.Errorf("expected %s, got %s", path, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for watcher event")
	}
}

func TestWatcher_IgnoresNonJSON(t *testing.T) {
	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w, err := New(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// Write a non-JSON file — should be ignored.
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hi"), 0644); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-w.Events():
		t.Fatalf("expected no event for .txt file, got %s", got)
	case <-time.After(200 * time.Millisecond):
		// Good — no event.
	}
}

func TestWatcher_DetectsFileInSubdirectory(t *testing.T) {
	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w, err := New(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	// Create a subdirectory (simulates Vuls time-stamped dir).
	subdir := filepath.Join(dir, "2026-03-16T05-00-00+0000")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}

	// Give fsnotify time to pick up the new directory watch.
	time.Sleep(100 * time.Millisecond)

	// Write a JSON file into the subdirectory.
	path := filepath.Join(subdir, "host1.json")
	if err := os.WriteFile(path, []byte(`{"serverName":"host1"}`), 0644); err != nil {
		t.Fatal(err)
	}

	select {
	case got := <-w.Events():
		if got != path {
			t.Errorf("expected %s, got %s", path, got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for subdirectory watcher event")
	}
}

func TestWatcher_Close(t *testing.T) {
	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	w, err := New(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatalf("Close() returned error: %v", err)
	}

	// Events channel should be closed after Close().
	_, ok := <-w.Events()
	if ok {
		t.Fatal("expected events channel to be closed after Close()")
	}
}
