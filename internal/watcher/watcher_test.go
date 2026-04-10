package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
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
	subdir := filepath.Join(dir, time.Now().Format(dirTimeLayout))
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

func TestCleanOldDirs(t *testing.T) {
	dir := t.TempDir()

	now := time.Now()
	oldDir := now.Add(-31 * 24 * time.Hour).Format(dirTimeLayout)
	recentDir := now.Add(-1 * 24 * time.Hour).Format(dirTimeLayout)
	nonTimestamp := "some-random-dir"

	for _, name := range []string{oldDir, recentDir, nonTimestamp} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0755); err != nil {
			t.Fatal(err)
		}
	}

	cleanOldDirs(dir)

	if _, err := os.Stat(filepath.Join(dir, oldDir)); !os.IsNotExist(err) {
		t.Errorf("expected old dir %s to be removed", oldDir)
	}
	if _, err := os.Stat(filepath.Join(dir, recentDir)); err != nil {
		t.Errorf("expected recent dir %s to be kept: %v", recentDir, err)
	}
	if _, err := os.Stat(filepath.Join(dir, nonTimestamp)); err != nil {
		t.Errorf("expected non-timestamp dir %s to be kept: %v", nonTimestamp, err)
	}
}

func TestAddRecursive_SkipsOldDirs(t *testing.T) {
	dir := t.TempDir()

	now := time.Now()
	oldDir := now.Add(-3 * 24 * time.Hour).Format(dirTimeLayout)
	recentDir := now.Add(-1 * 24 * time.Hour).Format(dirTimeLayout)

	for _, name := range []string{oldDir, recentDir} {
		if err := os.MkdirAll(filepath.Join(dir, name), 0755); err != nil {
			t.Fatal(err)
		}
	}

	fw, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer fw.Close()

	if err := addRecursive(fw, dir); err != nil {
		t.Fatal(err)
	}

	watched := fw.WatchList()
	watchSet := make(map[string]bool, len(watched))
	for _, p := range watched {
		watchSet[p] = true
	}

	if !watchSet[dir] {
		t.Error("expected root dir to be watched")
	}
	if !watchSet[filepath.Join(dir, recentDir)] {
		t.Errorf("expected recent dir %s to be watched", recentDir)
	}
	if watchSet[filepath.Join(dir, oldDir)] {
		t.Errorf("expected old dir %s to NOT be watched", oldDir)
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
