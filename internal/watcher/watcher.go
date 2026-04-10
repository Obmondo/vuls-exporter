package watcher

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fsnotify/fsnotify"
)

const (
	dirPollInterval = 5 * time.Second
	eventChanSize   = 16
)

// Watcher monitors a directory tree for new *.json files using fsnotify.
// It reports fully-written file paths on the Events channel.
type Watcher struct {
	w      *fsnotify.Watcher
	dir    string
	events chan string
	done   chan struct{}
}

// New creates a Watcher on the given directory. Only *.json files are reported.
// If the directory does not exist yet, New polls until it appears (the volume
// may be mounted after the container starts in k8s).
func New(ctx context.Context, dir string) (*Watcher, error) {
	for {
		if _, err := os.Stat(dir); err == nil {
			break
		}
		slog.Info("waiting for results directory to appear", "dir", dir)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(dirPollInterval):
		}
	}

	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}

	// Remove result directories older than 30 days.
	cleanOldDirs(dir)

	// Walk the directory tree and watch all subdirectories.
	if err := addRecursive(fw, dir); err != nil {
		_ = fw.Close()
		return nil, err
	}

	w := &Watcher{
		w:      fw,
		dir:    dir,
		events: make(chan string, eventChanSize),
		done:   make(chan struct{}),
	}

	go w.readLoop()

	return w, nil
}

// Events returns a channel of fully-written *.json file paths.
func (w *Watcher) Events() <-chan string {
	return w.events
}

// Close stops the watcher and releases resources.
func (w *Watcher) Close() error {
	err := w.w.Close()
	<-w.done
	return err
}

func (w *Watcher) readLoop() {
	defer close(w.done)
	defer close(w.events)

	for {
		select {
		case event, ok := <-w.w.Events:
			if !ok {
				return
			}
			w.handleEvent(event)
		case err, ok := <-w.w.Errors:
			if !ok {
				return
			}
			slog.Error("watcher error", "error", err)
		}
	}
}

func (w *Watcher) handleEvent(event fsnotify.Event) {
	// Watch new subdirectories as they're created.
	if event.Has(fsnotify.Create) {
		if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
			slog.Debug("watching new subdirectory", "dir", event.Name)
			_ = addRecursive(w.w, event.Name)
		}
	}

	// Only report *.json Write events (file fully written).
	if event.Has(fsnotify.Write) && strings.HasSuffix(event.Name, ".json") {
		slog.Debug("detected new result", "file", event.Name)
		w.events <- event.Name
	}
}

const (
	dirTimeLayout = "2006-01-02T15-04-05-0700"
	cleanupMaxAge = 30 * 24 * time.Hour
)

// cleanOldDirs removes top-level subdirectories of dir whose name parses to
// a timestamp older than 30 days.
func cleanOldDirs(dir string) {
	cutoff := time.Now().Add(-cleanupMaxAge)

	entries, err := os.ReadDir(dir)
	if err != nil {
		slog.Error("failed to read results directory for cleanup", "dir", dir, "error", err)
		return
	}

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		t, parseErr := time.Parse(dirTimeLayout, e.Name())
		if parseErr != nil {
			continue
		}
		if t.Before(cutoff) {
			path := filepath.Join(dir, e.Name())
			slog.Info("removing old result directory", "dir", path, "time", t)
			if err := os.RemoveAll(path); err != nil {
				slog.Error("failed to remove old directory", "dir", path, "error", err)
			}
		}
	}
}

// addRecursive walks dir and watches only directories from the last 2 days
// based on the timestamp encoded in the directory name.
func addRecursive(fw *fsnotify.Watcher, dir string) error {
	cutoff := time.Now().Add(-2 * 24 * time.Hour)

	return filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}

		if t, parseErr := time.Parse(dirTimeLayout, d.Name()); parseErr == nil && t.Before(cutoff) {
			slog.Debug("skipping old directory", "dir", path, "time", t)
			return filepath.SkipDir
		}

		slog.Debug("watching directory", "dir", path)
		return fw.Add(path)
	})
}
