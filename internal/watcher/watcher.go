package watcher

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Watcher uses raw inotify to monitor a directory for IN_CLOSE_WRITE events,
// which fire only after the writing process closes its file descriptor —
// guaranteeing the file is fully written.
type Watcher struct {
	fd     int
	wd     int
	dir    string
	events chan string
	done   chan struct{}
}

// New creates a Watcher on the given directory. Only *.json files are reported.
func New(dir string) (*Watcher, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC)
	if err != nil {
		return nil, fmt.Errorf("inotify_init1: %w", err)
	}

	wd, err := unix.InotifyAddWatch(fd, dir, unix.IN_CLOSE_WRITE)
	if err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("inotify_add_watch %s: %w", dir, err)
	}

	w := &Watcher{
		fd:     fd,
		wd:     wd,
		dir:    dir,
		events: make(chan string, 16),
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
	unix.InotifyRmWatch(w.fd, uint32(w.wd))
	err := unix.Close(w.fd)
	<-w.done // wait for readLoop to exit
	return err
}

func (w *Watcher) readLoop() {
	defer close(w.done)
	defer close(w.events)

	buf := make([]byte, 4096)
	for {
		n, err := unix.Read(w.fd, buf)
		if err != nil {
			// fd closed by Close() — normal shutdown
			return
		}

		w.parseEvents(buf[:n])
	}
}

func (w *Watcher) parseEvents(buf []byte) {
	for len(buf) > 0 {
		if len(buf) < unix.SizeofInotifyEvent {
			return
		}

		var raw unix.InotifyEvent
		binary.Read(bytes.NewReader(buf), binary.LittleEndian, &raw)

		nameLen := int(raw.Len)
		headerLen := int(unsafe.Sizeof(raw))

		if len(buf) < headerLen+nameLen {
			return
		}

		if nameLen > 0 {
			nameBytes := buf[headerLen : headerLen+nameLen]
			// Name is null-terminated
			name := string(bytes.TrimRight(nameBytes, "\x00"))

			if strings.HasSuffix(name, ".json") {
				path := filepath.Join(w.dir, name)
				slog.Debug("inotify IN_CLOSE_WRITE", "file", path)
				w.events <- path
			}
		}

		buf = buf[headerLen+nameLen:]
	}
}
