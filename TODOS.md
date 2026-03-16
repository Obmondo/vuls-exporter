# Vuls Exporter — TODOs

From CEO Plan Review (2026-03-16), HOLD SCOPE mode.

## Planned

### P2: Date-aware push with state file dedup [M]

**What:** Track pushed files by path+mtime in a state file on PVC. On ticker, only push today's results + unpushed files.

**Why:** Currently Push() re-sends ALL files every interval. State file prevents duplicates.

**How:** Maintain JSON state file (path → {mtime, pushed_at}) on PVC (location TBD by user). Skip files already in state.

**Blocked by:** User needs to provide PVC state file path.

---

### P3: Add self-observability metrics [M]

**What:** Prometheus metrics for files pushed, errors, push duration, last push timestamp.

**Why:** Currently the only way to know if the exporter is working is to check logs.

**Deferred:** The exporter pushes to an API, not Prometheus. Useful but not critical yet.

---

## Completed

### P1: Switch to fsnotify for subdirectory watching [M]

**Completed:** feat/hardening (2026-03-16)

Replaced raw inotify syscalls with `github.com/fsnotify/fsnotify`. Recursive directory watching via `addRecursive()` walks all subdirs on startup and watches `Create` events to auto-add new subdirs. Fixes the `fix/watch-subdirectories` bug.

---

### P1: errors.Join for push failures [S]

**Completed:** feat/hardening (2026-03-16)

Replaced last-error-only pattern with `errors.Join(errs...)` in `Push()`.

---

### P1: Walk-based file collection [S]

**Completed:** feat/hardening (2026-03-16)

Replaced broken `filepath.Glob("**/*.json")` with `filepath.WalkDir` which correctly finds JSON files at any depth.

---

### P2: Make HTTP timeout configurable [S]

**Completed:** feat/hardening (2026-03-16)

Added `obmondo.timeout` field to config (Duration type). Defaults to 30s.

---

### P2: Limit API error response body read [S]

**Completed:** feat/hardening (2026-03-16)

Added `io.LimitReader(resp.Body, 4096)` to prevent unbounded memory on verbose error responses.

---

### P2: Add watcher tests [M]

**Completed:** feat/hardening (2026-03-16)

4 tests: JSON detection, non-JSON filtering, subdirectory detection, close/cleanup.
