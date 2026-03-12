# vuls-exporter

Sidecar service that reads Vuls scan results and pushes them to the Obmondo API. Runs alongside the Vuls server in Kubernetes.

## Architecture

```
Linux hosts                          Kubernetes cluster
┌─────────────────────┐              ┌──────────────────────────────────┐
│ security-exporter   │──packages──▶ │ vuls-server     │ vuls-exporter │
│ (collects packages, │              │ (scans for CVEs)│ (pushes results│
│  exposes metrics)   │◀──results──  │                 │  to Obmondo API│
└─────────────────────┘              └──────────────────────────────────┘
```

- [security-exporter](https://github.com/Obmondo/security-exporter) runs on Linux hosts, collects installed packages, and sends them to the Vuls server
- **vuls-exporter** (this repo) runs as a sidecar in k8s, reads scan results from the Vuls server, and pushes them to the Obmondo API with mTLS client certificate authentication

## How it works

The exporter watches the shared results directory (`results_dir`) using Linux inotify (`IN_CLOSE_WRITE`). When vuls-server finishes writing a JSON result file and closes the file descriptor, the exporter detects it immediately and pushes it to the Obmondo API. A periodic ticker (`interval`) also runs as a fallback to push any files that may have been missed.

## Configuration

```yaml
results_dir: "/vuls/results"
interval: 12h
obmondo:
  url: "https://api.obmondo.com/v1/vuls"
  cert_file: "/etc/ssl/client.pem"
  key_file: "/etc/ssl/client-key.pem"
  ca_file: "/etc/ssl/ca.pem"
```

## Build

```sh
make build
```

## Test

```sh
make test
make lint
```

## Release

Releases are managed via [GoReleaser](https://goreleaser.com/). To create a release:

```sh
git tag v1.0.0
git push origin v1.0.0
```
