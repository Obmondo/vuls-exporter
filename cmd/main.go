package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Obmondo/vuls-exporter/config"
	"github.com/Obmondo/vuls-exporter/internal/exporter"
	"github.com/Obmondo/vuls-exporter/internal/watcher"
)

var (
	// Version is set at build time via ldflags.
	Version    = "dev"
	configPath string
	apiURL     string
)

func main() {
	root := &cobra.Command{
		Use:     "vuls-exporter",
		Short:   "Push Vuls scan results to the Obmondo API",
		Version: Version,
		PersistentPreRun: func(_ *cobra.Command, _ []string) {
			slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
		},
		RunE: run,
	}

	root.PersistentFlags().StringVarP(&configPath, "config", "c", "/etc/vuls-exporter/config.yaml", "path to config file")
	root.Flags().StringVar(&apiURL, "url", "", "Obmondo API URL (required, overrides config file)")

	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(_ *cobra.Command, _ []string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	if apiURL != "" {
		cfg.Obmondo.URL = apiURL
	}

	exp, err := exporter.New(cfg)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	w, err := watcher.New(ctx, cfg.ResultsDir)
	if err != nil {
		return err
	}
	defer w.Close()

	slog.Info("starting vuls-exporter", "interval", cfg.Interval.Duration, "results_dir", cfg.ResultsDir, "version", Version)

	// Run immediately on startup, then on interval + inotify.
	push(exp)
	ticker := time.NewTicker(cfg.Interval.Duration)
	defer ticker.Stop()

	for {
		select {
		case file := <-w.Events():
			slog.Info("detected new result file", "file", file)
			pushFile(exp, file)
		case <-ticker.C:
			push(exp)
		case <-ctx.Done():
			slog.Info("shutting down")
			return nil
		}
	}
}

func push(exp *exporter.Exporter) {
	slog.Info("pushing results")
	if err := exp.Push(); err != nil {
		slog.Error("push failed", "error", err)
	}
}

func pushFile(exp *exporter.Exporter, path string) {
	if err := exp.PushFile(path); err != nil {
		slog.Error("push failed", "file", path, "error", err)
		return
	}
	slog.Info("pushed result", "file", path)
}
