// Package app wires configuration, plugins, routing, the queue, and the SMTP
// server into a running service.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ferchd/gomta/config"
	"github.com/ferchd/gomta/internal/auth"
	"github.com/ferchd/gomta/internal/router"
	"github.com/ferchd/gomta/internal/smtpserver"
	"github.com/ferchd/gomta/plugin"
	"github.com/ferchd/gomta/queue"
)

// App is a fully constructed GoMTA instance.
type App struct {
	Config  *config.Config
	Domains *config.Domains
	Users   *auth.Store
	Plugins *plugin.Runner
	Router  *router.Router
	Queue   *queue.Manager
	Server  *smtpserver.Server
	Logger  *slog.Logger

	status    *http.Server
	started   time.Time
	closeOnce sync.Once
}

// LoadOptions overrides selected configuration values before components are
// built.
type LoadOptions struct {
	// LogLevel overrides log.level from the config file.
	LogLevel string
}

// Load reads configuration and constructs every runtime component.
func Load(configPath string) (*App, error) {
	return LoadWithOptions(configPath, LoadOptions{})
}

// LoadWithOptions is Load with explicit overrides.
func LoadWithOptions(configPath string, opts LoadOptions) (*App, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}
	if opts.LogLevel != "" {
		switch strings.ToLower(opts.LogLevel) {
		case "debug", "info", "warn", "error":
			cfg.Log.Level = strings.ToLower(opts.LogLevel)
		default:
			return nil, fmt.Errorf("invalid log level %q (use debug, info, warn or error)", opts.LogLevel)
		}
	}
	logger := NewLogger(cfg.Log)
	logger.Info("loading GoMTA", "config", cfg.Path)

	domains, err := config.LoadDomains(cfg.DomainsFile)
	if err != nil {
		return nil, err
	}
	users, err := auth.Load(cfg.UsersFile)
	if err != nil {
		return nil, err
	}
	pluginCfg, err := config.LoadPlugins(cfg.PluginsFile, cfg.BaseDir)
	if err != nil {
		return nil, err
	}
	runner, err := plugin.NewRunner(pluginCfg.Plugins, plugin.RunnerConfig{
		Workers:          pluginCfg.Workers,
		Timeout:          pluginCfg.Timeout.Std(),
		MaxSnapshotBytes: cfg.Limits.MaxDataMemoryBytes,
		BaseDir:          cfg.BaseDir,
		Logger:           logger,
	})
	if err != nil {
		return nil, err
	}

	bc := plugin.BuildContext{BaseDir: cfg.BaseDir, Logger: logger}
	rt, err := router.New(cfg, domains, bc)
	if err != nil {
		return nil, err
	}
	retry := make([]time.Duration, len(cfg.Queue.Retry))
	for i, d := range cfg.Queue.Retry {
		retry[i] = d.Std()
	}
	qm, err := queue.New(queue.Config{
		Dir:             cfg.Queue.Dir,
		MaxMessageBytes: cfg.Limits.MaxMessageBytes,
		Workers:         cfg.Queue.Workers,
		MaxAttempts:     cfg.Queue.MaxAttempts,
		MaxAge:          cfg.Queue.MaxAge.Std(),
		OrphanGrace:     cfg.Queue.OrphanGrace.Std(),
		FailedRetention: cfg.Queue.FailedRetention.Std(),
		QuarantineDir:   filepath.Join(cfg.DataDir, "quarantine"),
		SendDSN:         cfg.Queue.SendDSN,
		DSNInbound:      cfg.Queue.DSNInbound,
		Plugins:         runner,
		Retry:           retry,
		Logger:          logger,
	}, rt)
	if err != nil {
		return nil, err
	}
	server, err := smtpserver.New(smtpserver.Deps{
		Config:  cfg,
		Domains: domains,
		Users:   users,
		Plugins: runner,
		Queue:   qm,
		Logger:  logger,
	})
	if err != nil {
		return nil, err
	}
	a := &App{
		Config:  cfg,
		Domains: domains,
		Users:   users,
		Plugins: runner,
		Router:  rt,
		Queue:   qm,
		Server:  server,
		Logger:  logger,
		started: time.Now(),
	}
	if strings.TrimSpace(cfg.StatusAddr) != "" {
		a.status = &http.Server{
			Addr:              cfg.StatusAddr,
			Handler:           a.statusHandler(),
			ReadHeaderTimeout: 5 * time.Second,
		}
	}
	return a, nil
}

// NewLogger builds the configured slog logger.
func NewLogger(cfg config.Log) *slog.Logger {
	level := slog.LevelInfo
	switch strings.ToLower(cfg.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if strings.EqualFold(cfg.Format, "json") {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	} else {
		handler = slog.NewTextHandler(os.Stderr, opts)
	}
	return slog.New(handler)
}

// Run starts the queue, all SMTP listeners, and the optional status server. It
// blocks until ctx is canceled or a component fails.
func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var wg sync.WaitGroup
	errCh := make(chan error, 3)
	start := func(name string, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := fn(ctx); err != nil {
				select {
				case errCh <- fmt.Errorf("%s: %w", name, err):
				default:
				}
			}
		}()
	}
	// Never expose an SMTP listener before the queue has acquired exclusive
	// spool ownership and completed its initial readiness check.
	start("queue", a.Queue.Start)
	startupCtx, startupCancel := context.WithTimeout(ctx, 30*time.Second)
	defer startupCancel()
	poll := time.NewTicker(20 * time.Millisecond)
	defer poll.Stop()
	var startupErr error
queueStartup:
	for !a.Queue.Ready() {
		select {
		case err := <-errCh:
			startupErr = err
			break queueStartup
		case <-startupCtx.Done():
			startupErr = fmt.Errorf("queue unavailable during startup: %w", startupCtx.Err())
			break queueStartup
		case <-poll.C:
		}
	}
	if startupErr != nil {
		cancel()
		wg.Wait()
		return startupErr
	}
	start("smtp", a.Server.Run)
	if a.status != nil {
		start("status", a.serveStatus)
	}

	var firstErr error
	select {
	case <-ctx.Done():
	case firstErr = <-errCh:
		cancel()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil && !errors.Is(firstErr, context.Canceled) {
		a.Logger.Error("shutdown after error", "error", firstErr)
		return firstErr
	}
	a.Logger.Info("GoMTA stopped")
	return nil
}

func (a *App) serveStatus(ctx context.Context) error {
	if a.status == nil {
		return nil
	}
	errCh := make(chan error, 1)
	go func() {
		a.Logger.Info("status server started", "address", a.status.Addr)
		err := a.status.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.status.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return nil
	}
}

func (a *App) statusHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if !a.Server.Ready() || !a.Queue.Ready() {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ready\n"))
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(a.Stats())
	})
	return mux
}

// Stats is the /stats payload.
type Stats struct {
	Hostname      string              `json:"hostname"`
	Uptime        string              `json:"uptime"`
	Domains       []string            `json:"domains"`
	Listeners     []config.Listener   `json:"listeners"`
	Backends      Backends            `json:"backends"`
	Plugins       map[string][]string `json:"plugins"`
	Queue         QueueStats          `json:"queue"`
	QueuePath     string              `json:"queue_path"`
	Users         int                 `json:"users"`
	PluginWorkers int                 `json:"plugin_workers"`
}

// Backends names the configured delivery backends.
type Backends struct {
	Local    string `json:"local"`
	Outbound string `json:"outbound"`
	Filter   string `json:"filter,omitempty"`
}

// QueueStats reports spool counts.
type QueueStats struct {
	Queued      int `json:"queued"`
	Failed      int `json:"failed"`
	Quarantined int `json:"quarantined"`
}

// Stats returns a point-in-time snapshot.
func (a *App) Stats() Stats {
	queued, failed := a.Queue.Stats()
	local, outbound, filter := a.Router.Backends()
	return Stats{
		Hostname:  a.Config.Hostname,
		Uptime:    time.Since(a.started).Round(time.Second).String(),
		Domains:   a.Domains.List(),
		Listeners: a.Server.Listeners(),
		Backends:  Backends{Local: local, Outbound: outbound, Filter: filter},
		Plugins:   a.Plugins.Entries(),
		Queue: QueueStats{
			Queued:      queued,
			Failed:      failed,
			Quarantined: countMessages(filepath.Join(a.Config.DataDir, "quarantine")),
		},
		QueuePath:     a.Config.Queue.Dir,
		Users:         a.Users.Len(),
		PluginWorkers: a.Plugins.Workers(),
	}
}

func countMessages(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".eml") {
			n++
		}
	}
	return n
}

// Close releases long-lived resources. The current implementation has none,
// but the method keeps shutdown paths explicit.
func (a *App) Close() error {
	var err error
	a.closeOnce.Do(func() {})
	return err
}
