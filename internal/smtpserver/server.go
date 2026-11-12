// Package smtpserver wires go-smtp to the plugin, routing, and queue layers.
package smtpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/ferchd/gomta/config"
	"github.com/ferchd/gomta/internal/auth"
	"github.com/ferchd/gomta/internal/tlsutil"
	"github.com/ferchd/gomta/plugin"
	"github.com/ferchd/gomta/queue"
)

// Deps are the runtime services used by SMTP sessions.
type Deps struct {
	Config  *config.Config
	Domains *config.Domains
	Users   *auth.Store
	Plugins *plugin.Runner
	Queue   *queue.Manager
	Logger  *slog.Logger
}

// Server manages all configured SMTP listeners.
type Server struct {
	cfg     *config.Config
	domains *config.Domains
	users   *auth.Store
	plugins *plugin.Runner
	queue   *queue.Manager
	logger  *slog.Logger
	tls     *tls.Config
	relay   []*net.IPNet

	addrMu    sync.Mutex
	runtimes  []*runtime
	ready     atomic.Bool
	limits    *connectionLimits
	authGuard *authFailureGuard
	memory    *memoryBudget
}

type runtime struct {
	cfg      config.Listener
	server   *smtp.Server
	listener net.Listener
}

// New validates dependencies and prepares listeners. TLS material is loaded
// (or generated) here so configuration errors fail fast.
func New(deps Deps) (*Server, error) {
	if deps.Config == nil || deps.Domains == nil || deps.Plugins == nil || deps.Queue == nil {
		return nil, errors.New("smtpserver: missing dependency")
	}
	logger := deps.Logger
	if logger == nil {
		logger = slog.Default()
	}
	relay, err := deps.Config.ParseRelayNetworks()
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:       deps.Config,
		domains:   deps.Domains,
		users:     deps.Users,
		plugins:   deps.Plugins,
		queue:     deps.Queue,
		logger:    logger,
		relay:     relay,
		limits:    &connectionLimits{max: deps.Config.Limits.MaxConnections, maxPerIP: deps.Config.Limits.MaxConnectionsPerIP, counts: make(map[string]int)},
		authGuard: newAuthFailureGuard(deps.Config.Limits.MaxAuthFailures),
		memory:    newMemoryBudget(deps.Config.Limits.MaxDataMemoryBytes),
	}
	needTLS := false
	for _, l := range deps.Config.Listeners {
		if l.TLS != "none" {
			needTLS = true
		}
	}
	if needTLS {
		tlsCfg, err := tlsutil.Ensure(
			deps.Config.TLS.CertFile,
			deps.Config.TLS.KeyFile,
			deps.Config.Hostname,
			deps.Config.TLS.AutoGenerate,
			deps.Config.BuildTLSMinVersion(),
		)
		if err != nil {
			return nil, err
		}
		s.tls = tlsCfg
	}
	for _, l := range deps.Config.Listeners {
		s.runtimes = append(s.runtimes, s.newRuntime(l))
	}
	return s, nil
}

type backend struct {
	srv *Server
	lis config.Listener
}

func (b *backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return b.srv.newSession(c, b.lis)
}

func (s *Server) newRuntime(l config.Listener) *runtime {
	srv := smtp.NewServer(&backend{srv: s, lis: l})
	srv.Domain = s.cfg.Hostname
	srv.MaxMessageBytes = l.MaxMessageBytes
	srv.MaxRecipients = l.MaxRecipients
	srv.MaxLineLength = s.cfg.Limits.MaxLineLength
	srv.ReadTimeout = s.cfg.Limits.ReadTimeout.Std()
	srv.WriteTimeout = s.cfg.Limits.WriteTimeout.Std()
	srv.AllowInsecureAuth = l.AllowInsecureAuth
	srv.ErrorLog = smtpLogger{logger: s.logger}
	if l.TLS != "none" {
		srv.TLSConfig = s.tls
	} else {
		srv.TLSConfig = nil
	}
	return &runtime{cfg: l, server: srv}
}

// Run binds every listener and serves until ctx is canceled or a listener
// fails. Active sessions are shut down gracefully.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, len(s.runtimes))
	for _, rt := range s.runtimes {
		rt := rt
		ln, err := net.Listen("tcp", rt.cfg.Address)
		if err != nil {
			s.shutdown(context.Background())
			return fmt.Errorf("listen %s (%s): %w", rt.cfg.Name, rt.cfg.Address, err)
		}
		s.addrMu.Lock()
		rt.listener = ln
		s.addrMu.Unlock()
		ln = &limitListener{Listener: ln, limits: s.limits, logger: s.logger}
		if rt.cfg.TLS == "implicit" {
			ln = tls.NewListener(ln, s.tls)
		}
		s.logger.Info("SMTP listener started",
			"name", rt.cfg.Name,
			"address", ln.Addr().String(),
			"mode", rt.cfg.Mode,
			"tls", rt.cfg.TLS,
			"require_auth", rt.cfg.RequireAuth,
		)
		go func() {
			err := rt.server.Serve(ln)
			if err != nil && !errors.Is(err, smtp.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				select {
				case errCh <- fmt.Errorf("listener %s: %w", rt.cfg.Name, err):
				default:
				}
			}
		}()
	}
	s.ready.Store(true)
	defer s.ready.Store(false)
	select {
	case <-ctx.Done():
		s.logger.Info("shutting down SMTP listeners")
		s.shutdown(context.Background())
		return nil
	case err := <-errCh:
		s.shutdown(context.Background())
		return err
	}
}

func (s *Server) shutdown(ctx context.Context) {
	shutdownCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, rt := range s.runtimes {
		if rt.server == nil {
			continue
		}
		wg.Add(1)
		go func(rt *runtime) {
			defer wg.Done()
			_ = rt.server.Shutdown(shutdownCtx)
			if rt.listener != nil {
				_ = rt.listener.Close()
			}
		}(rt)
	}
	wg.Wait()
}

// Listeners returns the configured listener descriptions for diagnostics.
func (s *Server) Listeners() []config.Listener {
	out := make([]config.Listener, len(s.runtimes))
	for i, rt := range s.runtimes {
		out[i] = rt.cfg
	}
	return out
}

// Addresses returns the bound address of each listener keyed by listener name.
// Listeners that have not been bound yet report their configured address.
func (s *Server) Addresses() map[string]string {
	s.addrMu.Lock()
	defer s.addrMu.Unlock()
	out := make(map[string]string, len(s.runtimes))
	for _, rt := range s.runtimes {
		addr := rt.cfg.Address
		if rt.listener != nil {
			addr = rt.listener.Addr().String()
		}
		out[rt.cfg.Name] = addr
	}
	return out
}

func (s *Server) isRelayClient(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range s.relay {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

type smtpLogger struct{ logger *slog.Logger }

func (l smtpLogger) Printf(format string, v ...any) {
	l.logger.Warn(strings.TrimSpace(fmt.Sprintf(format, v...)))
}

func (l smtpLogger) Println(v ...any) {
	l.logger.Warn(strings.TrimSpace(fmt.Sprintln(v...)))
}

// Ready reports whether all listeners have successfully bound.
func (s *Server) Ready() bool { return s.ready.Load() }
