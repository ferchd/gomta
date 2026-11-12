package smtpserver

import (
	"log/slog"
	"net"
	"sync"
	"time"
)

// limitListener enforces total and per-IP connection ceilings before a
// connection reaches go-smtp. Excess clients receive a 421 greeting and are
// closed immediately.
type limitListener struct {
	net.Listener
	limits *connectionLimits
	logger *slog.Logger
}

// connectionLimits is shared across all configured SMTP listeners.
type connectionLimits struct {
	mu       sync.Mutex
	max      int
	maxPerIP int
	total    int
	counts   map[string]int
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip := remoteIPString(conn.RemoteAddr())
		l.limits.mu.Lock()
		over := (l.limits.max > 0 && l.limits.total >= l.limits.max) || (l.limits.maxPerIP > 0 && l.limits.counts[ip] >= l.limits.maxPerIP)
		if over {
			l.limits.mu.Unlock()
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = conn.Write([]byte("421 4.7.0 Too many connections, try again later\r\n"))
			_ = conn.Close()
			continue
		}
		l.limits.total++
		l.limits.counts[ip]++
		l.limits.mu.Unlock()
		return &limitedConn{Conn: conn, release: func() { l.limits.release(ip) }}, nil
	}
}

func (l *connectionLimits) release(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total--
	if l.counts[ip] <= 1 {
		delete(l.counts, ip)
	} else {
		l.counts[ip]--
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

func remoteIPString(addr net.Addr) string {
	if addr == nil {
		return "unknown"
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
