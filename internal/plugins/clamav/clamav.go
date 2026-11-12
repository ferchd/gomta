// Package clamav scans messages with a clamd daemon over the INSTREAM
// protocol.
package clamav

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/ferchd/gomta/plugin"
)

const chunkSize = 32 * 1024

func init() {
	plugin.Register("clamav", func(bc plugin.BuildContext, opts plugin.Options) (plugin.Plugin, error) {
		onVirus := strings.ToLower(strings.TrimSpace(opts.String("on_virus", "reject")))
		switch onVirus {
		case "reject", "tempfail", "quarantine", "tag":
		default:
			return nil, fmt.Errorf("on_virus must be reject, tempfail, quarantine or tag, got %q", onVirus)
		}
		p := &Plugin{
			address:           opts.String("address", "127.0.0.1:3310"),
			timeout:           opts.Duration("timeout", 30*time.Second),
			onVirus:           onVirus,
			tempfailOnError:   opts.Bool("tempfail_on_error", false),
			skipAuthenticated: opts.Bool("skip_authenticated", false),
		}
		if p.timeout <= 0 {
			p.timeout = 30 * time.Second
		}
		return p, nil
	})
}

// Plugin implements the data hook.
type Plugin struct {
	address           string
	timeout           time.Duration
	onVirus           string
	tempfailOnError   bool
	skipAuthenticated bool
}

// Name implements plugin.Plugin.
func (p *Plugin) Name() string { return "clamav" }

// Hooks implements plugin.Plugin.
func (p *Plugin) Hooks() []plugin.Hook { return []plugin.Hook{plugin.HookData} }

// Run implements plugin.Plugin.
func (p *Plugin) Run(ctx context.Context, hook plugin.Hook, tx *plugin.Tx) (plugin.Outcome, error) {
	if len(tx.Data) == 0 {
		return plugin.OK(), nil
	}
	if p.skipAuthenticated && tx.AuthUser != "" {
		return plugin.OK(), nil
	}
	virus, infected, err := p.scan(ctx, tx.Data)
	if err != nil {
		tx.SetMeta("clamav.result", "error")
		tx.SetMeta("clamav.error", err.Error())
		if p.tempfailOnError {
			return plugin.TempFail(451, "4.7.1 Virus scanner temporarily unavailable"), nil
		}
		return plugin.OK(), nil
	}
	if !infected {
		tx.SetMeta("clamav.result", "clean")
		return plugin.OK(), nil
	}
	tx.SetMeta("clamav.result", "infected")
	tx.SetMeta("clamav.virus", virus)
	switch p.onVirus {
	case "reject":
		return plugin.Reject(550, "5.7.1 Message contains malware (%s)", virus), nil
	case "tempfail":
		return plugin.TempFail(451, "4.7.1 Message contains malware"), nil
	case "quarantine":
		return plugin.Outcome{
			Action:  plugin.ActionQuarantine,
			Message: "malware detected: " + virus,
			Tags:    []string{"malware"},
		}, nil
	default:
		return plugin.Outcome{Action: plugin.ActionContinue, Tags: []string{"malware"}}, nil
	}
}

func (p *Plugin) scan(ctx context.Context, data []byte) (virus string, infected bool, err error) {
	dialer := &net.Dialer{}
	network, address := "tcp", p.address
	if strings.HasPrefix(p.address, "unix://") {
		network, address = "unix", strings.TrimPrefix(p.address, "unix://")
	}
	conn, err := dialer.DialContext(ctx, network, address)
	if err != nil {
		return "", false, err
	}
	defer conn.Close()

	deadline := time.Now().Add(p.timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return "", false, fmt.Errorf("send command: %w", err)
	}
	var lenBuf [4]byte
	for offset := 0; offset < len(data); offset += chunkSize {
		if err := ctx.Err(); err != nil {
			return "", false, err
		}
		end := offset + chunkSize
		if end > len(data) {
			end = len(data)
		}
		chunk := data[offset:end]
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(chunk)))
		if _, err := conn.Write(lenBuf[:]); err != nil {
			return "", false, fmt.Errorf("send chunk length: %w", err)
		}
		if _, err := conn.Write(chunk); err != nil {
			return "", false, fmt.Errorf("send chunk: %w", err)
		}
	}
	if _, err := conn.Write([]byte{0, 0, 0, 0}); err != nil {
		return "", false, fmt.Errorf("send terminator: %w", err)
	}

	reader := bufio.NewReader(io.LimitReader(conn, 8<<10))
	raw, err := reader.ReadString(0)
	if err != nil && !errors.Is(err, io.EOF) {
		return "", false, fmt.Errorf("read response: %w", err)
	}
	response := strings.TrimRight(strings.TrimSpace(raw), "\x00")
	switch {
	case strings.HasSuffix(response, "FOUND"):
		name := strings.TrimSuffix(response, "FOUND")
		name = strings.TrimPrefix(name, "stream:")
		return strings.TrimSpace(name), true, nil
	case strings.HasSuffix(response, "OK"):
		return "", false, nil
	case response == "":
		return "", false, errors.New("empty response from clamd")
	default:
		return "", false, fmt.Errorf("clamd error: %s", response)
	}
}
