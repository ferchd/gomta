package delivery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/ferchd/gomta/plugin"
)

func init() {
	Register("lmtp", NewLMTP)
}

// NewLMTP constructs an LMTP backend, typically used to forward filtered mail
// to Dovecot, Postfix, or another local delivery agent.
func NewLMTP(bc plugin.BuildContext, opts plugin.Options) (Backend, error) {
	host := opts.String("host", "")
	if host == "" {
		return nil, fmt.Errorf("host is required (host:port)")
	}
	if _, _, err := net.SplitHostPort(host); err != nil {
		return nil, fmt.Errorf("host must include a port: %w", err)
	}
	helo := opts.String("helo", "")
	if helo == "" {
		helo, _ = os.Hostname()
		if helo == "" {
			helo = "localhost"
		}
	}
	return &lmtpBackend{
		host:    host,
		helo:    helo,
		timeout: opts.Duration("timeout", 2*time.Minute),
		dialer:  &net.Dialer{Timeout: opts.Duration("connect_timeout", 15*time.Second)},
	}, nil
}

type lmtpBackend struct {
	host    string
	helo    string
	timeout time.Duration
	dialer  *net.Dialer
}

func (b *lmtpBackend) Name() string { return "lmtp" }

func (b *lmtpBackend) Deliver(ctx context.Context, m *Message) map[string]error {
	results := make(map[string]error, len(m.To))
	fail := func(err error) map[string]error {
		e := classify(err)
		for _, rcpt := range m.To {
			results[rcpt] = e
		}
		return results
	}
	conn, err := b.dialer.DialContext(ctx, "tcp", b.host)
	if err != nil {
		return fail(err)
	}
	client := smtp.NewClientLMTP(conn)
	defer client.Close()
	client.CommandTimeout = b.timeout
	client.SubmissionTimeout = b.timeout
	if err := client.Hello(b.helo); err != nil {
		return fail(err)
	}
	if err := client.Mail(m.From, nil); err != nil {
		return fail(err)
	}
	accepted := make([]string, 0, len(m.To))
	for _, rcpt := range m.To {
		if err := client.Rcpt(rcpt, nil); err != nil {
			results[rcpt] = classify(err)
			continue
		}
		accepted = append(accepted, rcpt)
	}
	if len(accepted) == 0 {
		_ = client.Quit()
		return results
	}
	w, err := client.Data()
	if err != nil {
		e := classify(err)
		for _, rcpt := range accepted {
			results[rcpt] = e
		}
		return results
	}
	if _, err := w.Write(m.Data); err != nil {
		_ = w.Close()
		e := Temp(err)
		for _, rcpt := range accepted {
			results[rcpt] = e
		}
		return results
	}
	responses, closeErr := w.CloseWithLMTPResponse()
	mergeLMTPResults(results, accepted, responses, closeErr)
	_ = client.Quit()
	return results
}

// mergeLMTPResults preserves per-recipient successes even if other RCPTs fail.
func mergeLMTPResults(results map[string]error, accepted []string, responses map[string]*smtp.DataResponse, closeErr error) {
	var recipientErrors smtp.LMTPDataError
	_ = errors.As(closeErr, &recipientErrors)
	for _, rcpt := range accepted {
		if _, ok := responses[rcpt]; ok {
			results[rcpt] = nil
			continue
		}
		if smtpErr, ok := recipientErrors[rcpt]; ok && smtpErr != nil {
			results[rcpt] = classify(smtpErr)
			continue
		}
		if closeErr != nil {
			results[rcpt] = Temp(closeErr)
		} else {
			results[rcpt] = Temp(fmt.Errorf("LMTP server returned no status for %s", rcpt))
		}
	}
}
