package clamav

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/ferchd/gomta/plugin"
)

// fakeClamd accepts one INSTREAM connection and replies with response. It
// returns the address and a channel carrying the scanned bytes.
func fakeClamd(t *testing.T, response string) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	received := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

		cmd := make([]byte, len("zINSTREAM\x00"))
		if _, err := io.ReadFull(conn, cmd); err != nil {
			received <- nil
			return
		}
		var body bytes.Buffer
		var lenBuf [4]byte
		for {
			if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
				received <- nil
				return
			}
			n := binary.BigEndian.Uint32(lenBuf[:])
			if n == 0 {
				break
			}
			chunk := make([]byte, n)
			if _, err := io.ReadFull(conn, chunk); err != nil {
				received <- nil
				return
			}
			body.Write(chunk)
		}
		_, _ = conn.Write([]byte(response))
		received <- body.Bytes()
	}()
	return ln.Addr().String(), received
}

func newPlugin(t *testing.T, opts plugin.Options) *Plugin {
	t.Helper()
	p, err := plugin.New("clamav", plugin.BuildContext{BaseDir: t.TempDir()}, opts)
	if err != nil {
		t.Fatal(err)
	}
	return p.(*Plugin)
}

func TestScanClean(t *testing.T) {
	addr, received := fakeClamd(t, "stream: OK\x00")
	p := newPlugin(t, plugin.Options{"address": addr})
	tx := plugin.NewTx()
	tx.Data = []byte("clean message body")
	out, err := p.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != plugin.ActionContinue {
		t.Fatalf("unexpected action %v", out.Action)
	}
	if tx.MetaString("clamav.result") != "clean" {
		t.Fatalf("unexpected metadata: %+v", tx.MetaSnapshot())
	}
	if got := <-received; !bytes.Equal(got, tx.Data) {
		t.Fatalf("clamd received %q, want %q", got, tx.Data)
	}
}

func TestScanInfected(t *testing.T) {
	tests := []struct {
		onVirus string
		want    plugin.Action
		code    int
	}{
		{"reject", plugin.ActionReject, 550},
		{"tempfail", plugin.ActionTempFail, 451},
		{"quarantine", plugin.ActionQuarantine, 0},
		{"tag", plugin.ActionContinue, 0},
	}
	for _, tc := range tests {
		addr, _ := fakeClamd(t, "stream: Eicar-Test-Signature FOUND\x00")
		p := newPlugin(t, plugin.Options{"address": addr, "on_virus": tc.onVirus})
		tx := plugin.NewTx()
		tx.Data = []byte("infected")
		out, err := p.Run(context.Background(), plugin.HookData, tx)
		if err != nil {
			t.Fatal(err)
		}
		if out.Action != tc.want {
			t.Errorf("%s: action = %v, want %v", tc.onVirus, out.Action, tc.want)
		}
		if tc.code != 0 && out.Code != tc.code {
			t.Errorf("%s: code = %d, want %d", tc.onVirus, out.Code, tc.code)
		}
		if tx.MetaString("clamav.result") != "infected" || tx.MetaString("clamav.virus") != "Eicar-Test-Signature" {
			t.Errorf("%s: unexpected metadata: %+v", tc.onVirus, tx.MetaSnapshot())
		}
	}
}

func TestScanChunking(t *testing.T) {
	addr, received := fakeClamd(t, "stream: OK\x00")
	p := newPlugin(t, plugin.Options{"address": addr})
	tx := plugin.NewTx()
	tx.Data = bytes.Repeat([]byte("x"), chunkSize*2+17)
	if _, err := p.Run(context.Background(), plugin.HookData, tx); err != nil {
		t.Fatal(err)
	}
	if got := <-received; !bytes.Equal(got, tx.Data) {
		t.Fatalf("clamd received %d bytes, want %d", len(got), len(tx.Data))
	}
}

func TestScanDaemonError(t *testing.T) {
	addr, _ := fakeClamd(t, "INSTREAM size limit exceeded. ERROR\x00")
	p := newPlugin(t, plugin.Options{"address": addr})
	tx := plugin.NewTx()
	tx.Data = []byte("body")
	out, err := p.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != plugin.ActionContinue {
		t.Fatalf("unexpected action %v", out.Action)
	}
	if tx.MetaString("clamav.result") != "error" || tx.MetaString("clamav.error") == "" {
		t.Fatalf("unexpected metadata: %+v", tx.MetaSnapshot())
	}

	addr2, _ := fakeClamd(t, "INSTREAM size limit exceeded. ERROR\x00")
	strict := newPlugin(t, plugin.Options{"address": addr2, "tempfail_on_error": true})
	out, err = strict.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != plugin.ActionTempFail || out.Code != 451 {
		t.Fatalf("expected tempfail, got %+v", out)
	}
}

func TestScanConnectionFailure(t *testing.T) {
	p := newPlugin(t, plugin.Options{"address": "127.0.0.1:1", "timeout": "100ms"})
	tx := plugin.NewTx()
	tx.Data = []byte("body")
	out, err := p.Run(context.Background(), plugin.HookData, tx)
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != plugin.ActionContinue || tx.MetaString("clamav.result") != "error" {
		t.Fatalf("unexpected outcome %+v metadata %+v", out, tx.MetaSnapshot())
	}
}

func TestScanSkipAuthenticated(t *testing.T) {
	p := newPlugin(t, plugin.Options{"address": "127.0.0.1:1", "skip_authenticated": true})
	tx := plugin.NewTx()
	tx.Data = []byte("body")
	tx.AuthUser = "alice"
	if _, err := p.Run(context.Background(), plugin.HookData, tx); err != nil {
		t.Fatal(err)
	}
	if _, ok := tx.Meta("clamav.result"); ok {
		t.Fatalf("authenticated mail should not be scanned: %+v", tx.MetaSnapshot())
	}
}

func TestFactoryValidation(t *testing.T) {
	if _, err := plugin.New("clamav", plugin.BuildContext{BaseDir: t.TempDir()}, plugin.Options{"on_virus": "bogus"}); err == nil {
		t.Fatal("expected an error for an unknown on_virus action")
	}
}
