package ratelimit

import (
	"net"
	"testing"

	"github.com/ferchd/gomta/plugin"
)

func TestSmartScopeUsesOnlyIPForUnauthenticatedSenders(t *testing.T) {
	p := &Plugin{scope: "smart"}
	a := plugin.NewTx()
	a.RemoteIP = net.ParseIP("203.0.113.20")
	a.MailFrom = "first@example.org"
	b := plugin.NewTx()
	b.RemoteIP = net.ParseIP("203.0.113.20")
	b.MailFrom = "second@example.net"
	if p.keyValue(a) != p.keyValue(b) {
		t.Fatal("rotating MAIL FROM bypasses IP limit")
	}
	b.RemoteIP = net.ParseIP("203.0.113.21")
	if p.keyValue(a) == p.keyValue(b) {
		t.Fatal("different IPs share limit")
	}
}
