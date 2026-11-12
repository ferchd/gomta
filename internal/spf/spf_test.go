package spf

import (
	"context"
	"net"
	"strings"
	"testing"
)

// fakeDNS is a small in-memory Resolver. Missing names return a not-found
// DNSError, matching what net.DefaultResolver returns for NXDOMAIN/NODATA.
type fakeDNS struct {
	txt map[string][]string
	ips map[string][]net.IP
	mx  map[string][]*net.MX
	ptr map[string][]string
	err map[string]error
}

func newFakeDNS() *fakeDNS {
	return &fakeDNS{
		txt: map[string][]string{},
		ips: map[string][]net.IP{},
		mx:  map[string][]*net.MX{},
		ptr: map[string][]string{},
		err: map[string]error{},
	}
}

func notFound(name string) error {
	return &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

func (f *fakeDNS) LookupTXT(_ context.Context, name string) ([]string, error) {
	if err := f.err["txt:"+name]; err != nil {
		return nil, err
	}
	if v, ok := f.txt[name]; ok {
		return v, nil
	}
	return nil, notFound(name)
}

func (f *fakeDNS) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	if err := f.err["ip:"+host]; err != nil {
		return nil, err
	}
	if v, ok := f.ips[host]; ok {
		return v, nil
	}
	return nil, notFound(host)
}

func (f *fakeDNS) LookupMX(_ context.Context, name string) ([]*net.MX, error) {
	if err := f.err["mx:"+name]; err != nil {
		return nil, err
	}
	if v, ok := f.mx[name]; ok {
		return v, nil
	}
	return nil, notFound(name)
}

func (f *fakeDNS) LookupAddr(_ context.Context, addr string) ([]string, error) {
	if err := f.err["ptr:"+addr]; err != nil {
		return nil, err
	}
	if v, ok := f.ptr[addr]; ok {
		return v, nil
	}
	return nil, notFound(addr)
}

func checker(f *fakeDNS) *Checker {
	return &Checker{Resolver: f, MaxLookups: 10, MaxVoid: 2, MaxMX: 10}
}

func TestCheckIP4(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 ip4:192.0.2.0/24 -all"}
	tests := []struct {
		name string
		ip   string
		want Result
	}{
		{"match", "192.0.2.10", Pass},
		{"outside network", "198.51.100.10", Fail},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := checker(f).Check(context.Background(), net.ParseIP(tc.ip), "mail.example.com", "user@example.com")
			if out.Result != tc.want {
				t.Fatalf("got %s, want %s (%+v)", out.Result, tc.want, out)
			}
			if out.Domain != "example.com" {
				t.Fatalf("unexpected domain %q", out.Domain)
			}
		})
	}
}

func TestCheckQualifiers(t *testing.T) {
	tests := []struct {
		record string
		want   Result
	}{
		{"v=spf1 -all", Fail},
		{"v=spf1 ~all", SoftFail},
		{"v=spf1 ?all", Neutral},
		{"v=spf1 +all", Pass},
		{"v=spf1 all", Pass},
	}
	for _, tc := range tests {
		f := newFakeDNS()
		f.txt["example.com"] = []string{tc.record}
		out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.1"), "mail.example.com", "user@example.com")
		if out.Result != tc.want {
			t.Errorf("%q: got %s, want %s", tc.record, out.Result, tc.want)
		}
	}
}

func TestCheckMissingAndMultipleRecords(t *testing.T) {
	f := newFakeDNS()
	out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.1"), "helo.example", "user@example.com")
	if out.Result != None {
		t.Fatalf("missing record: got %s, want none", out.Result)
	}

	f.txt["example.com"] = []string{
		"v=spf1 ip4:192.0.2.1 -all",
		"v=spf1 ip4:192.0.2.2 -all",
	}
	out = checker(f).Check(context.Background(), net.ParseIP("192.0.2.1"), "helo.example", "user@example.com")
	if out.Result != PermError {
		t.Fatalf("multiple records: got %s, want permerror", out.Result)
	}
}

func TestCheckHeloFallback(t *testing.T) {
	f := newFakeDNS()
	f.txt["helo.example"] = []string{"v=spf1 ip4:192.0.2.1 -all"}
	out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.1"), "helo.example", "")
	if out.Result != Pass {
		t.Fatalf("got %s, want pass (%+v)", out.Result, out)
	}
	if out.Domain != "helo.example" {
		t.Fatalf("unexpected identity domain %q", out.Domain)
	}
}

func TestCheckInclude(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 include:_spf.example.net -all"}
	f.txt["_spf.example.net"] = []string{"v=spf1 ip4:192.0.2.0/24 -all"}

	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.5"), "mx", "user@example.com"); out.Result != Pass {
		t.Fatalf("included pass: got %s", out.Result)
	}
	if out := checker(f).Check(context.Background(), net.ParseIP("203.0.113.5"), "mx", "user@example.com"); out.Result != Fail {
		t.Fatalf("included fail: got %s", out.Result)
	}
}

func TestCheckIncludePermErrorAndNone(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 include:missing.example -all"}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.1"), "mx", "user@example.com"); out.Result != PermError {
		t.Fatalf("include of missing domain: got %s, want permerror", out.Result)
	}

	f.txt["example.com"] = []string{"v=spf1 include:broken.example ?all"}
	f.txt["broken.example"] = []string{
		"v=spf1 ip4:192.0.2.1 -all",
		"v=spf1 ip4:192.0.2.2 -all",
	}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.1"), "mx", "user@example.com"); out.Result != PermError {
		t.Fatalf("include of permerror domain: got %s, want permerror", out.Result)
	}
}

func TestCheckRedirect(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 redirect=_spf.example.net"}
	f.txt["_spf.example.net"] = []string{"v=spf1 ip4:192.0.2.0/24 -all"}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.5"), "mx", "user@example.com"); out.Result != Pass {
		t.Fatalf("redirect pass: got %s", out.Result)
	}

	f.txt["example.com"] = []string{"v=spf1 redirect=missing.example"}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.5"), "mx", "user@example.com"); out.Result != PermError {
		t.Fatalf("redirect to missing record: got %s, want permerror", out.Result)
	}

	f.txt["example.com"] = []string{"v=spf1 ip4:192.0.2.1 redirect=_spf.example.net"}
	f.txt["_spf.example.net"] = []string{"v=spf1 ip4:192.0.2.0/24 -all"}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.5"), "mx", "user@example.com"); out.Result != Pass {
		t.Fatalf("mechanism should be evaluated before redirect: got %s", out.Result)
	}
}

func TestCheckAMechanism(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 a:mail.example.com/24 -all"}
	f.ips["mail.example.com"] = []net.IP{net.ParseIP("192.0.2.10")}

	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.200"), "mx", "user@example.com"); out.Result != Pass {
		t.Fatalf("a/24 pass: got %s", out.Result)
	}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.3.1"), "mx", "user@example.com"); out.Result != Fail {
		t.Fatalf("a/24 fail: got %s", out.Result)
	}
}

func TestCheckAMechanismDefaultDomain(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 a -all"}
	f.ips["example.com"] = []net.IP{net.ParseIP("192.0.2.10")}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.10"), "mx", "user@example.com"); out.Result != Pass {
		t.Fatalf("got %s, want pass", out.Result)
	}
}

func TestCheckMXMechanism(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 mx -all"}
	f.mx["example.com"] = []*net.MX{
		{Host: "mx1.example.com."},
		{Host: "mx2.example.com."},
	}
	f.ips["mx1.example.com"] = []net.IP{net.ParseIP("192.0.2.20")}
	f.ips["mx2.example.com"] = []net.IP{net.ParseIP("192.0.2.21")}

	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.21"), "mx", "user@example.com"); out.Result != Pass {
		t.Fatalf("mx pass: got %s", out.Result)
	}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.99"), "mx", "user@example.com"); out.Result != Fail {
		t.Fatalf("mx fail: got %s", out.Result)
	}
}

func TestCheckMXDoesNotApplyImplicitFallback(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 mx -all"}
	// A records exist, but RFC 7208 forbids the RFC 5321 implicit MX fallback.
	f.ips["example.com"] = []net.IP{net.ParseIP("192.0.2.10")}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.10"), "mx", "user@example.com"); out.Result != Fail {
		t.Fatalf("got %s, want fail (no implicit MX)", out.Result)
	}
}

func TestCheckPTRMechanism(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 ptr -all"}
	f.ptr["192.0.2.30"] = []string{"mail.example.com."}
	f.ips["mail.example.com"] = []net.IP{net.ParseIP("192.0.2.30")}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.30"), "mx", "user@example.com"); out.Result != Pass {
		t.Fatalf("ptr pass: got %s", out.Result)
	}

	f.ptr["192.0.2.30"] = []string{"mail.other.example."}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.30"), "mx", "user@example.com"); out.Result != Fail {
		t.Fatalf("ptr mismatch: got %s, want fail", out.Result)
	}
}

func TestCheckExistsMechanism(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 exists:probe.example.com -all"}
	f.ips["probe.example.com"] = []net.IP{net.ParseIP("127.0.0.2")}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.1"), "mx", "user@example.com"); out.Result != Pass {
		t.Fatalf("exists pass: got %s", out.Result)
	}

	f.txt["example.com"] = []string{"v=spf1 exists:missing.example.com -all"}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.1"), "mx", "user@example.com"); out.Result != Fail {
		t.Fatalf("exists miss: got %s, want fail", out.Result)
	}
}

func TestCheckIP6(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 ip6:2001:db8::/32 -all"}
	if out := checker(f).Check(context.Background(), net.ParseIP("2001:db8::1"), "mx", "user@example.com"); out.Result != Pass {
		t.Fatalf("ip6 pass: got %s", out.Result)
	}
	if out := checker(f).Check(context.Background(), net.ParseIP("2001:db9::1"), "mx", "user@example.com"); out.Result != Fail {
		t.Fatalf("ip6 fail: got %s", out.Result)
	}
}

func TestCheckTempError(t *testing.T) {
	f := newFakeDNS()
	f.err["txt:example.com"] = &net.DNSError{Err: "server misbehaving", Name: "example.com", IsTemporary: true}
	out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.1"), "mx", "user@example.com")
	if out.Result != TempError {
		t.Fatalf("got %s, want temperror", out.Result)
	}
}

func TestCheckLookupLimit(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{
		"v=spf1 include:a.example include:b.example include:c.example -all",
	}
	f.txt["a.example"] = []string{"v=spf1 include:a1.example -all"}
	f.txt["b.example"] = []string{"v=spf1 include:b1.example -all"}
	f.txt["c.example"] = []string{"v=spf1 include:c1.example -all"}

	c := checker(f)
	c.MaxLookups = 2
	if out := c.Check(context.Background(), net.ParseIP("192.0.2.1"), "mx", "user@example.com"); out.Result != PermError {
		t.Fatalf("got %s, want permerror after exceeding lookup limit", out.Result)
	}
}

func TestCheckVoidLimit(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 a:missing1.example a:missing2.example a:missing3.example -all"}
	c := checker(f)
	c.MaxVoid = 1
	if out := c.Check(context.Background(), net.ParseIP("192.0.2.1"), "mx", "user@example.com"); out.Result != PermError {
		t.Fatalf("got %s, want permerror after exceeding void limit", out.Result)
	}
}

func TestCheckExplanation(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 ip4:192.0.2.0/24 -all exp=explain.example.com"}
	f.txt["explain.example.com"] = []string{"%{s} is not permitted from %{i}"}
	out := checker(f).Check(context.Background(), net.ParseIP("198.51.100.7"), "mx", "User@Example.com")
	if out.Result != Fail {
		t.Fatalf("got %s, want fail", out.Result)
	}
	if !strings.Contains(out.Explanation, "User@example.com is not permitted from 198.51.100.7") {
		t.Fatalf("unexpected explanation %q", out.Explanation)
	}
}

func TestCheckMacroDomain(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 include:_spf.%{d} -all"}
	f.txt["_spf.example.com"] = []string{"v=spf1 ip4:192.0.2.1 -all"}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.1"), "mx", "user@example.com"); out.Result != Pass {
		t.Fatalf("got %s, want pass", out.Result)
	}
}

func TestCheckInvalidIP(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 +all"}
	if out := checker(f).Check(context.Background(), nil, "mx", "user@example.com"); out.Result != None {
		t.Fatalf("nil IP should be none, got %s", out.Result)
	}
}

func TestCheckRejectsIPLiteralIdentity(t *testing.T) {
	f := newFakeDNS()
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.1"), "[192.0.2.1]", ""); out.Result != None {
		t.Fatalf("ip literal identity should be none, got %s", out.Result)
	}
}

func TestCheckMalformedRecord(t *testing.T) {
	f := newFakeDNS()
	f.txt["example.com"] = []string{"v=spf1 bogus:thing -all"}
	if out := checker(f).Check(context.Background(), net.ParseIP("192.0.2.1"), "mx", "user@example.com"); out.Result != PermError {
		t.Fatalf("malformed mechanism: got %s, want permerror", out.Result)
	}
}
