// Package spf implements the SPF (RFC 7208) subset used for inbound policy
// checks. It supports ip4, ip6, a, mx, ptr, include, exists, redirect, exp and
// all, with lookup/void limits.
package spf

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/ferchd/gomta/plugin"
)

// Result is an SPF evaluation result.
type Result string

const (
	Pass      Result = "pass"
	Fail      Result = "fail"
	SoftFail  Result = "softfail"
	Neutral   Result = "neutral"
	None      Result = "none"
	TempError Result = "temperror"
	PermError Result = "permerror"
)

// Outcome is the result of an SPF check.
type Outcome struct {
	Result      Result
	Domain      string
	Identity    string
	Explanation string
}

// Resolver is the DNS surface used by SPF. net.DefaultResolver satisfies it.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
	LookupMX(ctx context.Context, name string) ([]*net.MX, error)
	LookupAddr(ctx context.Context, addr string) ([]string, error)
}

// Checker evaluates SPF records.
type Checker struct {
	Resolver   Resolver
	MaxLookups int
	MaxVoid    int
	MaxMX      int
}

// New returns a checker using the system resolver.
func New() *Checker {
	return &Checker{Resolver: net.DefaultResolver, MaxLookups: 10, MaxVoid: 2, MaxMX: 10}
}

// Check evaluates SPF for a connecting IP and SMTP identity.
func (c *Checker) Check(ctx context.Context, ip net.IP, helo, mailFrom string) Outcome {
	if c == nil {
		c = New()
	}
	if c.Resolver == nil {
		c.Resolver = net.DefaultResolver
	}
	if c.MaxLookups <= 0 {
		c.MaxLookups = 10
	}
	if c.MaxVoid <= 0 {
		c.MaxVoid = 2
	}
	if c.MaxMX <= 0 {
		c.MaxMX = 10
	}
	out := Outcome{Result: None}
	if ip == nil {
		return out
	}
	identity := plugin.NormalizeAddress(mailFrom)
	domain := plugin.Domain(identity)
	if domain == "" {
		identity = strings.Trim(strings.TrimSpace(helo), "[]")
		domain = normalizeDomain(identity)
	}
	if domain == "" || strings.Contains(domain, ":") || net.ParseIP(domain) != nil {
		return out
	}
	out.Domain = domain
	out.Identity = identity

	e := &eval{checker: c, ip: ip, helo: helo, sender: identity, senderDomain: domain}
	res, exp := e.evalDomain(ctx, domain, 0)
	out.Result = res
	if res == Fail || res == SoftFail {
		out.Explanation = exp
	}
	return out
}

type eval struct {
	checker      *Checker
	ip           net.IP
	helo         string
	sender       string
	senderDomain string
	lookups      int
	voids        int
}

type mech struct {
	qual    byte
	name    string
	arg     string
	hasCIDR bool
	cidr    int
}

func (e *eval) evalDomain(ctx context.Context, domain string, depth int) (Result, string) {
	if depth > 10 {
		return PermError, ""
	}
	domain = normalizeDomain(e.expandMacros(domain))
	if domain == "" {
		return PermError, ""
	}
	records, err := e.lookupTXT(ctx, domain)
	if err != nil {
		if errors.Is(err, errPerm) {
			return PermError, ""
		}
		if isNotFound(err) {
			return None, ""
		}
		return TempError, ""
	}
	var record string
	found := 0
	for _, txt := range records {
		txt = strings.TrimSpace(txt)
		if strings.HasPrefix(strings.ToLower(txt), "v=spf1") {
			found++
			record = txt
		}
	}
	if found == 0 {
		return None, ""
	}
	if found > 1 {
		return PermError, ""
	}
	terms := strings.Fields(record)
	if len(terms) == 0 {
		return PermError, ""
	}
	// Parse the whole record before evaluating it: RFC 7208 requires syntax
	// errors anywhere in the record to produce "permerror", and modifiers may
	// appear in any order (for example, "exp=" after "-all").
	var redirect, expDomain string
	var mechanisms []mech
	for _, term := range terms[1:] {
		if term == "" {
			continue
		}
		if isModifier(term) {
			key, val, _ := strings.Cut(term, "=")
			switch strings.ToLower(key) {
			case "redirect":
				redirect = val
			case "exp":
				expDomain = val
			}
			// Unknown modifiers are ignored.
			continue
		}
		m, err := parseMech(term)
		if err != nil {
			return PermError, ""
		}
		mechanisms = append(mechanisms, m)
	}
	for _, m := range mechanisms {
		matched, err := e.match(ctx, m, domain, depth)
		if err != nil {
			if errors.Is(err, errTemp) {
				return TempError, ""
			}
			return PermError, ""
		}
		if matched {
			res := resultForQualifier(m.qual)
			if res == Fail {
				return res, e.explanation(ctx, expDomain, domain)
			}
			return res, ""
		}
	}
	if redirect != "" {
		target := e.expandMacros(redirect)
		if target == "" {
			return PermError, ""
		}
		if err := e.countLookup(); err != nil {
			return PermError, ""
		}
		res, _ := e.evalDomain(ctx, target, depth+1)
		if res == None {
			return PermError, ""
		}
		return res, ""
	}
	return Neutral, ""
}

func (e *eval) match(ctx context.Context, m mech, domain string, depth int) (bool, error) {
	switch m.name {
	case "all":
		return true, nil
	case "ip4", "ip6":
		return matchIP(m, e.ip), nil
	case "a":
		if err := e.countLookup(); err != nil {
			return false, err
		}
		target := e.argDomain(m.arg, domain)
		if target == "" {
			return false, errPerm
		}
		ips, err := e.lookupIP(ctx, target)
		if err != nil {
			if isNotFound(err) {
				return false, e.addVoid()
			}
			return false, errTemp
		}
		return matchCIDRs(m, e.ip, ips), nil
	case "mx":
		if err := e.countLookup(); err != nil {
			return false, err
		}
		target := e.argDomain(m.arg, domain)
		if target == "" {
			return false, errPerm
		}
		records, err := e.checker.Resolver.LookupMX(ctx, target)
		if err != nil {
			if isNotFound(err) {
				return false, e.addVoid()
			}
			return false, errTemp
		}
		if len(records) == 0 {
			// RFC 7208: do not apply the RFC 5321 implicit MX fallback.
			return false, e.addVoid()
		}
		if len(records) > e.checker.MaxMX {
			return false, errPerm
		}
		for _, mx := range records {
			ips, err := e.lookupIP(ctx, normalizeDomain(mx.Host))
			if err != nil {
				continue
			}
			if matchCIDRs(m, e.ip, ips) {
				return true, nil
			}
		}
		return false, nil
	case "ptr":
		spec := e.argDomain(m.arg, domain)
		if spec == "" {
			return false, errPerm
		}
		if err := e.countLookup(); err != nil {
			return false, err
		}
		names, err := e.checker.Resolver.LookupAddr(ctx, e.ip.String())
		if err != nil {
			if isNotFound(err) {
				return false, e.addVoid()
			}
			return false, errTemp
		}
		for _, name := range names {
			name = normalizeDomain(name)
			if name != spec && !strings.HasSuffix(name, "."+spec) {
				continue
			}
			ips, err := e.lookupIP(ctx, name)
			if err != nil {
				continue
			}
			for _, ip := range ips {
				if ip.Equal(e.ip) {
					return true, nil
				}
			}
		}
		return false, nil
	case "include":
		target := e.expandMacros(m.arg)
		if target == "" {
			return false, errPerm
		}
		if err := e.countLookup(); err != nil {
			return false, err
		}
		res, _ := e.evalDomain(ctx, target, depth+1)
		switch res {
		case Pass:
			return true, nil
		case TempError:
			return false, errTemp
		case PermError, None:
			return false, errPerm
		default:
			return false, nil
		}
	case "exists":
		target := e.expandMacros(m.arg)
		if target == "" {
			return false, errPerm
		}
		if err := e.countLookup(); err != nil {
			return false, err
		}
		ips, err := e.checker.Resolver.LookupIP(ctx, "ip4", target)
		if err != nil {
			if isNotFound(err) {
				return false, e.addVoid()
			}
			return false, errTemp
		}
		return len(ips) > 0, nil
	default:
		return false, errPerm
	}
}

func (e *eval) argDomain(arg, current string) string {
	if arg == "" {
		return current
	}
	if i := strings.LastIndexByte(arg, '/'); i >= 0 {
		arg = arg[:i]
	}
	return normalizeDomain(e.expandMacros(arg))
}

func (e *eval) lookupTXT(ctx context.Context, domain string) ([]string, error) {
	return e.checker.Resolver.LookupTXT(ctx, domain)
}

func (e *eval) lookupIP(ctx context.Context, domain string) ([]net.IP, error) {
	ips, err := e.checker.Resolver.LookupIP(ctx, "ip", domain)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

func (e *eval) countLookup() error {
	e.lookups++
	if e.lookups > e.checker.MaxLookups {
		return errPerm
	}
	return nil
}

func (e *eval) addVoid() error {
	e.voids++
	if e.voids > e.checker.MaxVoid {
		return errPerm
	}
	return nil
}

func (e *eval) explanation(ctx context.Context, expDomain, current string) string {
	if expDomain == "" {
		return ""
	}
	target := e.expandMacros(expDomain)
	if target == "" {
		return ""
	}
	// exp is opportunistic; a failure must not change the result.
	txts, err := e.checker.Resolver.LookupTXT(ctx, target)
	if err != nil || len(txts) != 1 {
		return ""
	}
	// Multiple character-strings in one TXT record are concatenated without
	// adding spaces (RFC 7208 section 6.2).
	text := strings.Join(txts, "")
	return e.expandMacrosWith(text, current)
}

func (e *eval) expandMacros(s string) string { return e.expandMacrosWith(s, "") }

func (e *eval) expandMacrosWith(s, currentDomain string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			b.WriteByte(s[i])
			continue
		}
		if i+1 >= len(s) {
			b.WriteByte('%')
			break
		}
		next := s[i+1]
		switch next {
		case '%':
			b.WriteByte('%')
			i++
		case '_':
			b.WriteByte(' ')
			i++
		case '-':
			b.WriteString("%20")
			i++
		case '{':
			end := strings.IndexByte(s[i+2:], '}')
			if end < 0 {
				b.WriteByte('%')
				continue
			}
			body := s[i+2 : i+2+end]
			i = i + 2 + end
			if len(body) == 0 {
				continue
			}
			letter := body[0]
			var value string
			switch letter {
			case 's':
				value = e.sender
			case 'l':
				value = plugin.LocalPart(e.sender)
			case 'o':
				value = e.senderDomain
			case 'd':
				value = currentDomain
			case 'i':
				value = ipMacro(e.ip)
			case 'h':
				value = e.helo
			case 'v':
				if e.ip.To4() != nil {
					value = "in-addr"
				} else {
					value = "ip6"
				}
			}
			if value == "" && letter == 'd' {
				value = e.senderDomain
			}
			b.WriteString(value)
		default:
			b.WriteByte('%')
		}
	}
	return b.String()
}

func ipMacro(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	// RFC 7208 IPv6 macro form: dot-separated nibbles.
	raw := ip.To16()
	if raw == nil {
		return ip.String()
	}
	var parts []string
	for _, b := range raw {
		parts = append(parts, fmt.Sprintf("%x.%x", b>>4, b&0x0f))
	}
	return strings.Join(parts, ".")
}

// isModifier reports whether term is a modifier (name=value) rather than a
// mechanism. The '=' must appear in the name position, before any ':' or '/'
// belonging to a mechanism argument.
func isModifier(term string) bool {
	eq := strings.IndexByte(term, '=')
	if eq <= 0 {
		return false
	}
	return !strings.ContainsAny(term[:eq], ":/+~?-")
}

func parseMech(term string) (mech, error) {
	m := mech{qual: '+'}
	if term == "" {
		return m, errPerm
	}
	switch term[0] {
	case '+', '-', '~', '?':
		m.qual = term[0]
		term = term[1:]
	}
	name, arg, _ := strings.Cut(term, ":")
	m.name = strings.ToLower(strings.TrimSpace(name))
	if m.name == "" {
		return m, errPerm
	}
	m.arg = strings.TrimSpace(arg)
	if m.name == "a" || m.name == "mx" {
		if i := strings.LastIndexByte(m.arg, '/'); i >= 0 {
			cidr, err := strconv.Atoi(m.arg[i+1:])
			if err != nil || cidr < 0 || cidr > 128 {
				return m, errPerm
			}
			m.hasCIDR = true
			m.cidr = cidr
			m.arg = m.arg[:i]
		}
	}
	if m.name == "ip4" || m.name == "ip6" {
		if i := strings.LastIndexByte(m.arg, '/'); i >= 0 {
			cidr, err := strconv.Atoi(m.arg[i+1:])
			if err != nil {
				return m, errPerm
			}
			m.hasCIDR = true
			m.cidr = cidr
			m.arg = m.arg[:i]
		}
	}
	switch m.name {
	case "all":
		if m.arg != "" {
			return m, errPerm
		}
	case "include", "exists":
		if m.arg == "" {
			return m, errPerm
		}
	case "ptr":
		// The domain is optional and defaults to the current domain.
	case "a", "mx":
		// arg is optional
	case "ip4":
		ip := net.ParseIP(m.arg)
		if ip == nil || ip.To4() == nil {
			return m, errPerm
		}
		if !m.hasCIDR {
			m.cidr = 32
		}
		if m.cidr > 32 {
			return m, errPerm
		}
	case "ip6":
		ip := net.ParseIP(m.arg)
		if ip == nil || ip.To4() != nil {
			return m, errPerm
		}
		if !m.hasCIDR {
			m.cidr = 128
		}
	default:
		return m, errPerm
	}
	return m, nil
}

func matchIP(m mech, ip net.IP) bool {
	spec := net.ParseIP(m.arg)
	if spec == nil {
		return false
	}
	if m.name == "ip4" {
		a, b := ip.To4(), spec.To4()
		return a != nil && b != nil && a.Mask(net.CIDRMask(m.cidr, 32)).Equal(b.Mask(net.CIDRMask(m.cidr, 32)))
	}
	a, b := ip.To16(), spec.To16()
	return a != nil && b != nil && a.Mask(net.CIDRMask(m.cidr, 128)).Equal(b.Mask(net.CIDRMask(m.cidr, 128)))
}

func matchCIDRs(m mech, ip net.IP, ips []net.IP) bool {
	if m.name == "ip6" || ip.To4() == nil {
		cidr := m.cidr
		if !m.hasCIDR {
			cidr = 128
		}
		if cidr > 128 {
			cidr = 128
		}
		for _, candidate := range ips {
			a, b := ip.To16(), candidate.To16()
			if a != nil && b != nil && a.Mask(net.CIDRMask(cidr, 128)).Equal(b.Mask(net.CIDRMask(cidr, 128))) {
				return true
			}
		}
		return false
	}
	cidr := m.cidr
	if !m.hasCIDR {
		cidr = 32
	}
	if cidr > 32 {
		cidr = 32
	}
	for _, candidate := range ips {
		a, b := ip.To4(), candidate.To4()
		if a != nil && b != nil && a.Mask(net.CIDRMask(cidr, 32)).Equal(b.Mask(net.CIDRMask(cidr, 32))) {
			return true
		}
	}
	return false
}

func resultForQualifier(q byte) Result {
	switch q {
	case '-':
		return Fail
	case '~':
		return SoftFail
	case '?':
		return Neutral
	default:
		return Pass
	}
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(strings.TrimSuffix(d, "."))
	if strings.ContainsAny(d, " \t\r\n") {
		return ""
	}
	return strings.ToLower(d)
}

var (
	errTemp = errors.New("spf: temporary failure")
	errPerm = errors.New("spf: permanent failure")
)

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}
