package plugin

import (
	"bytes"
	"net/mail"
	"strings"
)

// PrependHeaders inserts headers before the existing header block of an RFC
// 5322 message. The original message (including its line endings) is left
// untouched. Header values are sanitized to prevent header injection.
func PrependHeaders(data []byte, headers []Header) []byte {
	if len(headers) == 0 {
		return data
	}
	var prefix bytes.Buffer
	for _, h := range headers {
		name := strings.TrimSpace(h.Name)
		if name == "" {
			continue
		}
		prefix.WriteString(name)
		prefix.WriteString(": ")
		prefix.WriteString(SanitizeHeaderValue(h.Value))
		prefix.WriteString("\r\n")
	}
	if prefix.Len() == 0 {
		return data
	}
	if len(data) == 0 {
		return append(prefix.Bytes(), []byte("\r\n")...)
	}
	return append(prefix.Bytes(), data...)
}

// HasHeader reports whether the message header block contains name.
func HasHeader(data []byte, name string) bool {
	head, _, _ := splitMessage(data)
	for _, line := range headerLines(head) {
		if i := strings.IndexByte(line, ':'); i > 0 && strings.EqualFold(strings.TrimSpace(line[:i]), name) {
			return true
		}
	}
	return false
}

// HeaderValue returns the first value of name in the header block.
func HeaderValue(data []byte, name string) string {
	head, _, _ := splitMessage(data)
	lines := headerLines(head)
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		idx := strings.IndexByte(line, ':')
		if idx <= 0 || !strings.EqualFold(strings.TrimSpace(line[:idx]), name) {
			continue
		}
		value := strings.TrimSpace(line[idx+1:])
		for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || strings.HasPrefix(lines[i+1], "\t")) {
			i++
			value += " " + strings.TrimSpace(lines[i])
		}
		return value
	}
	return ""
}

// ParseHeaders returns the header block as a map of canonical key to values.
func ParseHeaders(data []byte) map[string][]string {
	out := make(map[string][]string)
	head, _, _ := splitMessage(data)
	lines := headerLines(head)
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(line[:idx]))
		value := strings.TrimSpace(line[idx+1:])
		for i+1 < len(lines) && (strings.HasPrefix(lines[i+1], " ") || strings.HasPrefix(lines[i+1], "\t")) {
			i++
			value += " " + strings.TrimSpace(lines[i])
		}
		out[key] = append(out[key], value)
	}
	return out
}

// FromDomain extracts the domain from a From header value.
func FromDomain(data []byte) string {
	v := HeaderValue(data, "From")
	if v == "" {
		return ""
	}
	if addr, err := mail.ParseAddress(v); err == nil {
		return Domain(addr.Address)
	}
	return Domain(v)
}

// Domain returns the lower-cased domain of an SMTP address. It accepts bare
// addresses, angle-bracketed addresses, and display-name forms.
func Domain(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" || addr == "<>" {
		return ""
	}
	if parsed, err := mail.ParseAddress(addr); err == nil {
		addr = parsed.Address
	}
	addr = strings.Trim(addr, "<> \t")
	at := strings.LastIndexByte(addr, '@')
	if at < 0 || at == len(addr)-1 {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(addr[at+1:]))
}

// LocalPart returns the local part of an SMTP address.
func LocalPart(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" || addr == "<>" {
		return ""
	}
	if parsed, err := mail.ParseAddress(addr); err == nil {
		addr = parsed.Address
	}
	addr = strings.Trim(addr, "<> \t")
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 {
		return ""
	}
	return addr[:at]
}

// NormalizeAddress trims SMTP brackets and whitespace and lower-cases the
// domain while preserving local-part case.
func NormalizeAddress(addr string) string {
	addr = strings.TrimSpace(strings.Trim(strings.TrimSpace(addr), "<>"))
	if addr == "" {
		return ""
	}
	if parsed, err := mail.ParseAddress(addr); err == nil {
		addr = parsed.Address
	}
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 {
		return addr
	}
	return addr[:at] + "@" + strings.ToLower(addr[at+1:])
}

// ValidAddress performs a conservative syntax check suitable for envelope
// addresses. The null reverse-path <> is accepted only when allowEmpty is true.
func ValidAddress(addr string, allowEmpty bool) bool {
	addr = strings.TrimSpace(addr)
	if addr == "" || addr == "<>" {
		return allowEmpty
	}
	addr = strings.Trim(addr, "<>")
	if len(addr) > 320 || strings.ContainsAny(addr, " \t\r\n<>") {
		return false
	}
	at := strings.LastIndexByte(addr, '@')
	if at <= 0 || at == len(addr)-1 {
		return false
	}
	local, domain := addr[:at], addr[at+1:]
	if len(local) > 64 || strings.HasPrefix(local, ".") || strings.HasSuffix(local, ".") || strings.Contains(local, "..") {
		return false
	}
	return validDomain(domain)
}

func validDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 || strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				continue
			}
			return false
		}
	}
	return true
}

// SanitizeHeaderValue collapses CR/LF and control characters so untrusted
// data cannot inject extra header fields.
func SanitizeHeaderValue(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if r == '\t' || (r >= 0x20 && r != 0x7f) {
			b.WriteRune(r)
		} else {
			b.WriteByte(' ')
		}
	}
	return strings.TrimSpace(b.String())
}

func splitMessage(data []byte) (head, body []byte, sep string) {
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return data[:i], data[i+4:], "\r\n\r\n"
	}
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		return data[:i], data[i+2:], "\n\n"
	}
	// Header-only or malformed message: treat everything as headers.
	return data, nil, ""
}

func headerLines(head []byte) []string {
	s := strings.ReplaceAll(string(head), "\r\n", "\n")
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}
