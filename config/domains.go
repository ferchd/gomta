package config

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ferchd/gomta/plugin"
)

// Domains is the set of domains for which this server accepts mail locally.
type Domains struct {
	set map[string]struct{}
}

// LoadDomains reads one domain per line. Blank lines and # comments are
// ignored.
func LoadDomains(path string) (*Domains, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read domains file: %w", err)
	}
	defer f.Close()

	d := &Domains{set: make(map[string]struct{})}
	sc := bufio.NewScanner(f)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" {
			continue
		}
		if strings.ContainsAny(line, " \t") {
			return nil, fmt.Errorf("%s:%d: expected one domain per line", path, lineNo)
		}
		if !plugin.ValidAddress("postmaster@"+line, false) {
			return nil, fmt.Errorf("%s:%d: invalid domain %q", path, lineNo, line)
		}
		d.set[line] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read domains file: %w", err)
	}
	return d, nil
}

// IsLocal reports whether domain is configured for local acceptance.
func (d *Domains) IsLocal(domain string) bool {
	if d == nil {
		return false
	}
	_, ok := d.set[strings.ToLower(strings.TrimSpace(domain))]
	return ok
}

// List returns the configured domains sorted.
func (d *Domains) List() []string {
	if d == nil {
		return nil
	}
	out := make([]string, 0, len(d.set))
	for domain := range d.set {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out
}

// Len returns the number of domains.
func (d *Domains) Len() int {
	if d == nil {
		return 0
	}
	return len(d.set)
}
