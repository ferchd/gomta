package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ferchd/gomta/config"
	"github.com/ferchd/gomta/internal/app"
	"github.com/ferchd/gomta/internal/auth"
	_ "github.com/ferchd/gomta/internal/plugins/all"
	"github.com/ferchd/gomta/plugin"
)

func testOptions(dir string) Options {
	return Options{
		Dir:           dir,
		Hostname:      "mail.example.com",
		Domains:       []string{"example.com", "example.org"},
		AdminUser:     "postmaster@example.com",
		AdminPassword: "correct horse battery",
		Selector:      "sel",
		KeyBits:       1024,
	}
}

func TestInitCreatesRunnableConfiguration(t *testing.T) {
	dir := t.TempDir()
	res, err := Init(testOptions(dir))
	if err != nil {
		t.Fatal(err)
	}
	if res.PasswordGenerated {
		t.Fatal("password should not be generated when one is supplied")
	}
	if res.Password != "correct horse battery" {
		t.Fatalf("unexpected password %q", res.Password)
	}
	if got, want := res.Domains, []string{"example.com", "example.org"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("domains = %v, want %v", got, want)
	}

	for _, path := range res.GeneratedFiles {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("missing generated file %s: %v", path, err)
		}
	}

	// The config must load with strict field checking.
	cfg, err := config.Load(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Hostname != "mail.example.com" {
		t.Fatalf("unexpected hostname %q", cfg.Hostname)
	}
	if len(cfg.Listeners) != 3 {
		t.Fatalf("unexpected listeners: %+v", cfg.Listeners)
	}
	if cfg.Listeners[1].Mode != "submission" || !cfg.Listeners[1].RequireAuth {
		t.Fatalf("unexpected submission listener: %+v", cfg.Listeners[1])
	}

	domains, err := config.LoadDomains(cfg.DomainsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !domains.IsLocal("example.com") || !domains.IsLocal("EXAMPLE.ORG") || domains.IsLocal("other.example") {
		t.Fatalf("unexpected domains: %v", domains.List())
	}

	plugins, err := config.LoadPlugins(cfg.PluginsFile, cfg.BaseDir)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(plugins.Plugins))
	for _, p := range plugins.Plugins {
		names = append(names, p.Name)
	}
	for _, want := range []string{"headers", "dkim_sign", "dkim_verify", "dmarc", "spf", "helo"} {
		if !contains(names, want) {
			t.Errorf("plugins.yaml is missing %q: %v", want, names)
		}
	}

	users, err := auth.Load(cfg.UsersFile)
	if err != nil {
		t.Fatal(err)
	}
	if users.Len() != 1 || !users.Authenticate("postmaster@example.com", "correct horse battery") {
		t.Fatal("generated credentials do not authenticate")
	}
	if users.Authenticate("postmaster@example.com", "wrong password") {
		t.Fatal("wrong password accepted")
	}

	// app.Load ties every component together; this catches template/config
	// drift (bad paths, unknown plugin options, missing DKIM key, etc.).
	a, err := app.Load(res.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	stats := a.Stats()
	if stats.Hostname != "mail.example.com" || stats.Users != 1 {
		t.Fatalf("unexpected stats: %+v", stats)
	}
	if stats.Backends.Local != "maildir" || stats.Backends.Outbound != "smtp" {
		t.Fatalf("unexpected backends: %+v", stats.Backends)
	}
	if len(stats.Plugins[string(plugin.HookData)]) == 0 {
		t.Fatalf("no data-hook plugins registered: %+v", stats.Plugins)
	}

	// The DKIM key must parse and the DNS output must mention every domain.
	if _, err := os.Stat(res.KeyFile); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range res.DNSRecords {
		seen[r.Name] = true
		if r.Type == "TXT" && strings.Contains(r.Value, "v=DKIM1") && !strings.Contains(r.Name, "._domainkey.") {
			t.Errorf("DKIM record has an unexpected name %q", r.Name)
		}
	}
	for _, domain := range res.Domains {
		if !seen["_dmarc."+domain] || !seen[domain] {
			t.Errorf("missing DNS records for %s: %+v", domain, res.DNSRecords)
		}
	}
}

func TestInitRefusesToOverwrite(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(testOptions(dir)); err != nil {
		t.Fatal(err)
	}
	if _, err := Init(testOptions(dir)); err == nil {
		t.Fatal("expected an error when files already exist")
	}
	opts := testOptions(dir)
	opts.Force = true
	if _, err := Init(opts); err != nil {
		t.Fatalf("force should overwrite: %v", err)
	}
}

func TestInitGeneratesPasswordAndAdminUser(t *testing.T) {
	dir := t.TempDir()
	opts := Options{
		Dir:      dir,
		Hostname: "mail.example.com",
		Domains:  []string{"example.com"},
		KeyBits:  1024,
	}
	res, err := Init(opts)
	if err != nil {
		t.Fatal(err)
	}
	if !res.PasswordGenerated || len(res.Password) < 16 {
		t.Fatalf("expected a generated password, got %q", res.Password)
	}
	if res.AdminUser != "postmaster@example.com" {
		t.Fatalf("unexpected admin user %q", res.AdminUser)
	}
	users, err := auth.Load(filepath.Join(dir, "users.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if !users.Authenticate(res.AdminUser, res.Password) {
		t.Fatal("generated password does not authenticate")
	}
}

func TestInitValidation(t *testing.T) {
	if _, err := Init(Options{Dir: t.TempDir(), Hostname: "mail.example.com"}); err == nil {
		t.Fatal("expected an error when no domains are given")
	}
	if _, err := Init(Options{
		Dir:      t.TempDir(),
		Hostname: "mail.example.com",
		Domains:  []string{"not a domain"},
		KeyBits:  1024,
	}); err == nil {
		t.Fatal("expected an error for an invalid domain")
	}
	if _, err := Init(Options{
		Dir:           t.TempDir(),
		Hostname:      "mail.example.com",
		Domains:       []string{"example.com"},
		AdminPassword: "short",
		KeyBits:       1024,
	}); err == nil {
		t.Fatal("expected an error for a short password")
	}
}

func TestNormalizeDomains(t *testing.T) {
	got := normalizeDomains([]string{"Example.COM, example.org", "example.com.", ""})
	want := []string{"example.com", "example.org"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("normalizeDomains = %v, want %v", got, want)
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
