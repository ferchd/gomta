// Command gomta runs and manages a GoMTA server.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/ferchd/gomta/delivery"
	"github.com/ferchd/gomta/internal/app"
	"github.com/ferchd/gomta/internal/dkimkey"
	_ "github.com/ferchd/gomta/internal/plugins/all"
	"github.com/ferchd/gomta/internal/setup"
	"github.com/ferchd/gomta/plugin"
)

// These are set with -ldflags at build time.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "gomta:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage(os.Stdout)
		return nil
	}
	switch args[0] {
	case "serve":
		return cmdServe(args[1:])
	case "init":
		return cmdInit(args[1:])
	case "check":
		return cmdCheck(args[1:])
	case "status":
		return cmdStatus(args[1:])
	case "send":
		return cmdSend(args[1:])
	case "dkim-keygen":
		return cmdDKIMKeygen(args[1:])
	case "plugins":
		return cmdPlugins(args[1:])
	case "backends":
		return cmdBackends(args[1:])
	case "version", "--version", "-version":
		fmt.Printf("gomta %s (commit %s, built %s, %s)\n", version, commit, date, runtime.Version())
		return nil
	case "help", "-h", "--help":
		usage(os.Stdout)
		return nil
	default:
		return fmt.Errorf("unknown command %q (try `gomta help`)", args[0])
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `GoMTA - a modular SMTP server

Usage:
  gomta <command> [flags]

Commands:
  init          Create config, policy files, TLS certificate, and DKIM key
  serve         Run the SMTP server and delivery queue
  check         Validate configuration and print a summary
  status        Print a runtime snapshot without starting the server
  send          Send a test message through an SMTP listener
  dkim-keygen   Generate a DKIM private key and DNS TXT record
  plugins       List built-in plugins
  backends      List delivery backends
  version       Print version information

Examples:
  gomta init -domain example.com -hostname mail.example.com
  gomta check -config gomta.yaml
  gomta serve -config gomta.yaml
  gomta send -server 127.0.0.1:5587 -from you@example.com -to postmaster@example.com
  gomta dkim-keygen -domain example.com -out dkim/default.key

Run "gomta <command> -h" for command-specific flags.
`)
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	configPath := fs.String("config", "gomta.yaml", "path to gomta.yaml")
	logLevel := fs.String("log-level", "", "override log level (debug, info, warn, error)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := app.LoadWithOptions(*configPath, app.LoadOptions{LogLevel: *logLevel})
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return a.Run(ctx)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	dir := fs.String("dir", ".", "directory to initialize")
	hostname := fs.String("hostname", "", "SMTP hostname (default: OS hostname)")
	domain := fs.String("domain", "", "comma-separated local domains")
	adminUser := fs.String("admin-user", "", "admin login (default: postmaster@<first-domain>)")
	adminPassword := fs.String("admin-password", "", "admin password (default: generated)")
	selector := fs.String("selector", "default", "DKIM selector")
	bits := fs.Int("bits", 2048, "DKIM RSA key size")
	force := fs.Bool("force", false, "overwrite existing configuration files")
	if err := fs.Parse(args); err != nil {
		return err
	}
	domains := []string{}
	if *domain != "" {
		domains = append(domains, *domain)
	}
	domains = append(domains, fs.Args()...)
	if len(domains) == 0 {
		return errors.New("a domain is required: gomta init -domain example.com")
	}
	res, err := setup.Init(setup.Options{
		Dir:           *dir,
		Hostname:      *hostname,
		Domains:       domains,
		AdminUser:     *adminUser,
		AdminPassword: *adminPassword,
		Selector:      *selector,
		KeyBits:       *bits,
		Force:         *force,
	})
	if err != nil {
		return err
	}
	fmt.Printf("GoMTA initialized in %s\n\n", res.Dir)
	fmt.Printf("  hostname:  %s\n", res.Hostname)
	fmt.Printf("  domains:   %s\n", strings.Join(res.Domains, ", "))
	fmt.Printf("  config:    %s\n", res.ConfigPath)
	fmt.Printf("  admin:     %s\n", res.AdminUser)
	if res.PasswordGenerated {
		fmt.Printf("  password:  %s   (shown once; change it before production)\n", res.Password)
	} else {
		fmt.Printf("  password:  (provided on the command line)\n")
	}
	fmt.Printf("  DKIM key:  %s (selector %q)\n\n", res.KeyFile, res.Selector)

	fmt.Println("DNS records to publish:")
	for _, r := range res.DNSRecords {
		fmt.Printf("  %-45s %-7s %s\n", r.Name, r.Type, r.Value)
		if r.Note != "" {
			fmt.Printf("  %-45s %-7s # %s\n", "", "", r.Note)
		}
	}
	fmt.Printf(`
Next steps:
  1. Review gomta.yaml and plugins.yaml (ports default to 2525/5587 for unprivileged runs).
  2. Validate everything:  gomta check -config %s
  3. Start the server:     gomta serve -config %s
  4. Send a test message:  gomta send -server 127.0.0.1:5587 -from %s -to %s
`, res.ConfigPath, res.ConfigPath, res.AdminUser, res.AdminUser)
	return nil
}

func cmdCheck(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	configPath := fs.String("config", "gomta.yaml", "path to gomta.yaml")
	asJSON := fs.Bool("json", false, "print JSON summary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := app.Load(*configPath)
	if err != nil {
		return err
	}
	defer a.Close()
	stats := a.Stats()
	if *asJSON {
		return printJSON(stats)
	}
	fmt.Println("configuration OK")
	fmt.Printf("  hostname:  %s\n", stats.Hostname)
	fmt.Printf("  domains:   %s\n", strings.Join(stats.Domains, ", "))
	fmt.Printf("  users:     %d\n", stats.Users)
	fmt.Printf("  local:     %s\n", stats.Backends.Local)
	fmt.Printf("  outbound:  %s\n", stats.Backends.Outbound)
	if stats.Backends.Filter != "" {
		fmt.Printf("  filter:    %s\n", stats.Backends.Filter)
	}
	fmt.Printf("  queue:     %s\n", stats.QueuePath)
	fmt.Println("  listeners:")
	for _, l := range stats.Listeners {
		auth := ""
		if l.RequireAuth {
			auth = ", require_auth"
		}
		fmt.Printf("    - %-12s %-22s mode=%s tls=%s%s\n", l.Name, l.Address, l.Mode, l.TLS, auth)
	}
	fmt.Println("  plugins:")
	for _, hook := range plugin.Hooks() {
		if names := stats.Plugins[string(hook)]; len(names) > 0 {
			fmt.Printf("    - %-11s %s\n", hook, strings.Join(names, ", "))
		}
	}
	fmt.Printf("  status:    %s\n", orNone(a.Config.StatusAddr))
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	configPath := fs.String("config", "gomta.yaml", "path to gomta.yaml")
	asJSON := fs.Bool("json", true, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	a, err := app.Load(*configPath)
	if err != nil {
		return err
	}
	defer a.Close()
	stats := a.Stats()
	if *asJSON {
		return printJSON(stats)
	}
	fmt.Printf("%s  uptime %s\n", stats.Hostname, stats.Uptime)
	fmt.Printf("queue: %d queued, %d failed, %d quarantined\n", stats.Queue.Queued, stats.Queue.Failed, stats.Queue.Quarantined)
	fmt.Printf("domains: %s\n", strings.Join(stats.Domains, ", "))
	return nil
}

func cmdSend(args []string) error {
	fs := flag.NewFlagSet("send", flag.ContinueOnError)
	server := fs.String("server", "127.0.0.1:5587", "SMTP server address")
	from := fs.String("from", "", "envelope/header sender")
	to := fs.String("to", "", "comma-separated recipients")
	subject := fs.String("subject", "GoMTA test message", "subject")
	body := fs.String("body", "Hello from GoMTA!\n", "plain-text body")
	file := fs.String("file", "", "read the body from a file instead")
	user := fs.String("user", "", "AUTH username")
	password := fs.String("password", "", "AUTH password")
	tlsMode := fs.String("tls", "starttls", "starttls, implicit or none")
	helo := fs.String("helo", "localhost", "HELO name")
	insecure := fs.Bool("insecure", false, "skip TLS certificate verification")
	timeout := fs.Duration("timeout", 30*time.Second, "overall timeout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *from == "" {
		return errors.New("-from is required")
	}
	if *to == "" {
		return errors.New("-to is required")
	}
	bodyBytes := []byte(*body)
	if *file != "" {
		data, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		bodyBytes = data
	}

	recipients := splitList(*to)
	msg := buildMessage(*from, recipients, *subject, bodyBytes, *helo)
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", *server)
	if err != nil {
		return err
	}
	defer conn.Close()

	tlsCfg := &tls.Config{
		ServerName:         hostOnly(*server),
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: *insecure,
	}
	var client *smtp.Client
	switch strings.ToLower(*tlsMode) {
	case "none":
		client = smtp.NewClient(conn)
	case "implicit":
		tconn := tls.Client(conn, tlsCfg)
		if err := tconn.HandshakeContext(ctx); err != nil {
			return err
		}
		client = smtp.NewClient(tconn)
	case "starttls":
		client, err = smtp.NewClientStartTLS(conn, tlsCfg)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("tls must be starttls, implicit or none, got %q", *tlsMode)
	}
	defer client.Close()
	client.CommandTimeout = *timeout
	client.SubmissionTimeout = *timeout

	if err := client.Hello(*helo); err != nil {
		return err
	}
	if *user != "" {
		if err := client.Auth(sasl.NewPlainClient("", *user, *password)); err != nil {
			return err
		}
	}
	if err := client.Mail(*from, nil); err != nil {
		return err
	}
	for _, rcpt := range recipients {
		if err := client.Rcpt(rcpt, nil); err != nil {
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		_ = w.Close()
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if err := client.Quit(); err != nil {
		return err
	}
	fmt.Printf("sent %d byte message to %s\n", len(msg), strings.Join(recipients, ", "))
	return nil
}

func cmdDKIMKeygen(args []string) error {
	fs := flag.NewFlagSet("dkim-keygen", flag.ContinueOnError)
	domain := fs.String("domain", "", "domain the key signs for")
	selector := fs.String("selector", "default", "DKIM selector")
	bits := fs.Int("bits", 2048, "RSA key size")
	out := fs.String("out", "", "write the private key to this path (default: stdout)")
	ed := fs.Bool("ed25519", false, "generate an Ed25519 key instead of RSA")
	asJSON := fs.Bool("json", false, "print JSON")
	force := fs.Bool("force", false, "overwrite the output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *domain == "" {
		return errors.New("-domain is required")
	}
	var (
		keyPEM, dnsValue string
		err              error
	)
	if *ed {
		_, keyPEM, dnsValue, err = dkimkey.GenerateEd25519()
	} else {
		_, keyPEM, dnsValue, err = dkimkey.GenerateRSA(*bits)
	}
	if err != nil {
		return err
	}
	name := dkimkey.RecordName(*selector, *domain)
	record := fmt.Sprintf("%s 3600 IN TXT %q", name, dnsValue)

	if *out != "" {
		if !*force {
			if _, err := os.Stat(*out); err == nil {
				return fmt.Errorf("%s already exists (use -force)", *out)
			}
		}
		if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil && filepath.Dir(*out) != "." {
			return err
		}
		if err := os.WriteFile(*out, []byte(keyPEM), 0o600); err != nil {
			return err
		}
	}
	if *asJSON {
		return printJSON(map[string]string{
			"private_key": keyPEM,
			"key_file":    *out,
			"dns_name":    name,
			"dns_value":   dnsValue,
		})
	}
	if *out != "" {
		fmt.Printf("wrote private key to %s\n\n", *out)
	} else {
		fmt.Println("# DKIM private key (PEM)")
		fmt.Print(keyPEM)
		fmt.Println()
	}
	fmt.Println("# DNS record")
	fmt.Println(record)
	return nil
}

func cmdPlugins(args []string) error {
	fs := flag.NewFlagSet("plugins", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	names := plugin.Default.Names()
	if *asJSON {
		return printJSON(names)
	}
	for _, name := range names {
		fmt.Println(name)
	}
	return nil
}

func cmdBackends(args []string) error {
	fs := flag.NewFlagSet("backends", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	names := delivery.Default.Names()
	if *asJSON {
		return printJSON(names)
	}
	for _, name := range names {
		fmt.Println(name)
	}
	return nil
}

func buildMessage(from string, to []string, subject string, body []byte, helo string) []byte {
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		copy(id, []byte(fmt.Sprintf("%d", time.Now().UnixNano())))
	}
	host := hostOnly(helo)
	if host == "" {
		host = "localhost"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", strings.Join(to, ", "))
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&b, "Message-ID: <%s@%s>\r\n", hex.EncodeToString(id), host)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	b.Write(bytesReplaceCRLF(body))
	return []byte(b.String())
}

// bytesReplaceCRLF normalizes bare LF to CRLF for SMTP DATA.
func bytesReplaceCRLF(body []byte) []byte {
	s := strings.ReplaceAll(string(body), "\r\n", "\n")
	s = strings.ReplaceAll(s, "\n", "\r\n")
	if !strings.HasSuffix(s, "\r\n") {
		s += "\r\n"
	}
	return []byte(s)
}

func splitList(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func hostOnly(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(addr, "[]")
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(disabled)"
	}
	return s
}
