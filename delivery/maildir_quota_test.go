package delivery

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMaildirUsageSumsNestedMailbox(t *testing.T) {
	root := t.TempDir()
	box := filepath.Join(root, "mail", "example.test", "alice")
	if err := os.MkdirAll(filepath.Join(box, "new"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(box, "new", "m1"), []byte("123456"), 0o600); err != nil {
		t.Fatal(err)
	}
	n, err := maildirUsage(box)
	if err != nil || n != 6 {
		t.Fatalf("quota usage: %d, %v", n, err)
	}
}
