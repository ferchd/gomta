package delivery

import (
	"context"
	"testing"

	"github.com/ferchd/gomta/plugin"
)

func TestExecTimeoutIsTemporary(t *testing.T) {
	b, err := NewExec(plugin.BuildContext{BaseDir: t.TempDir()}, plugin.Options{
		"command": "sleep",
		"args": []string{"2"},
		"timeout": "20ms",
	})
	if err != nil {
		t.Fatal(err)
	}
	results := b.Deliver(context.Background(), &Message{
		ID: "timeout", To: []string{"recipient@example.test"}, Data: []byte("test"),
	})
	if !IsTemporary(results["recipient@example.test"]) {
		t.Fatalf("execution timeout should retry: %v", results["recipient@example.test"])
	}
}
