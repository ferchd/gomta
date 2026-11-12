package exec

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ferchd/gomta/plugin"
)

func TestExecFilterOutputIsBounded(t *testing.T) {
	p := &Plugin{
		command: os.Args[0], args: []string{"-test.run=TestExecOutputHelper"},
		env: plugin.Options{"GOMTA_EXEC_TEST_OUTPUT": "1"},
		timeout: 3*time.Second, replaceBody: false, tempfailOnError: true,
		maxOutput: 64,
	}
	out, err := p.Run(context.Background(), plugin.HookData, plugin.NewTx())
	if err != nil { t.Fatal(err) }
	if out.Action != plugin.ActionTempFail { t.Fatalf("overflow not rejected: %+v", out) }
}
func TestExecOutputHelper(t *testing.T) {
	if os.Getenv("GOMTA_EXEC_TEST_OUTPUT") != "1" { return }
	fmt.Print(strings.Repeat("a", 4096))
	os.Exit(0)
}
