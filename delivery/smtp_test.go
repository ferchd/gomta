package delivery

import (
	"testing"

	"github.com/ferchd/gomta/plugin"
)

func TestAuthenticatedRelayRequiresVerifiedTLS(t *testing.T) {
	for _, tc := range []struct {
		mode     string
		insecure bool
		wantErr  bool
	}{
		{"none", false, true},
		{"opportunistic", false, true},
		{"required", true, true},
		{"required", false, false},
		{"implicit", false, false},
	} {
		_, err := NewSMTP(plugin.BuildContext{}, plugin.Options{
			"smarthost":            "localhost:2525",
			"username":             "user@example.test",
			"password":             "secret",
			"tls":                  tc.mode,
			"insecure_skip_verify": tc.insecure,
		})
		if (err != nil) != tc.wantErr {
			t.Errorf("mode %s insecure %v: got %v, wantErr %v", tc.mode, tc.insecure, err, tc.wantErr)
		}
	}
}
