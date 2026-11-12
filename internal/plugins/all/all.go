// Package all registers every built-in plugin. Import it for side effects:
//
//	import _ "github.com/ferchd/gomta/internal/plugins/all"
package all

import (
	_ "github.com/ferchd/gomta/internal/plugins/clamav"
	_ "github.com/ferchd/gomta/internal/plugins/dkimsign"
	_ "github.com/ferchd/gomta/internal/plugins/dkimverify"
	_ "github.com/ferchd/gomta/internal/plugins/dmarc"
	_ "github.com/ferchd/gomta/internal/plugins/dnsbl"
	_ "github.com/ferchd/gomta/internal/plugins/exec"
	_ "github.com/ferchd/gomta/internal/plugins/greylist"
	_ "github.com/ferchd/gomta/internal/plugins/headers"
	_ "github.com/ferchd/gomta/internal/plugins/helo"
	_ "github.com/ferchd/gomta/internal/plugins/ratelimit"
	_ "github.com/ferchd/gomta/internal/plugins/rspamd"
	_ "github.com/ferchd/gomta/internal/plugins/spf"
)
