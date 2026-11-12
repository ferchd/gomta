package plugin

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Options is a plugin's free-form YAML configuration map.
type Options map[string]any

// String returns a string option or def.
func (o Options) String(key, def string) string {
	if o == nil {
		return def
	}
	v, ok := o[key]
	if !ok || v == nil {
		return def
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

// Bool returns a boolean option or def.
func (o Options) Bool(key string, def bool) bool {
	if o == nil {
		return def
	}
	v, ok := o[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case bool:
		return t
	case string:
		b, err := strconv.ParseBool(t)
		if err == nil {
			return b
		}
	case int:
		return t != 0
	}
	return def
}

// Int returns an integer option or def.
func (o Options) Int(key string, def int) int {
	if o == nil {
		return def
	}
	v, ok := o[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case int:
		return t
	case int64:
		return int(t)
	case float64:
		return int(t)
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(t))
		if err == nil {
			return n
		}
	}
	return def
}

// Duration returns a duration option or def. Strings use time.ParseDuration;
// bare numbers are interpreted as seconds.
func (o Options) Duration(key string, def time.Duration) time.Duration {
	if o == nil {
		return def
	}
	v, ok := o[key]
	if !ok || v == nil {
		return def
	}
	switch t := v.(type) {
	case time.Duration:
		return t
	case string:
		d, err := time.ParseDuration(strings.TrimSpace(t))
		if err == nil {
			return d
		}
	case int:
		return time.Duration(t) * time.Second
	case int64:
		return time.Duration(t) * time.Second
	case float64:
		return time.Duration(t * float64(time.Second))
	}
	return def
}

// Strings returns a string slice option or nil.
func (o Options) Strings(key string) []string {
	if o == nil {
		return nil
	}
	v, ok := o[key]
	if !ok || v == nil {
		return nil
	}
	switch t := v.(type) {
	case []string:
		return append([]string(nil), t...)
	case []any:
		out := make([]string, 0, len(t))
		for _, item := range t {
			out = append(out, fmt.Sprint(item))
		}
		return out
	case string:
		if strings.TrimSpace(t) == "" {
			return nil
		}
		parts := strings.Split(t, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		return out
	}
	return nil
}

// Map returns a nested option map.
func (o Options) Map(key string) Options {
	if o == nil {
		return Options{}
	}
	v, ok := o[key]
	if !ok || v == nil {
		return Options{}
	}
	switch t := v.(type) {
	case map[string]any:
		return Options(t)
	case Options:
		return t
	case map[any]any:
		out := make(Options, len(t))
		for k, v := range t {
			out[fmt.Sprint(k)] = v
		}
		return out
	}
	return Options{}
}

// Decode re-encodes the options into a struct with yaml tags. Unknown fields
// are ignored so plugins can remain forward compatible.
func (o Options) Decode(v any) error {
	b, err := yaml.Marshal(map[string]any(o))
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, v)
}

// HomeDir returns the current user's home directory. It is a variable so tests
// can replace it.
var homeDir = func() (string, error) { return os.UserHomeDir() }
