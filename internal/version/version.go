// Package version names this build. Version is set at link time:
// go build -ldflags "-X github.com/rahmadafandi/valetkey/internal/version.Version=v0.2.0".
package version

import (
	"net/http"
	"runtime/debug"
	"strings"
)

var Version string

// String is the link-time version, else the module version that go install
// records, else "dev".
func String() string {
	if Version != "" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return "dev"
}

func UserAgent() string { return "valetkey/" + strings.TrimPrefix(String(), "v") }

type transport struct{ base http.RoundTripper }

// Transport sets valetkey's User-Agent on every request it sends.
func Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return transport{base}
}

func (t transport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("User-Agent", UserAgent())
	return t.base.RoundTrip(r)
}
