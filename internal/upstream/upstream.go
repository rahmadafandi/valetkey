// Package upstream holds HTTP helpers shared by the integrations.
package upstream

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ErrUnauthorized marks an upstream 401/403: the user's stored credentials were rejected.
var ErrUnauthorized = errors.New("upstream rejected the credentials")

// Client returns an HTTP client for one upstream. Timeouts come from the request context.
func Client(insecure bool) *http.Client {
	if !insecure {
		return &http.Client{}
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	return &http.Client{Transport: t}
}

// Origin is the scheme and host of raw, e.g. the Grafana behind a datasource proxy URL.
func Origin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

// StatusErr turns a status >= 400 into an error carrying the start of the body.
func StatusErr(system string, code int, body []byte) error {
	if code < 400 {
		return nil
	}
	msg := strings.TrimSpace(string(body))
	if len(msg) > 300 {
		msg = msg[:300]
	}
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		return fmt.Errorf("%s %d: %s: %w", system, code, msg, ErrUnauthorized)
	}
	return fmt.Errorf("%s %d: %s", system, code, msg)
}

// SetAuth applies c["token"] (as Bearer unless it already names a scheme) and/or
// basic auth from c["username"] and c["password"].
func SetAuth(req *http.Request, c map[string]string) {
	if tok := c["token"]; tok != "" {
		if !strings.Contains(tok, " ") {
			tok = "Bearer " + tok
		}
		req.Header.Set("Authorization", tok)
	}
	if c["username"] != "" {
		req.SetBasicAuth(c["username"], c["password"])
	}
}

// ParseTime accepts RFC3339, or "YYYY-MM-DD[ HH:MM[:SS]]" (T also accepted) read
// in time.Local. Set TZ to choose the zone; the image defaults to UTC.
func ParseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	for _, l := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(l, s, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
