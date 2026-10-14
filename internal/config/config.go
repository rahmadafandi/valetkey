// Package config reads valetkey's settings from the environment.
package config

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Systems are the upstreams valetkey integrates; each is enabled by <SYSTEM>_URL.
var Systems = []string{"jenkins", "argocd", "loki", "metrics", "bitbucket"}

type Upstream struct {
	URL      string
	Insecure bool // skip TLS verification (self-signed internal endpoints)
}

type Config struct {
	Addr           string
	PublicURL      string // origin only, no trailing slash
	DatabaseURL    string
	GoogleClientID string
	GoogleSecret   string
	AllowedDomains []string // lowercase
	VaultKey       []byte   // 32 bytes
	SessionKey     []byte
	AccessTTL      time.Duration
	RefreshTTL     time.Duration
	Upstreams      map[string]Upstream // only systems whose URL is set
	CatalogFile    string
}

func Load(getenv func(string) string) (Config, error) {
	var missing []string
	need := func(k string) string {
		v := strings.TrimSpace(getenv(k))
		if v == "" {
			missing = append(missing, k)
		}
		return v
	}
	or := func(k, def string) string {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			return v
		}
		return def
	}

	c := Config{
		Addr:           or("ADDR", ":8080"),
		PublicURL:      strings.TrimRight(need("PUBLIC_URL"), "/"),
		DatabaseURL:    need("DATABASE_URL"),
		GoogleClientID: need("GOOGLE_CLIENT_ID"),
		GoogleSecret:   need("GOOGLE_CLIENT_SECRET"),
		CatalogFile:    or("CATALOG_FILE", "catalog.json"),
		Upstreams:      map[string]Upstream{},
	}
	for _, d := range strings.Split(need("ALLOWED_DOMAINS"), ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			c.AllowedDomains = append(c.AllowedDomains, d)
		}
	}
	if len(c.AllowedDomains) == 0 && !slices.Contains(missing, "ALLOWED_DOMAINS") {
		missing = append(missing, "ALLOWED_DOMAINS")
	}
	vaultKey, sessionKey := need("VAULT_KEY"), need("SESSION_KEY")
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required env: %s", strings.Join(missing, ", "))
	}

	var err error
	if c.PublicURL, err = normalizeOrigin(c.PublicURL); err != nil {
		return Config{}, fmt.Errorf("PUBLIC_URL: %w", err)
	}
	if c.VaultKey, err = decodeKey(vaultKey); err != nil {
		return Config{}, err
	}
	if len(sessionKey) < 32 {
		return Config{}, errors.New("SESSION_KEY must be at least 32 characters")
	}
	c.SessionKey = []byte(sessionKey)
	if c.AccessTTL, err = time.ParseDuration(or("ACCESS_TOKEN_TTL", "1h")); err != nil {
		return Config{}, fmt.Errorf("ACCESS_TOKEN_TTL: %w", err)
	}
	if c.RefreshTTL, err = time.ParseDuration(or("REFRESH_TOKEN_TTL", "720h")); err != nil {
		return Config{}, fmt.Errorf("REFRESH_TOKEN_TTL: %w", err)
	}
	if c.AccessTTL <= 0 {
		return Config{}, errors.New("ACCESS_TOKEN_TTL must be positive")
	}
	if c.RefreshTTL <= 0 {
		return Config{}, errors.New("REFRESH_TOKEN_TTL must be positive")
	}
	for _, s := range Systems {
		p := strings.ToUpper(s)
		if u := strings.TrimRight(strings.TrimSpace(getenv(p+"_URL")), "/"); u != "" {
			c.Upstreams[s] = Upstream{URL: u, Insecure: getenv(p+"_INSECURE") == "true"}
		}
	}
	return c, nil
}

// decodeKey reads a 32-byte key as 64 hex characters (openssl rand -hex 32) or as
// base64 (openssl rand -base64 32). Hex is checked first: a 64-char hex string is
// also valid base64, but would decode to 48 bytes.
func decodeKey(s string) ([]byte, error) {
	if k, err := hex.DecodeString(s); err == nil && len(k) == 32 {
		return k, nil
	}
	if k, err := base64.StdEncoding.DecodeString(s); err == nil && len(k) == 32 {
		return k, nil
	}
	return nil, errors.New("VAULT_KEY must be 32 bytes as 64 hex characters (openssl rand -hex 32) or base64")
}

// normalizeOrigin checks raw is a bare http(s) origin and returns it with a
// lowercase scheme and host and no trailing slash.
func normalizeOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("scheme must be http or https")
	}
	if u.Hostname() == "" {
		return "", errors.New("host is required")
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", errors.New("must be an origin only (no path, query, fragment or userinfo)")
	}
	if p := u.Port(); (scheme == "https" && p == "443") || (scheme == "http" && p == "80") {
		return "", fmt.Errorf("remove the default port :%s", p)
	}
	return scheme + "://" + strings.ToLower(u.Host), nil
}
