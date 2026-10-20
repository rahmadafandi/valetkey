package config

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func valid() map[string]string {
	return map[string]string{
		"PUBLIC_URL":         "https://mcp.example.com/",
		"DATABASE_URL":       "postgres://x",
		"OIDC_ISSUER":        "https://idp.example.com",
		"OIDC_CLIENT_ID":     "cid",
		"OIDC_CLIENT_SECRET": "csecret",
		"ALLOWED_DOMAINS":    " Example.com, example.org ",
		"VAULT_KEY":          base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"SESSION_KEY":        strings.Repeat("s", 32),
		"JENKINS_URL":        "https://jenkins.example.com/",
		"LOKI_URL":           "https://loki.example.com",
		"LOKI_INSECURE":      "true",
	}
}

func TestLoadValid(t *testing.T) {
	c, err := Load(env(valid()))
	if err != nil {
		t.Fatal(err)
	}
	if c.PublicURL != "https://mcp.example.com" {
		t.Errorf("PublicURL = %q", c.PublicURL)
	}
	if strings.Join(c.AllowedDomains, ",") != "example.com,example.org" {
		t.Errorf("AllowedDomains = %v", c.AllowedDomains)
	}
	if c.Addr != ":8080" || c.AccessTTL != time.Hour || c.RefreshTTL != 720*time.Hour || c.SessionTTL != 12*time.Hour {
		t.Errorf("defaults: addr=%q access=%v refresh=%v session=%v", c.Addr, c.AccessTTL, c.RefreshTTL, c.SessionTTL)
	}
	if c.CatalogFile != "catalog.json" {
		t.Errorf("catalog file: %q", c.CatalogFile)
	}
	if got := c.Upstreams["jenkins"]; got.URL != "https://jenkins.example.com" || got.Insecure {
		t.Errorf("jenkins = %+v", got)
	}
	if got := c.Upstreams["loki"]; !got.Insecure {
		t.Errorf("loki = %+v", got)
	}
	if _, ok := c.Upstreams["argocd"]; ok {
		t.Error("argocd should be absent when ARGOCD_URL is unset")
	}
	if len(c.VaultKey) != 32 {
		t.Errorf("VaultKey len = %d", len(c.VaultKey))
	}
}

func TestLoadListsAllMissing(t *testing.T) {
	m := valid()
	delete(m, "OIDC_CLIENT_SECRET")
	m["ALLOWED_DOMAINS"] = " , "
	_, err := Load(env(m))
	if err == nil {
		t.Fatal("want error")
	}
	for _, k := range []string{"OIDC_CLIENT_SECRET", "ALLOWED_DOMAINS or ALLOWED_EMAILS"} {
		if !strings.Contains(err.Error(), k) {
			t.Errorf("error %q does not name %s", err, k)
		}
	}
}

func TestVaultKeyAcceptsHexAndBase64(t *testing.T) {
	want := make([]byte, 32)
	for i := range want {
		want[i] = byte(i)
	}
	for name, v := range map[string]string{"hex": hex.EncodeToString(want), "base64": base64.StdEncoding.EncodeToString(want)} {
		m := valid()
		m["VAULT_KEY"] = v
		c, err := Load(env(m))
		if err != nil || !bytes.Equal(c.VaultKey, want) {
			t.Errorf("%s: key=%x err=%v", name, c.VaultKey, err)
		}
	}
}

func TestLoadRejectsBadKeys(t *testing.T) {
	m := valid()
	m["VAULT_KEY"] = base64.StdEncoding.EncodeToString(make([]byte, 16))
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "VAULT_KEY") {
		t.Errorf("short vault key: err = %v", err)
	}
	m["VAULT_KEY"] = hex.EncodeToString(make([]byte, 16))
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "VAULT_KEY") {
		t.Errorf("short hex vault key: err = %v", err)
	}
	m = valid()
	m["SESSION_KEY"] = "short"
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "SESSION_KEY") {
		t.Errorf("short session key: err = %v", err)
	}
	m = valid()
	m["ACCESS_TOKEN_TTL"] = "soon"
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "ACCESS_TOKEN_TTL") {
		t.Errorf("bad ttl: err = %v", err)
	}
}

func TestLoadPublicURL(t *testing.T) {
	m := valid()
	m["PUBLIC_URL"] = "HTTPS://MCP.Example.com/"
	if c, err := Load(env(m)); err != nil || c.PublicURL != "https://mcp.example.com" {
		t.Errorf("normalise: %q, %v", c.PublicURL, err)
	}
	for _, bad := range []string{"ftp://x.com", "mcp.example.com", "https://", "https://x.com/app", "https://x.com?a=1",
		"https://x.com#f", "https://u:p@x.com", "https://x.com:443", "http://x.com:80"} {
		m["PUBLIC_URL"] = bad
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "PUBLIC_URL") {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	m["PUBLIC_URL"] = "http://localhost:8080"
	if _, err := Load(env(m)); err != nil {
		t.Errorf("localhost:8080: %v", err)
	}
}

func TestLoadRejectsNonPositiveTTL(t *testing.T) {
	for _, k := range []string{"ACCESS_TOKEN_TTL", "REFRESH_TOKEN_TTL", "SESSION_TTL"} {
		for _, v := range []string{"0s", "-1h"} {
			m := valid()
			m[k] = v
			if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), k) {
				t.Errorf("%s=%s: err = %v", k, v, err)
			}
		}
	}
}

func TestAllowLists(t *testing.T) {
	m := valid()
	delete(m, "ALLOWED_DOMAINS")
	if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "ALLOWED_DOMAINS or ALLOWED_EMAILS") {
		t.Fatalf("neither list set: %v", err)
	}
	m["ALLOWED_EMAILS"] = "A@x.com"
	c, err := Load(env(m))
	if err != nil || strings.Join(c.AllowedEmails, ",") != "a@x.com" {
		t.Fatalf("emails only: %v, %v", c.AllowedEmails, err)
	}
}

func TestAuditRetentionAndDatabaseDefault(t *testing.T) {
	m := valid()
	delete(m, "DATABASE_URL")
	c, err := Load(env(m))
	if err != nil {
		t.Fatal(err)
	}
	if c.AuditRetention != 90*24*time.Hour {
		t.Errorf("AuditRetention = %v", c.AuditRetention)
	}
	if c.DatabaseURL != "sqlite://./valetkey.db" {
		t.Errorf("DatabaseURL = %q", c.DatabaseURL)
	}
	m["AUDIT_RETENTION_DAYS"] = "-1"
	if _, err := Load(env(m)); err == nil {
		t.Error("negative retention accepted")
	}
}

func TestLoadOIDCIssuerNeedsHTTPS(t *testing.T) {
	m := valid()
	for _, bad := range []string{"http://idp.example.com", "http://10.0.0.5:8080", "idp.example.com", "ftp://idp.example.com"} {
		m["OIDC_ISSUER"] = bad
		if _, err := Load(env(m)); err == nil || !strings.Contains(err.Error(), "OIDC_ISSUER") {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
	for _, ok := range []string{"https://idp.example.com", "http://127.0.0.1:5556/dex", "http://localhost:8081", "http://[::1]:9000"} {
		m["OIDC_ISSUER"] = ok
		if _, err := Load(env(m)); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
}

func TestUpstreamAllowHosts(t *testing.T) {
	m := valid()
	c, err := Load(env(m))
	if err != nil || len(c.UpstreamAllowHosts) != 0 {
		t.Fatalf("unset: %v, %v", c.UpstreamAllowHosts, err)
	}
	m["UPSTREAM_ALLOW_HOSTS"] = " Mcp.Internal.Example.com, 127.0.0.1 "
	c, err = Load(env(m))
	if err != nil || strings.Join(c.UpstreamAllowHosts, ",") != "mcp.internal.example.com,127.0.0.1" {
		t.Fatalf("set: %v, %v", c.UpstreamAllowHosts, err)
	}
}
