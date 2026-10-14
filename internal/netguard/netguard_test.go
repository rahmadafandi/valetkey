package netguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rahmadafandi/valetkey/internal/version"
)

func TestPublic(t *testing.T) {
	for _, s := range []string{
		"127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1",
		"0.0.0.0", "224.0.0.1", "::1", "fc00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1", "::",
		"100.100.100.200", "255.255.255.255", "198.18.0.1", "192.0.0.170",
		"::ffff:169.254.169.254", "fd00:ec2::254", "fec0::1", "ff02::1",
		"fe80::1%eth0", "::1%lo",
		"::7f00:1",                          // IPv4-compatible 127.0.0.1
		"64:ff9b::a00:1", "64:ff9b::7f00:1", // NAT64 of 10.0.0.1 and 127.0.0.1
		"64:ff9b::a00:1%eth0",             // a zone must not hide the prefix
		"64:ff9b:1::a00:1",                // local-use NAT64
		"2002:7f00:1::1", "2002:a00:1::1", // 6to4 of 127.0.0.1 and 10.0.0.1
		"2001:0:4136:e378:8000:63bf:f5ff:fffe", // Teredo, embeds an IPv4 server and client
		"2001:db8::1",
		"::ffff:0:a00:1", "::ffff:0:7f00:1", // SIIT IPv4-translated 10.0.0.1 and 127.0.0.1
		"192.0.2.1", "198.51.100.1", "203.0.113.1", "192.88.99.1", "2001:20::1",
	} {
		if Public(netip.MustParseAddr(s)) {
			t.Errorf("Public(%s) = true", s)
		}
	}
	if Public(netip.Addr{}) {
		t.Error("Public(zero Addr) = true")
	}
	for _, s := range []string{"93.184.216.34", "2606:4700::1111", "1.1.1.1", "::ffff:93.184.216.34"} {
		if !Public(netip.MustParseAddr(s)) {
			t.Errorf("Public(%s) = false", s)
		}
	}
}

func TestCheckURL(t *testing.T) {
	g := &Guard{AllowHosts: []string{"mcp.internal.example.com"}}
	for _, raw := range []string{
		"http://example.com/mcp", "ftp://x", "https://user:pw@example.com/", "https://user@example.com/",
		"https:///nohost", "https:example.com", "//example.com/mcp", "example.com/mcp", "",
		"http://mcp.internal.example.com./", "http://other.example.com/", "javascript:alert(1)",
	} {
		if _, err := g.CheckURL(raw); err == nil {
			t.Errorf("CheckURL(%q) accepted", raw)
		}
	}
	for _, raw := range []string{
		"https://example.com/mcp", "HTTPS://Example.com/mcp", "http://mcp.internal.example.com/",
		"http://MCP.Internal.Example.com:8080/mcp",
	} {
		if _, err := g.CheckURL(raw); err != nil {
			t.Errorf("CheckURL(%q): %v", raw, err)
		}
	}
	if _, err := (&Guard{}).CheckURL("http://mcp.internal.example.com/"); err == nil {
		t.Error("http accepted for a host that is not allowed")
	}
}

// listener counts TCP connections that reach it; a refused dial must leave it at zero.
func listener(t *testing.T) (port string, accepted *atomic.Int32) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted = new(atomic.Int32)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	_, port, _ = net.SplitHostPort(ln.Addr().String())
	return port, accepted
}

type lookups struct {
	mu    sync.Mutex
	hosts []string
}

func (l *lookups) answer(addrs ...string) func(context.Context, string) ([]netip.Addr, error) {
	return func(_ context.Context, host string) ([]netip.Addr, error) {
		l.mu.Lock()
		l.hosts = append(l.hosts, host)
		l.mu.Unlock()
		var out []netip.Addr
		for _, a := range addrs {
			out = append(out, netip.MustParseAddr(a))
		}
		return out, nil
	}
}

func (l *lookups) seen() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.hosts...)
}

func get(t *testing.T, g *Guard, raw string) (*http.Response, error) {
	t.Helper()
	resp, err := g.Client().Get(raw)
	if err == nil {
		t.Cleanup(func() { resp.Body.Close() })
	}
	return resp, err
}

func TestDialRefusesPrivateAnswer(t *testing.T) {
	port, accepted := listener(t)
	var l lookups
	g := &Guard{Lookup: l.answer("127.0.0.1")}
	_, err := get(t, g, "https://evil.example:"+port+"/")
	if err == nil || !strings.Contains(err.Error(), "not a public address") {
		t.Fatalf("err = %v", err)
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections reached the local listener", n)
	}
	if got := l.seen(); len(got) != 1 || got[0] != "evil.example" {
		t.Fatalf("Lookup saw %v", got)
	}
}

func TestDialRefusesAnyPrivateAnswer(t *testing.T) {
	port, accepted := listener(t)
	for _, addrs := range [][]string{
		{"93.184.216.34", "10.0.0.1"},
		{"10.0.0.1", "93.184.216.34"},
		{"2606:4700::1111", "::1"},
		{"93.184.216.34", "64:ff9b::7f00:1"},
	} {
		var l lookups
		g := &Guard{Lookup: l.answer(addrs...)}
		if _, err := get(t, g, "https://rebind.example:"+port+"/"); !errors.Is(err, ErrNotPublic) || !strings.Contains(err.Error(), "not a public address") {
			t.Errorf("%v: err = %v", addrs, err)
		}
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections reached the local listener", n)
	}
}

func TestDialRefusesIPLiteralsWithoutLookup(t *testing.T) {
	port, accepted := listener(t)
	g := &Guard{Lookup: func(context.Context, string) ([]netip.Addr, error) {
		t.Error("Lookup called for an IP literal")
		return nil, errors.New("unexpected lookup")
	}}
	for _, host := range []string{
		"10.0.0.1", "127.0.0.1", "[::1]", "[::ffff:127.0.0.1]", "[::ffff:7f00:1]", "[0:0:0:0:0:ffff:127.0.0.1]",
		"[fe80::1%25lo]", "[::1%25lo]", "[64:ff9b::7f00:1%25lo]", "[::7f00:1]",
	} {
		_, err := get(t, g, "https://"+host+":"+port+"/")
		if !errors.Is(err, ErrNotPublic) || strings.Contains(err.Error(), "resolves to") {
			t.Errorf("%s: err = %v", host, err)
		}
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections reached the local listener", n)
	}
}

// Numeric host spellings that some resolvers read as 127.0.0.1 must still go
// through Lookup, whose answer is checked, rather than straight to a dial.
func TestNumericHostSpellingsAreChecked(t *testing.T) {
	port, accepted := listener(t)
	for _, host := range []string{"2130706433", "0x7f.1", "017700000001", "127.1", "0177.0.0.1"} {
		var l lookups
		g := &Guard{Lookup: l.answer("127.0.0.1")}
		_, err := get(t, g, "https://"+host+":"+port+"/")
		if err == nil || !strings.Contains(err.Error(), "not a public address") {
			t.Errorf("%s: err = %v", host, err)
		}
		if got := l.seen(); len(got) != 1 || got[0] != host {
			t.Errorf("%s: Lookup saw %v", host, got)
		}
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections reached the local listener", n)
	}
}

func TestSystemResolverLocalhost(t *testing.T) {
	port, accepted := listener(t)
	g := &Guard{}
	for _, host := range []string{"localhost", "localhost.", "LOCALHOST"} {
		if _, err := get(t, g, "https://"+host+":"+port+"/"); err == nil {
			t.Errorf("%s: request succeeded", host)
		}
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections reached the local listener", n)
	}
}

func TestLookupEmptyOrFailing(t *testing.T) {
	port, accepted := listener(t)
	empty := &Guard{Lookup: func(context.Context, string) ([]netip.Addr, error) { return nil, nil }}
	if _, err := get(t, empty, "https://empty.example:"+port+"/"); err == nil || !strings.Contains(err.Error(), "no address") {
		t.Errorf("empty answer: err = %v", err)
	}
	failing := &Guard{Lookup: func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("dns down") }}
	if _, err := get(t, failing, "https://fail.example:"+port+"/"); err == nil || !strings.Contains(err.Error(), "dns down") {
		t.Errorf("failing lookup: err = %v", err)
	}
	invalid := &Guard{Lookup: func(context.Context, string) ([]netip.Addr, error) { return []netip.Addr{{}}, nil }}
	if _, err := get(t, invalid, "https://invalid.example:"+port+"/"); err == nil {
		t.Error("zero Addr answer: request succeeded")
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections reached the local listener", n)
	}
}

func hostPort(t *testing.T, ts *httptest.Server) (host, port string) {
	t.Helper()
	u, _ := url.Parse(ts.URL)
	return u.Hostname(), u.Port()
}

func TestAllowedHostReachedWithUserAgent(t *testing.T) {
	var ua atomic.Value
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua.Store(r.UserAgent())
		io.WriteString(w, "ok")
	}))
	defer ts.Close()
	g := &Guard{AllowHosts: []string{"127.0.0.1"}}
	resp, err := get(t, g, ts.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != "ok" {
		t.Fatalf("body = %q", b)
	}
	if got, _ := ua.Load().(string); got != version.UserAgent() || !strings.HasPrefix(got, "valetkey/") {
		t.Fatalf("User-Agent = %q", got)
	}
}

func TestAllowedHostNameIsCaseInsensitive(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	defer ts.Close()
	_, port := hostPort(t, ts)
	var l lookups
	g := &Guard{AllowHosts: []string{"upstream.test"}, Lookup: l.answer("127.0.0.1")}
	u, err := g.CheckURL("http://UPSTREAM.Test:" + port + "/")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := get(t, g, u.String()); err != nil {
		t.Fatal(err)
	}
}

// A trailing dot names the same host in DNS but is not the allowed spelling,
// so it gets the public-address check instead of the exemption.
func TestAllowedHostTrailingDotIsNotAllowed(t *testing.T) {
	port, accepted := listener(t)
	var l lookups
	g := &Guard{AllowHosts: []string{"upstream.test"}, Lookup: l.answer("127.0.0.1")}
	if _, err := get(t, g, "https://upstream.test.:"+port+"/"); err == nil {
		t.Fatal("request succeeded")
	}
	if n := accepted.Load(); n != 0 {
		t.Fatalf("%d connections reached the local listener", n)
	}
}

func TestRedirects(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch p := r.URL.Path; {
		case p == "/private":
			http.Redirect(w, r, "http://10.0.0.1/", http.StatusFound)
		case p == "/private-https":
			http.Redirect(w, r, "https://10.0.0.1/", http.StatusFound)
		case p == "/plain-http":
			http.Redirect(w, r, "http://example.com/", http.StatusFound)
		case p == "/userinfo":
			http.Redirect(w, r, "https://u:p@example.com/", http.StatusFound)
		case strings.HasPrefix(p, "/hop/"):
			var n int
			fmt.Sscanf(p, "/hop/%d", &n)
			if n == 0 {
				io.WriteString(w, "done")
				return
			}
			http.Redirect(w, r, fmt.Sprintf("/hop/%d", n-1), http.StatusFound)
		}
	}))
	defer ts.Close()
	g := &Guard{AllowHosts: []string{"127.0.0.1"}, Lookup: func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.1")}, nil
	}}

	if _, err := get(t, g, ts.URL+"/private"); err == nil {
		t.Error("redirect to http://10.0.0.1/ followed")
	}
	if _, err := get(t, g, ts.URL+"/private-https"); err == nil || !strings.Contains(err.Error(), "not a public address") {
		t.Errorf("redirect to https://10.0.0.1/: err = %v", err)
	}
	if _, err := get(t, g, ts.URL+"/plain-http"); err == nil || !strings.Contains(err.Error(), "https") {
		t.Errorf("redirect to http on a host that is not allowed: err = %v", err)
	}
	if _, err := get(t, g, ts.URL+"/userinfo"); err == nil {
		t.Error("redirect to a URL with user info followed")
	}
	resp, err := get(t, g, ts.URL+"/hop/3")
	if err != nil {
		t.Fatalf("3 redirects: %v", err)
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != "done" {
		t.Fatalf("3 redirects: body = %q", b)
	}
	if _, err := get(t, g, ts.URL+"/hop/4"); err == nil || !strings.Contains(err.Error(), "too many redirects") {
		t.Errorf("4 redirects: err = %v", err)
	}
}

func TestBodyCap(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n int
		fmt.Sscanf(r.URL.Path, "/%d", &n)
		if r.URL.Query().Has("length") {
			w.Header().Set("Content-Length", fmt.Sprint(n))
		}
		w.Write(make([]byte, n))
	}))
	defer ts.Close()
	g := &Guard{AllowHosts: []string{"127.0.0.1"}}

	// With a Content-Length the last bytes arrive together with io.EOF.
	for _, query := range []string{"", "?length"} {
		resp, err := get(t, g, fmt.Sprintf("%s/%d%s", ts.URL, MaxBody, query))
		if err != nil {
			t.Fatal(err)
		}
		if b, err := io.ReadAll(resp.Body); err != nil || len(b) != MaxBody {
			t.Errorf("exactly MaxBody %s: read %d bytes, err %v", query, len(b), err)
		}

		resp, err = get(t, g, fmt.Sprintf("%s/%d%s", ts.URL, MaxBody+1, query))
		if err != nil {
			t.Fatal(err)
		}
		if b, err := io.ReadAll(resp.Body); err == nil || len(b) > MaxBody {
			t.Errorf("MaxBody+1 %s: read %d bytes, err %v", query, len(b), err)
		}
	}
}

func TestIgnoresProxyEnvironment(t *testing.T) {
	var proxied atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxied.Add(1)
		io.WriteString(w, "proxy")
	}))
	defer proxy.Close()
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(k, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "direct") }))
	defer ts.Close()
	_, port := hostPort(t, ts)
	var l lookups
	// 127.0.0.1 is allowed so that a proxy on it would be reachable if the client used one.
	g := &Guard{AllowHosts: []string{"upstream.test", "127.0.0.1"}, Lookup: l.answer("127.0.0.1")}
	resp, err := get(t, g, "http://upstream.test:"+port+"/")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != "direct" {
		t.Fatalf("body = %q", b)
	}
	if n := proxied.Load(); n != 0 {
		t.Fatalf("proxy received %d requests", n)
	}
}

// Many unreachable answers must not hold a request open for one timeout each.
func TestDialHasOneDeadline(t *testing.T) {
	oldTimeout, oldDial := connectTimeout, dialAddr
	t.Cleanup(func() { connectTimeout, dialAddr = oldTimeout, oldDial })
	connectTimeout = 200 * time.Millisecond
	var mu sync.Mutex
	var tried []string
	dialAddr = func(ctx context.Context, network, addr string) (net.Conn, error) {
		mu.Lock()
		tried = append(tried, addr)
		mu.Unlock()
		<-ctx.Done() // a blackholed address: the SYN is never answered
		return nil, ctx.Err()
	}
	var l lookups
	g := &Guard{Lookup: l.answer("93.184.216.34", "93.184.216.35", "93.184.216.36", "93.184.216.37", "93.184.216.38")}
	start := time.Now()
	if _, err := get(t, g, "https://blackhole.example/"); err == nil {
		t.Fatal("request succeeded")
	}
	if d := time.Since(start); d > 2*connectTimeout {
		t.Fatalf("dial took %v with a %v connect timeout", d, connectTimeout)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(tried) == 0 || len(tried) > 3 {
		t.Fatalf("tried %d addresses: %v", len(tried), tried)
	}
}

// One transport per Guard, so idle connections are reused rather than piling up per client.
func TestClientsShareTransport(t *testing.T) {
	g := &Guard{}
	a, b := g.Client(), g.Client()
	if a == b || a.Transport != b.Transport {
		t.Fatal("two clients from one Guard do not share a transport")
	}
	if (&Guard{}).Client().Transport == a.Transport {
		t.Fatal("two Guards share a transport")
	}
}
