// Package netguard is the HTTP client for servers that users point valetkey
// at. It refuses loopback, private, link-local and other non-public addresses
// when it dials, after DNS, so a user cannot make valetkey reach its own network.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/rahmadafandi/valetkey/internal/version"
)

const MaxBody = 1 << 20

var (
	connectTimeout = 10 * time.Second
	dialAddr       = (&net.Dialer{}).DialContext
)

type Guard struct {
	AllowHosts []string // exact lowercase host names that skip the address check and may use http
	Lookup     func(ctx context.Context, host string) ([]netip.Addr, error)

	once      sync.Once
	transport http.RoundTripper // shared by every Client, so idle connections are reused
}

var notPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2001:20::/28"),
	netip.MustParsePrefix("fec0::/10"),
	// IPv6 ranges that embed or translate to an IPv4 address, which may be private.
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("::ffff:0:0:0/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// Public reports whether a is an address on the public internet.
func Public(a netip.Addr) bool {
	a = a.WithZone("").Unmap() // Prefix.Contains never matches an address with a zone
	if !a.IsGlobalUnicast() || a.IsPrivate() {
		return false
	}
	for _, p := range notPublic {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

func (g *Guard) allowed(host string) bool {
	return slices.Contains(g.AllowHosts, strings.ToLower(host))
}

// CheckURL accepts an absolute https URL with a host and no user info; http only for an allowed host.
func (g *Guard) CheckURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Hostname() == "" {
		return nil, errors.New("URL needs a scheme and a host")
	}
	if u.User != nil {
		return nil, errors.New("URL must not contain a user name or password")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && g.allowed(u.Hostname()):
	default:
		return nil, errors.New("URL must use https")
	}
	return u, nil
}

func (g *Guard) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{a}, nil
	}
	if g.Lookup != nil {
		return g.Lookup(ctx, host)
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func (g *Guard) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	addrs, err := g.lookup(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("netguard: %s has no address", host)
	}
	if !g.allowed(host) {
		_, literalErr := netip.ParseAddr(host)
		for _, a := range addrs {
			switch {
			case Public(a):
			case literalErr == nil:
				return nil, fmt.Errorf("netguard: %s is %w", host, ErrNotPublic)
			default:
				return nil, fmt.Errorf("netguard: %s resolves to %s, which is %w", host, a, ErrNotPublic)
			}
		}
	}
	// Dial the checked addresses themselves, so a second DNS answer cannot differ,
	// under one deadline, so many unreachable answers cannot stretch it.
	ctx, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()
	for _, a := range addrs[:min(len(addrs), 3)] {
		var c net.Conn
		if c, err = dialAddr(ctx, network, net.JoinHostPort(a.Unmap().String(), port)); err == nil {
			return c, nil
		}
	}
	return nil, err
}

// ErrNotPublic marks a dial refused because the host is, or resolves to, a
// private, loopback or other non-public address. The wrapping error names the
// address, so it belongs in logs, not in pages.
var ErrNotPublic = errors.New("not a public address")

var errTooLarge = fmt.Errorf("netguard: response body is larger than %d bytes", MaxBody)

type capped struct {
	io.ReadCloser
	left int64 // bytes still allowed; -1 once the body went over
}

func (c *capped) Read(p []byte) (int, error) {
	if c.left < 0 {
		return 0, errTooLarge
	}
	// Ask for one byte past the cap: seeing it is how an oversized body is told apart.
	if int64(len(p)) > c.left+1 {
		p = p[:c.left+1]
	}
	n, err := c.ReadCloser.Read(p)
	if int64(n) > c.left {
		n, c.left = int(c.left), -1
		return n, errTooLarge
	}
	c.left -= int64(n)
	return n, err
}

type capTransport struct{ base http.RoundTripper }

func (t capTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(r)
	if err == nil {
		resp.Body = &capped{ReadCloser: resp.Body, left: MaxBody}
	}
	return resp, err
}

// Client is an HTTP client that only reaches public addresses and allowed hosts.
// Callers may change its CheckRedirect; the transport is shared.
func (g *Guard) Client() *http.Client {
	g.once.Do(func() {
		g.transport = version.Transport(capTransport{&http.Transport{
			Proxy:                 nil,
			DialContext:           g.dial,
			ForceAttemptHTTP2:     true,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 60 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		}})
	})
	return &http.Client{
		Transport: g.transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return errors.New("netguard: too many redirects")
			}
			_, err := g.CheckURL(req.URL.String())
			return err
		},
	}
}
