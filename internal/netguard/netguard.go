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
	"time"

	"github.com/rahmadafandi/valetkey/internal/version"
)

const MaxBody = 1 << 20

type Guard struct {
	AllowHosts []string // exact lowercase host names that skip the address check and may use http
	Lookup     func(ctx context.Context, host string) ([]netip.Addr, error)
}

var notPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("fec0::/10"),
	// IPv6 ranges that embed or translate to an IPv4 address, which may be private.
	netip.MustParsePrefix("::/96"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("2001::/32"),
	netip.MustParsePrefix("2002::/16"),
}

// Public reports whether a is an address on the public internet.
func Public(a netip.Addr) bool {
	a = a.WithZone("").Unmap() // Prefix.Contains never matches an address with a zone
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() {
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
		for _, a := range addrs {
			if !Public(a) {
				return nil, fmt.Errorf("netguard: %s resolves to %s, which is not a public address", host, a)
			}
		}
	}
	// Dial the checked addresses themselves, so a second DNS answer cannot differ.
	d := net.Dialer{Timeout: 10 * time.Second}
	for _, a := range addrs {
		var c net.Conn
		if c, err = d.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port)); err == nil {
			return c, nil
		}
	}
	return nil, err
}

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
func (g *Guard) Client() *http.Client {
	t := &http.Transport{
		Proxy:                 nil,
		DialContext:           g.dial,
		ForceAttemptHTTP2:     true,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 60 * time.Second,
		IdleConnTimeout:       90 * time.Second,
	}
	return &http.Client{
		Transport: version.Transport(capTransport{t}),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 3 {
				return errors.New("netguard: too many redirects")
			}
			_, err := g.CheckURL(req.URL.String())
			return err
		},
	}
}
