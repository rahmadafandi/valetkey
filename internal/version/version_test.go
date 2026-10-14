package version

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestUserAgent(t *testing.T) {
	old := Version
	t.Cleanup(func() { Version = old })
	Version = "v0.2.0"
	if got := UserAgent(); got != "valetkey/0.2.0" {
		t.Fatalf("UserAgent = %q", got)
	}
	Version = ""
	if got := String(); got == "" {
		t.Fatal("String is empty without ldflags")
	}
}

func TestTransportSetsUserAgent(t *testing.T) {
	var got string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.UserAgent() }))
	defer ts.Close()
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("User-Agent", "curl/8")
	if _, err := (&http.Client{Transport: Transport(nil)}).Do(req); err != nil {
		t.Fatal(err)
	}
	if got != UserAgent() {
		t.Fatalf("server saw %q", got)
	}
	if req.Header.Get("User-Agent") != "curl/8" {
		t.Fatal("Transport modified the caller's request")
	}
}
