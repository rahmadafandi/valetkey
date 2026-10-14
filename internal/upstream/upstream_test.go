package upstream

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestStatusErr(t *testing.T) {
	if err := StatusErr("jenkins", 201, nil); err != nil {
		t.Errorf("201: %v", err)
	}
	for _, code := range []int{401, 403} {
		if err := StatusErr("jenkins", code, []byte("nope")); !errors.Is(err, ErrUnauthorized) {
			t.Errorf("%d: %v is not ErrUnauthorized", code, err)
		}
	}
	err := StatusErr("jenkins", 500, []byte(strings.Repeat("x", 1000)))
	if err == nil || errors.Is(err, ErrUnauthorized) || len(err.Error()) > 320 {
		t.Errorf("500: %v", err)
	}
}

func TestSetAuth(t *testing.T) {
	r, _ := http.NewRequest("GET", "http://x", nil)
	SetAuth(r, map[string]string{"token": "abc"})
	if got := r.Header.Get("Authorization"); got != "Bearer abc" {
		t.Errorf("bearer = %q", got)
	}
	r, _ = http.NewRequest("GET", "http://x", nil)
	SetAuth(r, map[string]string{"token": "Basic zzz"})
	if got := r.Header.Get("Authorization"); got != "Basic zzz" {
		t.Errorf("explicit scheme = %q", got)
	}
	r, _ = http.NewRequest("GET", "http://x", nil)
	SetAuth(r, map[string]string{"username": "u", "password": "p"})
	if u, p, ok := r.BasicAuth(); !ok || u != "u" || p != "p" {
		t.Errorf("basic = %q %q %v", u, p, ok)
	}
}

func TestParseTimeUsesLocal(t *testing.T) {
	zone := time.FixedZone("UTC+7", 7*60*60)
	old := time.Local
	time.Local = zone
	defer func() { time.Local = old }()

	got, ok := ParseTime("2026-10-14 10:00")
	if !ok || !got.Equal(time.Date(2026, 10, 14, 3, 0, 0, 0, time.UTC)) {
		t.Errorf("naive time = %v %v, want 03:00 UTC", got, ok)
	}
	got, ok = ParseTime("2026-10-14T10:00:00Z")
	if !ok || !got.Equal(time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("RFC3339 = %v %v", got, ok)
	}
	if _, ok := ParseTime("yesterday"); ok {
		t.Error("garbage parsed")
	}
	if _, ok := ParseTime(""); ok {
		t.Error("empty parsed")
	}
}
