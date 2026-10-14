package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// fakeGoogle answers the token endpoint with an ID token built from claims.
func fakeGoogle(t *testing.T, claims map[string]any) *httptest.Server {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := json.Marshal(claims)
		idt := "e30." + base64.RawURLEncoding.EncodeToString(b) + ".sig"
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"access_token": "g", "token_type": "Bearer", "expires_in": 3600, "id_token": idt})
	}))
	t.Cleanup(ts.Close)
	return ts
}

func googleServer(g *httptest.Server) *Server {
	return &Server{
		Google: &oauth2.Config{ClientID: "gid", ClientSecret: "gs",
			Endpoint: oauth2.Endpoint{AuthURL: g.URL + "/auth", TokenURL: g.URL + "/token"}},
		AllowedDomains: []string{"example.com"},
	}
}

func claims(email string) map[string]any {
	return map[string]any{"iss": "https://accounts.google.com", "aud": "gid", "email": email, "email_verified": true, "hd": email[strings.LastIndex(email, "@")+1:]}
}

func TestGoogleEmailLowercased(t *testing.T) {
	s := googleServer(fakeGoogle(t, claims("Rahmad@Example.COM")))
	got, err := s.googleEmail(context.Background(), "code")
	if err != nil || got != "rahmad@example.com" {
		t.Errorf("got %q, %v", got, err)
	}
}

func TestGoogleEmailRejects(t *testing.T) {
	cases := map[string]map[string]any{
		"other domain": claims("someone@gmail.com"),
		"lookalike":    claims("someone@notexample.com"),
		"unverified":   {"iss": "https://accounts.google.com", "aud": "gid", "email": "a@example.com", "email_verified": false},
		"wrong aud":    {"iss": "https://accounts.google.com", "aud": "other", "email": "a@example.com", "email_verified": true},
		"missing hd":   {"iss": "https://accounts.google.com", "aud": "gid", "email": "a@example.com", "email_verified": true},
		"other hd":     {"iss": "https://accounts.google.com", "aud": "gid", "email": "a@example.com", "email_verified": true, "hd": "gmail.com"},
		"wrong iss":    {"iss": "https://evil.example", "aud": "gid", "email": "a@example.com", "email_verified": true},
	}
	for name, c := range cases {
		s := googleServer(fakeGoogle(t, c))
		if got, err := s.googleEmail(context.Background(), "code"); err == nil {
			t.Errorf("%s: accepted %q", name, got)
		}
	}
}
