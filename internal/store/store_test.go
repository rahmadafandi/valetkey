package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

var ctx = context.Background()

func TestUpsertUserIdempotent(t *testing.T) {
	s := OpenTest(t)
	a, err := s.UpsertUser(ctx, "rahmad@example.com")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.UpsertUser(ctx, "rahmad@example.com")
	if err != nil || a.ID != b.ID || a.ID == "" {
		t.Fatalf("a=%+v b=%+v err=%v", a, b, err)
	}
}

func TestClients(t *testing.T) {
	s := OpenTest(t)
	if err := s.CreateClient(ctx, Client{ID: "c1", Name: "Claude", RedirectURIs: []string{"https://claude.ai/cb"}}); err != nil {
		t.Fatal(err)
	}
	c, err := s.GetClient(ctx, "c1")
	if err != nil || c.Name != "Claude" || len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://claude.ai/cb" {
		t.Fatalf("GetClient = %+v, %v", c, err)
	}
	if _, err := s.GetClient(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing client: err = %v", err)
	}
}

func seed(t *testing.T, s *Store) User {
	t.Helper()
	u, err := s.UpsertUser(ctx, "rahmad@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.CreateClient(ctx, Client{ID: "c1", RedirectURIs: []string{"https://x/cb"}}); err != nil {
		t.Fatal(err)
	}
	return u
}

func TestTakeCodeOnce(t *testing.T) {
	s := OpenTest(t)
	u := seed(t, s)
	code := Code{Hash: []byte("h1"), ClientID: "c1", UserID: u.ID, RedirectURI: "https://x/cb", Challenge: "ch", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.SaveCode(ctx, code); err != nil {
		t.Fatal(err)
	}
	got, err := s.TakeCode(ctx, []byte("h1"))
	if err != nil || got.UserID != u.ID || got.Challenge != "ch" || got.RedirectURI != "https://x/cb" {
		t.Fatalf("TakeCode = %+v, %v", got, err)
	}
	if _, err := s.TakeCode(ctx, []byte("h1")); !errors.Is(err, ErrNotFound) {
		t.Errorf("second take: err = %v", err)
	}
}

func TestTokens(t *testing.T) {
	s := OpenTest(t)
	u := seed(t, s)
	live := Token{Hash: []byte("a1"), Kind: "access", ClientID: "c1", UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)}
	dead := Token{Hash: []byte("a2"), Kind: "access", ClientID: "c1", UserID: u.ID, ExpiresAt: time.Now().Add(-time.Second)}
	ref := Token{Hash: []byte("r1"), Kind: "refresh", ClientID: "c1", UserID: u.ID, ExpiresAt: time.Now().Add(time.Hour)}
	for _, tk := range []Token{live, dead, ref} {
		if err := s.SaveToken(ctx, tk); err != nil {
			t.Fatal(err)
		}
	}
	_, gotUser, err := s.LookupToken(ctx, []byte("a1"), "access")
	if err != nil || gotUser.Email != "rahmad@example.com" {
		t.Fatalf("LookupToken live = %+v, %v", gotUser, err)
	}
	if _, _, err := s.LookupToken(ctx, []byte("a2"), "access"); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired token: err = %v", err)
	}
	if _, _, err := s.LookupToken(ctx, []byte("r1"), "access"); !errors.Is(err, ErrNotFound) {
		t.Errorf("refresh token used as access: err = %v", err)
	}
	if _, err := s.TakeToken(ctx, []byte("r1"), "refresh"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeToken(ctx, []byte("r1"), "refresh"); !errors.Is(err, ErrNotFound) {
		t.Errorf("refresh reuse: err = %v", err)
	}
	if err := s.DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.TakeToken(ctx, []byte("a2"), "access"); !errors.Is(err, ErrNotFound) {
		t.Errorf("DeleteExpired left the expired token: err = %v", err)
	}
}

func TestCredentials(t *testing.T) {
	s := OpenTest(t)
	u := seed(t, s)
	if err := s.PutCredential(ctx, u.ID, "jenkins", []byte("v1")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutCredential(ctx, u.ID, "jenkins", []byte("v2")); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCredential(ctx, u.ID, "jenkins")
	if err != nil || string(got) != "v2" {
		t.Fatalf("GetCredential = %q, %v", got, err)
	}
	m, err := s.ConnectedSystems(ctx, u.ID)
	if err != nil || !m["jenkins"] || m["loki"] {
		t.Fatalf("ConnectedSystems = %v, %v", m, err)
	}
	if err := s.DeleteCredential(ctx, u.ID, "jenkins"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetCredential(ctx, u.ID, "jenkins"); !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: err = %v", err)
	}
}

func TestPersonalTokens(t *testing.T) {
	s := OpenTest(t)
	u, _ := s.UpsertUser(ctx, "rahmad@example.com")
	other, _ := s.UpsertUser(ctx, "bob@example.com")
	past := time.Now().Add(-time.Minute)
	id, err := s.CreatePersonalToken(ctx, PersonalToken{UserID: u.ID, Name: "atlas", Tools: []string{"loki_query"}, Scope: []byte(`{"loki":"{a=\"b\"}"}`)}, []byte("h1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePersonalToken(ctx, PersonalToken{UserID: u.ID, Name: "old", Tools: []string{}, Scope: []byte(`{}`), ExpiresAt: &past}, []byte("h2")); err != nil {
		t.Fatal(err)
	}

	p, owner, err := s.UsePersonalToken(ctx, []byte("h1"))
	if err != nil || p.ID != id || p.Name != "atlas" || owner.Email != "rahmad@example.com" || p.Tools[0] != "loki_query" || p.ExpiresAt != nil {
		t.Fatalf("use: %+v %+v %v", p, owner, err)
	}
	if _, _, err := s.UsePersonalToken(ctx, []byte("h2")); !errors.Is(err, ErrNotFound) {
		t.Errorf("expired token: %v", err)
	}
	if _, _, err := s.UsePersonalToken(ctx, []byte("nope")); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown token: %v", err)
	}

	list, err := s.ListPersonalTokens(ctx, u.ID)
	if err != nil || len(list) != 2 {
		t.Fatalf("list: %d %v", len(list), err)
	}
	for _, x := range list {
		if x.Name == "atlas" && x.LastUsedAt == nil {
			t.Error("last_used_at not recorded")
		}
	}

	if err := s.DeletePersonalToken(ctx, other.ID, id); !errors.Is(err, ErrNotFound) {
		t.Errorf("another user revoked it: %v", err)
	}
	if err := s.DeletePersonalToken(ctx, u.ID, id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UsePersonalToken(ctx, []byte("h1")); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoked token still works: %v", err)
	}
	if err := s.DeleteExpired(ctx); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListPersonalTokens(ctx, u.ID); len(list) != 0 {
		t.Errorf("expired token not cleaned up: %d left", len(list))
	}
}
