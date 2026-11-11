package store

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
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
	if err := s.DeleteExpired(ctx, time.Time{}); err != nil {
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
	if err := s.DeleteExpired(ctx, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListPersonalTokens(ctx, u.ID); len(list) != 1 {
		t.Errorf("a token expired within the grace period was deleted: %d left", len(list))
	}
}

func TestRenewPersonalToken(t *testing.T) {
	s := OpenTest(t)
	u, _ := s.UpsertUser(ctx, "rahmad@example.com")
	other, _ := s.UpsertUser(ctx, "bob@example.com")
	past := time.Now().Add(-time.Hour)
	ancient := time.Now().Add(-ExpiredTokenGrace - time.Hour)
	id, _ := s.CreatePersonalToken(ctx, PersonalToken{UserID: u.ID, Name: "atlas", Tools: []string{"loki_query"}, Scope: []byte(`{"loki":"x"}`), ExpiresAt: &past}, []byte("h1"))
	s.CreatePersonalToken(ctx, PersonalToken{UserID: u.ID, Name: "gone", Tools: []string{"loki_query"}, Scope: []byte(`{}`), ExpiresAt: &ancient}, []byte("h2"))

	future := time.Now().Add(time.Hour)
	if err := s.RenewPersonalToken(ctx, other.ID, id, &future); !errors.Is(err, ErrNotFound) {
		t.Errorf("another user renewed it: %v", err)
	}
	if _, _, err := s.UsePersonalToken(ctx, []byte("h1")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired token works before renewal: %v", err)
	}
	if err := s.RenewPersonalToken(ctx, u.ID, id, &future); err != nil {
		t.Fatal(err)
	}
	p, _, err := s.UsePersonalToken(ctx, []byte("h1"))
	if err != nil || string(p.Scope) != `{"loki":"x"}` || p.ExpiresAt == nil {
		t.Fatalf("renewed token: %+v %v", p, err)
	}
	if err := s.RenewPersonalToken(ctx, u.ID, id, nil); err != nil {
		t.Fatal(err)
	}
	if p, _, _ := s.UsePersonalToken(ctx, []byte("h1")); p.ExpiresAt != nil {
		t.Errorf("renewed to never, still expires %v", p.ExpiresAt)
	}
	if err := s.DeleteExpired(ctx, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.ListPersonalTokens(ctx, u.ID); len(list) != 1 || list[0].Name != "atlas" {
		t.Errorf("after cleanup: %+v; want only atlas (gone is past the grace period)", list)
	}
}

func TestExpiredTokenNotFoundAcrossZones(t *testing.T) {
	s := OpenTest(t)
	u := seed(t, s)
	// A non-UTC zone: SQLite compares timestamps as text, so the store must normalise.
	zone := time.FixedZone("UTC+7", 7*3600)
	if err := s.SaveToken(ctx, Token{Hash: []byte("h1"), Kind: "access", ClientID: "c1", UserID: u.ID,
		ExpiresAt: time.Now().In(zone).Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.LookupToken(ctx, []byte("h1"), "access"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired token found: %v", err)
	}
	if err := s.SaveToken(ctx, Token{Hash: []byte("h2"), Kind: "access", ClientID: "c1", UserID: u.ID, ExpiresAt: time.Now().In(zone).Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if _, got, err := s.LookupToken(ctx, []byte("h2"), "access"); err != nil || got.Email != "rahmad@example.com" {
		t.Fatalf("live token: %v %v", got, err)
	}
}

func TestToolCalls(t *testing.T) {
	s := OpenTest(t)
	u, _ := s.UpsertUser(ctx, "a@example.com")
	other, _ := s.UpsertUser(ctx, "b@example.com")
	now := time.Now()
	for _, c := range []ToolCall{
		{UserID: u.ID, TokenID: "t1", TokenName: "atlas", Tool: "jenkins_deploy", IsWrite: true, Outcome: "ok", At: now.Add(-10 * time.Minute)},
		{UserID: u.ID, TokenID: "t1", TokenName: "atlas", Tool: "jenkins_deploy", IsWrite: true, Outcome: "dry_run", At: now.Add(-5 * time.Minute)},
		{UserID: u.ID, TokenID: "t1", TokenName: "atlas", Tool: "jenkins_deploy", IsWrite: true, Outcome: "refused", At: now.Add(-4 * time.Minute)},
		{UserID: u.ID, TokenID: "t1", TokenName: "atlas", Tool: "jenkins_job", Outcome: "ok", At: now.Add(-3 * time.Minute)},
		{UserID: u.ID, TokenID: "t1", TokenName: "atlas", Tool: "jenkins_deploy", IsWrite: true, Outcome: "ok", At: now.Add(-2 * time.Hour)},
		{UserID: other.ID, Tool: "loki_query", Outcome: "error", Message: "boom", At: now},
	} {
		if err := s.RecordCall(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := s.CountWrites(ctx, "t1", now.Add(-time.Hour)); err != nil || n != 2 {
		t.Errorf("CountWrites = %d, %v; want 2 (ok + dry_run within the hour)", n, err)
	}
	mine, err := s.ListCalls(ctx, CallFilter{UserID: u.ID, Limit: 200})
	if err != nil || len(mine) != 5 || mine[0].Tool != "jenkins_job" || mine[0].Email != "a@example.com" {
		t.Fatalf("ListCalls mine: %d %v %+v", len(mine), err, mine)
	}
	all, _ := s.ListCalls(ctx, CallFilter{Limit: 200})
	if len(all) != 6 || all[0].Email != "b@example.com" {
		t.Errorf("ListCalls all: %d", len(all))
	}
	if byEmail, _ := s.ListCalls(ctx, CallFilter{Email: "b@example.com", Limit: 200}); len(byEmail) != 1 || byEmail[0].Tool != "loki_query" {
		t.Errorf("email filter: %+v", byEmail)
	}
	refused, _ := s.ListCalls(ctx, CallFilter{UserID: u.ID, Outcome: "refused", Limit: 200})
	if len(refused) != 1 {
		t.Errorf("outcome filter: %d", len(refused))
	}
	if err := s.DeleteExpired(ctx, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if all, _ := s.ListCalls(ctx, CallFilter{Limit: 200}); len(all) != 5 {
		t.Errorf("retention kept %d calls, want 5", len(all))
	}
}

func TestPersonalTokenFields(t *testing.T) {
	s := OpenTest(t)
	u, _ := s.UpsertUser(ctx, "a@example.com")
	exp := time.Now().Add(time.Hour)
	id, err := s.CreatePersonalToken(ctx, PersonalToken{UserID: u.ID, Name: "atlas", Tools: []string{"loki_query"},
		Scope: []byte(`{"loki":"{app=\"web\"}"}`), ExpiresAt: &exp, MaxWritesPerHour: 5, DryRun: true}, []byte("hash"))
	if err != nil {
		t.Fatal(err)
	}
	p, owner, err := s.UsePersonalToken(ctx, []byte("hash"))
	if err != nil || p.ID != id || p.MaxWritesPerHour != 5 || !p.DryRun || p.Tools[0] != "loki_query" || owner.Email != "a@example.com" {
		t.Fatalf("UsePersonalToken: %+v %v", p, err)
	}
	list, _ := s.ListPersonalTokens(ctx, u.ID)
	if len(list) != 1 || list[0].LastUsedAt == nil {
		t.Errorf("last used not recorded: %+v", list)
	}
}

func TestMigrationsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")
	for range 2 {
		s, err := Open(context.Background(), "sqlite://"+path)
		if err != nil {
			t.Fatal(err)
		}
		s.Close()
	}
	out, err := MigrationStatus(context.Background(), "sqlite://"+path)
	if err != nil || !strings.Contains(out, "20261014000001") || strings.Contains(out, "pending: 2026") {
		t.Errorf("status: %q %v", out, err)
	}
}

func TestReserveWrite(t *testing.T) {
	s := OpenTest(t)
	u, _ := s.UpsertUser(ctx, "a@example.com")
	since := time.Now().Add(-time.Hour)
	s.RecordCall(ctx, ToolCall{UserID: u.ID, TokenID: "t1", Tool: "jenkins_deploy", IsWrite: true, Outcome: "ok"})
	id1, n, err := s.ReserveWrite(ctx, ToolCall{UserID: u.ID, TokenID: "t1", TokenName: "atlas", Tool: "jenkins_deploy", Args: `{}`}, since)
	if err != nil || id1 == "" || n != 2 {
		t.Fatalf("first reservation: %q %d %v; want count 2", id1, n, err)
	}
	// A second call, as from another instance, sees the first one still running.
	id2, n, err := s.ReserveWrite(ctx, ToolCall{UserID: u.ID, TokenID: "t1", Tool: "jenkins_deploy"}, since)
	if err != nil || n != 3 {
		t.Fatalf("second reservation: %d %v; want count 3", n, err)
	}
	if _, n, _ := s.ReserveWrite(ctx, ToolCall{UserID: u.ID, TokenID: "other", Tool: "jenkins_deploy"}, since); n != 1 {
		t.Errorf("another token's count = %d, want 1", n)
	}
	// A refused reservation stops counting; a finished one keeps counting.
	if err := s.RecordCall(ctx, ToolCall{ID: id2, Outcome: "refused", Message: "refused: limit"}); err != nil {
		t.Fatal(err)
	}
	if err := s.RecordCall(ctx, ToolCall{ID: id1, Outcome: "ok", MS: 12}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.CountWrites(ctx, "t1", since); n != 2 {
		t.Errorf("count after finishing = %d, want 2", n)
	}
	calls, _ := s.ListCalls(ctx, CallFilter{UserID: u.ID, Outcome: "ok", Limit: 200})
	var done *ToolCall
	for i := range calls {
		if calls[i].ID == id1 {
			done = &calls[i]
		}
	}
	if done == nil || done.MS != 12 || done.TokenName != "atlas" || done.Tool != "jenkins_deploy" || !done.IsWrite {
		t.Errorf("finished row = %+v; finishing must keep what the reservation stored", done)
	}
}
