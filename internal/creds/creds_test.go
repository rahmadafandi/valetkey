package creds

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/vault"
)

var ctx = context.Background()

func newStore(t *testing.T) Store {
	v, err := vault.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	return Store{DB: store.OpenTest(t), Vault: v, Log: slog.New(slog.DiscardHandler)}
}

func TestSaveLoadDelete(t *testing.T) {
	s := newStore(t)
	u, _ := s.DB.UpsertUser(ctx, "a@example.com")
	if _, err := s.Load(ctx, u.ID, "jenkins"); !errors.Is(err, tools.ErrNotConnected) {
		t.Fatalf("before save: %v", err)
	}
	if err := s.Save(ctx, u.ID, "jenkins", tools.Creds{"username": "a", "token": "t"}); err != nil {
		t.Fatal(err)
	}
	c, err := s.Load(ctx, u.ID, "jenkins")
	if err != nil || c["username"] != "a" || c["token"] != "t" {
		t.Fatalf("Load = %v, %v", c, err)
	}
	if m, _ := s.Connected(ctx, u.ID); !m["jenkins"] {
		t.Errorf("Connected = %v", m)
	}
	if err := s.Delete(ctx, u.ID, "jenkins"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, u.ID, "jenkins"); !errors.Is(err, tools.ErrNotConnected) {
		t.Errorf("after delete: %v", err)
	}
}

func TestSwappedRowIsNotConnected(t *testing.T) {
	s := newStore(t)
	a, _ := s.DB.UpsertUser(ctx, "a@example.com")
	b, _ := s.DB.UpsertUser(ctx, "b@example.com")
	if err := s.Save(ctx, a.ID, "jenkins", tools.Creds{"token": "a-secret"}); err != nil {
		t.Fatal(err)
	}
	sealed, _ := s.DB.GetCredential(ctx, a.ID, "jenkins")
	if err := s.DB.PutCredential(ctx, b.ID, "jenkins", sealed); err != nil {
		t.Fatal(err)
	}
	if c, err := s.Load(ctx, b.ID, "jenkins"); !errors.Is(err, tools.ErrNotConnected) {
		t.Errorf("b read a's credentials: %v, %v", c, err)
	}
	if err := s.DB.PutCredential(ctx, a.ID, "loki", sealed); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, a.ID, "loki"); !errors.Is(err, tools.ErrNotConnected) {
		t.Errorf("jenkins row opened as loki: %v", err)
	}
}
