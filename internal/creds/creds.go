// Package creds stores each user's upstream credentials, sealed by the vault.
package creds

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/rahmadafandi/valetkey/internal/store"
	"github.com/rahmadafandi/valetkey/internal/tools"
	"github.com/rahmadafandi/valetkey/internal/vault"
)

type Store struct {
	DB    *store.Store
	Vault *vault.Vault
	Log   *slog.Logger
}

func aad(userID, system string) []byte { return []byte(userID + "/" + system) }

func (s Store) Save(ctx context.Context, userID, system string, c tools.Creds) error {
	plain, err := json.Marshal(c)
	if err != nil {
		return err
	}
	return s.DB.PutCredential(ctx, userID, system, s.Vault.Seal(plain, aad(userID, system)))
}

// Load returns tools.ErrNotConnected when nothing is stored or the stored data
// cannot be opened (wrong key, or a row that belongs to another owner).
func (s Store) Load(ctx context.Context, userID, system string) (tools.Creds, error) {
	sealed, err := s.DB.GetCredential(ctx, userID, system)
	if errors.Is(err, store.ErrNotFound) {
		return nil, tools.ErrNotConnected
	}
	if err != nil {
		return nil, err
	}
	plain, err := s.Vault.Open(sealed, aad(userID, system))
	if err != nil {
		s.Log.Warn("credentials could not be decrypted", "user", userID, "system", system)
		return nil, tools.ErrNotConnected
	}
	var c tools.Creds
	if err := json.Unmarshal(plain, &c); err != nil {
		s.Log.Warn("credentials could not be decoded", "user", userID, "system", system)
		return nil, tools.ErrNotConnected
	}
	return c, nil
}

func (s Store) Delete(ctx context.Context, userID, system string) error {
	return s.DB.DeleteCredential(ctx, userID, system)
}

func (s Store) Connected(ctx context.Context, userID string) (map[string]bool, error) {
	return s.DB.ConnectedSystems(ctx, userID)
}
