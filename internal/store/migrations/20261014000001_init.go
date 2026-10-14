package migrations

import (
	"context"
	"errors"
	"time"

	"github.com/uptrace/bun"
)

type user0001 struct {
	bun.BaseModel `bun:"table:users"`
	ID            string    `bun:"id,pk"`
	Email         string    `bun:"email,notnull,unique"`
	CreatedAt     time.Time `bun:"created_at,notnull"`
}

type oauthClient0001 struct {
	bun.BaseModel `bun:"table:oauth_clients"`
	ID            string    `bun:"id,pk"`
	Name          string    `bun:"name,notnull"`
	RedirectURIs  []string  `bun:"redirect_uris,type:text,notnull"`
	CreatedAt     time.Time `bun:"created_at,notnull"`
}

type oauthCode0001 struct {
	bun.BaseModel `bun:"table:oauth_codes"`
	Hash          []byte    `bun:"code_hash,pk"`
	ClientID      string    `bun:"client_id,notnull"`
	UserID        string    `bun:"user_id,notnull"`
	RedirectURI   string    `bun:"redirect_uri,notnull"`
	Challenge     string    `bun:"code_challenge,notnull"`
	ExpiresAt     time.Time `bun:"expires_at,notnull"`
}

type oauthToken0001 struct {
	bun.BaseModel `bun:"table:oauth_tokens"`
	Hash          []byte    `bun:"token_hash,pk"`
	Kind          string    `bun:"kind,notnull"`
	ClientID      string    `bun:"client_id,notnull"`
	UserID        string    `bun:"user_id,notnull"`
	ExpiresAt     time.Time `bun:"expires_at,notnull"`
	CreatedAt     time.Time `bun:"created_at,notnull"`
}

type credential0001 struct {
	bun.BaseModel `bun:"table:credentials"`
	UserID        string    `bun:"user_id,pk"`
	System        string    `bun:"system,pk"`
	Sealed        []byte    `bun:"sealed,notnull"`
	UpdatedAt     time.Time `bun:"updated_at,notnull"`
}

type personalToken0001 struct {
	bun.BaseModel    `bun:"table:personal_tokens"`
	ID               string     `bun:"id,pk"`
	UserID           string     `bun:"user_id,notnull"`
	Name             string     `bun:"name,notnull"`
	Hash             []byte     `bun:"token_hash,notnull,unique"`
	Tools            []string   `bun:"tools,type:text,notnull"`
	Scope            []byte     `bun:"scope,notnull"`
	MaxWritesPerHour int        `bun:"max_writes_per_hour,notnull"`
	DryRun           bool       `bun:"dry_run,notnull"`
	ExpiresAt        *time.Time `bun:"expires_at"`
	CreatedAt        time.Time  `bun:"created_at,notnull"`
	LastUsedAt       *time.Time `bun:"last_used_at"`
}

type toolCall0001 struct {
	bun.BaseModel `bun:"table:tool_calls"`
	ID            string    `bun:"id,pk"`
	UserID        string    `bun:"user_id,notnull"`
	TokenID       string    `bun:"token_id,nullzero"`
	TokenName     string    `bun:"token_name,notnull"`
	Tool          string    `bun:"tool,notnull"`
	IsWrite       bool      `bun:"is_write,notnull"`
	Args          string    `bun:"args,notnull"`
	Outcome       string    `bun:"outcome,notnull"`
	Message       string    `bun:"message,notnull"`
	MS            int64     `bun:"ms,notnull"`
	At            time.Time `bun:"at,notnull"`
}

const cascadeUser = `(user_id) REFERENCES users (id) ON DELETE CASCADE`

func init() {
	Migrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		tables := []struct {
			model any
			fks   []string
		}{
			{(*user0001)(nil), nil},
			{(*oauthClient0001)(nil), nil},
			{(*oauthCode0001)(nil), []string{cascadeUser, `(client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE`}},
			{(*oauthToken0001)(nil), []string{cascadeUser, `(client_id) REFERENCES oauth_clients (id) ON DELETE CASCADE`}},
			{(*credential0001)(nil), []string{cascadeUser}},
			{(*personalToken0001)(nil), []string{cascadeUser}},
			{(*toolCall0001)(nil), []string{cascadeUser}},
		}
		for _, tb := range tables {
			q := db.NewCreateTable().Model(tb.model)
			for _, fk := range tb.fks {
				q = q.ForeignKey(fk)
			}
			if _, err := q.Exec(ctx); err != nil {
				return err
			}
		}
		for _, ix := range []struct {
			model   any
			name    string
			columns []string
		}{
			{(*personalToken0001)(nil), "personal_tokens_user_idx", []string{"user_id"}},
			{(*toolCall0001)(nil), "tool_calls_user_at_idx", []string{"user_id", "at"}},
			{(*toolCall0001)(nil), "tool_calls_token_at_idx", []string{"token_id", "at"}},
		} {
			if _, err := db.NewCreateIndex().Model(ix.model).Index(ix.name).Column(ix.columns...).Exec(ctx); err != nil {
				return err
			}
		}
		return nil
	}, func(context.Context, *bun.DB) error {
		return errors.New("0001_init cannot be undone")
	})
}
