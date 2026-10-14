// Package store is valetkey's database layer: SQLite or Postgres through bun.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/migrate"
	_ "modernc.org/sqlite"

	"github.com/rahmadafandi/valetkey/internal/store/migrations"
)

var ErrNotFound = errors.New("not found")

type Store struct{ db *bun.DB }

type User struct {
	bun.BaseModel `bun:"table:users"`
	ID            string    `bun:"id,pk"`
	Email         string    `bun:"email"`
	CreatedAt     time.Time `bun:"created_at"`
}

type Client struct {
	bun.BaseModel `bun:"table:oauth_clients"`
	ID            string    `bun:"id,pk"`
	Name          string    `bun:"name"`
	RedirectURIs  []string  `bun:"redirect_uris"`
	CreatedAt     time.Time `bun:"created_at"`
}

type Code struct {
	bun.BaseModel `bun:"table:oauth_codes"`
	Hash          []byte    `bun:"code_hash,pk"`
	ClientID      string    `bun:"client_id"`
	UserID        string    `bun:"user_id"`
	RedirectURI   string    `bun:"redirect_uri"`
	Challenge     string    `bun:"code_challenge"`
	ExpiresAt     time.Time `bun:"expires_at"`
}

type Token struct {
	bun.BaseModel `bun:"table:oauth_tokens"`
	Hash          []byte    `bun:"token_hash,pk"`
	Kind          string    `bun:"kind"`
	ClientID      string    `bun:"client_id"`
	UserID        string    `bun:"user_id"`
	ExpiresAt     time.Time `bun:"expires_at"`
	CreatedAt     time.Time `bun:"created_at"`
}

type credential struct {
	bun.BaseModel `bun:"table:credentials"`
	UserID        string    `bun:"user_id,pk"`
	System        string    `bun:"system,pk"`
	Sealed        []byte    `bun:"sealed"`
	UpdatedAt     time.Time `bun:"updated_at"`
}

// PersonalToken is a static bearer token that acts as its owner, limited to
// Tools and Scope (raw JSON, interpreted by the tools package).
type PersonalToken struct {
	bun.BaseModel    `bun:"table:personal_tokens"`
	ID               string     `bun:"id,pk"`
	UserID           string     `bun:"user_id"`
	Name             string     `bun:"name"`
	Hash             []byte     `bun:"token_hash"`
	Tools            []string   `bun:"tools"`
	Scope            []byte     `bun:"scope"`
	MaxWritesPerHour int        `bun:"max_writes_per_hour"` // 0 means unlimited
	DryRun           bool       `bun:"dry_run"`
	ExpiresAt        *time.Time `bun:"expires_at"` // nil means it never expires
	CreatedAt        time.Time  `bun:"created_at"`
	LastUsedAt       *time.Time `bun:"last_used_at"`
}

// ToolCall is one audited MCP tool call.
type ToolCall struct {
	bun.BaseModel `bun:"table:tool_calls,alias:tc"`
	ID            string    `bun:"id,pk"`
	UserID        string    `bun:"user_id"`
	TokenID       string    `bun:"token_id,nullzero"` // empty for an OAuth session
	TokenName     string    `bun:"token_name"`
	Tool          string    `bun:"tool"`
	IsWrite       bool      `bun:"is_write"`
	Args          string    `bun:"args"`
	Outcome       string    `bun:"outcome"` // ok, error, refused, dry_run
	Message       string    `bun:"message"`
	MS            int64     `bun:"ms"`
	At            time.Time `bun:"at"`
	Email         string    `bun:"email,scanonly"`
}

type CallFilter struct {
	UserID, TokenName, Tool, Outcome string // empty means any
	Limit                            int
}

// Open connects to url (sqlite://path or postgres://...) and applies pending migrations.
func Open(ctx context.Context, url string) (*Store, error) {
	db, err := connect(url)
	if err != nil {
		return nil, err
	}
	if err := migrations.Up(ctx, db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return &Store{db: db}, nil
}

func connect(url string) (*bun.DB, error) {
	switch {
	case strings.HasPrefix(url, "sqlite://"):
		path := strings.TrimPrefix(url, "sqlite://")
		if path == "" {
			return nil, errors.New("DATABASE_URL: sqlite:// needs a file path, e.g. sqlite:///data/valetkey.db")
		}
		sqldb, err := sql.Open("sqlite", "file:"+path+"?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
		if err != nil {
			return nil, err
		}
		// ponytail: one connection serialises writes and avoids SQLITE_BUSY; switch to Postgres when that limits throughput.
		sqldb.SetMaxOpenConns(1)
		return bun.NewDB(sqldb, sqlitedialect.New()), nil
	case strings.HasPrefix(url, "postgres://"), strings.HasPrefix(url, "postgresql://"):
		return bun.NewDB(sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(url))), pgdialect.New()), nil
	}
	return nil, errors.New("DATABASE_URL must start with sqlite:// or postgres://")
}

// MigrationStatus lists applied and pending migrations without applying any.
func MigrationStatus(ctx context.Context, url string) (string, error) {
	db, err := connect(url)
	if err != nil {
		return "", err
	}
	defer db.Close()
	m := migrate.NewMigrator(db, migrations.Migrations)
	if err := m.Init(ctx); err != nil {
		return "", err
	}
	ms, err := m.MigrationsWithStatus(ctx)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "applied: %s\n", ms.Applied())
	fmt.Fprintf(&b, "pending: %s\n", ms.Unapplied())
	return b.String(), nil
}

func (s *Store) Close() { s.db.Close() }

func newID() string { return rand.Text() }

// now is UTC so SQLite, which compares timestamps as text, orders them correctly.
func now() time.Time { return time.Now().UTC() }

func notFound(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (s *Store) UpsertUser(ctx context.Context, email string) (User, error) {
	u := User{ID: newID(), Email: email, CreatedAt: now()}
	if _, err := s.db.NewInsert().Model(&u).On("CONFLICT (email) DO NOTHING").Exec(ctx); err != nil {
		return User{}, err
	}
	err := s.db.NewSelect().Model(&u).Where("email = ?", email).Scan(ctx)
	return u, err
}

func (s *Store) CreateClient(ctx context.Context, c Client) error {
	c.CreatedAt = now()
	_, err := s.db.NewInsert().Model(&c).Exec(ctx)
	return err
}

func (s *Store) GetClient(ctx context.Context, id string) (Client, error) {
	var c Client
	err := s.db.NewSelect().Model(&c).Where("id = ?", id).Scan(ctx)
	return c, notFound(err)
}

func (s *Store) SaveCode(ctx context.Context, c Code) error {
	c.ExpiresAt = c.ExpiresAt.UTC()
	_, err := s.db.NewInsert().Model(&c).Exec(ctx)
	return err
}

// TakeCode deletes and returns a code, so each code is redeemed at most once.
func (s *Store) TakeCode(ctx context.Context, hash []byte) (Code, error) {
	var c Code
	err := s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if err := tx.NewSelect().Model(&c).Where("code_hash = ?", hash).Scan(ctx); err != nil {
			return err
		}
		return deleteOne(tx.NewDelete().Model((*Code)(nil)).Where("code_hash = ?", hash).Exec(ctx))
	})
	return c, notFound(err)
}

// deleteOne turns a delete that lost a race (no row left) into sql.ErrNoRows.
func deleteOne(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) SaveToken(ctx context.Context, t Token) error {
	t.ExpiresAt, t.CreatedAt = t.ExpiresAt.UTC(), now()
	_, err := s.db.NewInsert().Model(&t).Exec(ctx)
	return err
}

// TakeToken deletes and returns a token; used to rotate refresh tokens.
func (s *Store) TakeToken(ctx context.Context, hash []byte, kind string) (Token, error) {
	var t Token
	err := s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if err := tx.NewSelect().Model(&t).Where("token_hash = ? AND kind = ?", hash, kind).Scan(ctx); err != nil {
			return err
		}
		return deleteOne(tx.NewDelete().Model((*Token)(nil)).Where("token_hash = ? AND kind = ?", hash, kind).Exec(ctx))
	})
	return t, notFound(err)
}

// LookupToken returns an unexpired token and its user.
func (s *Store) LookupToken(ctx context.Context, hash []byte, kind string) (Token, User, error) {
	var t Token
	var u User
	err := s.db.NewSelect().Model(&t).Where("token_hash = ? AND kind = ? AND expires_at > ?", hash, kind, now()).Scan(ctx)
	if err == nil {
		err = s.db.NewSelect().Model(&u).Where("id = ?", t.UserID).Scan(ctx)
	}
	return t, u, notFound(err)
}

func (s *Store) PutCredential(ctx context.Context, userID, system string, sealed []byte) error {
	c := credential{UserID: userID, System: system, Sealed: sealed, UpdatedAt: now()}
	_, err := s.db.NewInsert().Model(&c).
		On("CONFLICT (user_id, system) DO UPDATE").
		Set("sealed = EXCLUDED.sealed").Set("updated_at = EXCLUDED.updated_at").
		Exec(ctx)
	return err
}

func (s *Store) GetCredential(ctx context.Context, userID, system string) ([]byte, error) {
	var c credential
	err := s.db.NewSelect().Model(&c).Where("user_id = ? AND system = ?", userID, system).Scan(ctx)
	return c.Sealed, notFound(err)
}

func (s *Store) DeleteCredential(ctx context.Context, userID, system string) error {
	_, err := s.db.NewDelete().Model((*credential)(nil)).Where("user_id = ? AND system = ?", userID, system).Exec(ctx)
	return err
}

func (s *Store) ConnectedSystems(ctx context.Context, userID string) (map[string]bool, error) {
	var systems []string
	err := s.db.NewSelect().Model((*credential)(nil)).Column("system").Where("user_id = ?", userID).Scan(ctx, &systems)
	m := make(map[string]bool, len(systems))
	for _, sys := range systems {
		m[sys] = true
	}
	return m, err
}

// DeleteExpired removes expired codes and tokens, and tool calls older than
// auditBefore unless it is zero.
func (s *Store) DeleteExpired(ctx context.Context, auditBefore time.Time) error {
	t := now()
	for _, q := range []*bun.DeleteQuery{
		s.db.NewDelete().Model((*Code)(nil)).Where("expires_at < ?", t),
		s.db.NewDelete().Model((*Token)(nil)).Where("expires_at < ?", t),
		s.db.NewDelete().Model((*PersonalToken)(nil)).Where("expires_at < ?", t),
	} {
		if _, err := q.Exec(ctx); err != nil {
			return err
		}
	}
	if auditBefore.IsZero() {
		return nil
	}
	_, err := s.db.NewDelete().Model((*ToolCall)(nil)).Where("at < ?", auditBefore.UTC()).Exec(ctx)
	return err
}

func (s *Store) CreatePersonalToken(ctx context.Context, t PersonalToken, hash []byte) (string, error) {
	t.ID, t.Hash, t.CreatedAt = newID(), hash, now()
	if t.ExpiresAt != nil {
		exp := t.ExpiresAt.UTC()
		t.ExpiresAt = &exp
	}
	_, err := s.db.NewInsert().Model(&t).Exec(ctx)
	return t.ID, err
}

// UsePersonalToken returns an unexpired token and its owner, and records the use.
func (s *Store) UsePersonalToken(ctx context.Context, hash []byte) (PersonalToken, User, error) {
	var t PersonalToken
	var u User
	at := now()
	err := s.db.NewSelect().Model(&t).
		Where("token_hash = ? AND (expires_at IS NULL OR expires_at > ?)", hash, at).Scan(ctx)
	if err == nil {
		_, err = s.db.NewUpdate().Model((*PersonalToken)(nil)).Set("last_used_at = ?", at).Where("id = ?", t.ID).Exec(ctx)
		t.LastUsedAt = &at
	}
	if err == nil {
		err = s.db.NewSelect().Model(&u).Where("id = ?", t.UserID).Scan(ctx)
	}
	return t, u, notFound(err)
}

func (s *Store) ListPersonalTokens(ctx context.Context, userID string) ([]PersonalToken, error) {
	var list []PersonalToken
	err := s.db.NewSelect().Model(&list).Where("user_id = ?", userID).Order("created_at DESC").Scan(ctx)
	return list, err
}

// DeletePersonalToken revokes one of the user's tokens; other users' tokens are untouched.
func (s *Store) DeletePersonalToken(ctx context.Context, userID, id string) error {
	err := deleteOne(s.db.NewDelete().Model((*PersonalToken)(nil)).Where("user_id = ? AND id = ?", userID, id).Exec(ctx))
	return notFound(err)
}

func (s *Store) RecordCall(ctx context.Context, c ToolCall) error {
	c.ID = newID()
	if c.At.IsZero() {
		c.At = now()
	}
	c.At = c.At.UTC()
	_, err := s.db.NewInsert().Model(&c).Exec(ctx)
	return err
}

// CountWrites counts a token's write calls since a time that used the
// upstream or would have (ok, error, dry_run); refusals do not count.
func (s *Store) CountWrites(ctx context.Context, tokenID string, since time.Time) (int, error) {
	n, err := s.db.NewSelect().Model((*ToolCall)(nil)).
		Where("token_id = ? AND is_write = ? AND at >= ?", tokenID, true, since.UTC()).
		Where("outcome IN (?)", bun.In([]string{"ok", "error", "dry_run"})).
		Count(ctx)
	return int(n), err
}

// ListCalls returns the newest calls first, with each caller's email.
func (s *Store) ListCalls(ctx context.Context, f CallFilter) ([]ToolCall, error) {
	var calls []ToolCall
	q := s.db.NewSelect().Model(&calls).ColumnExpr("tc.*").ColumnExpr("u.email").
		Join("JOIN users AS u ON u.id = tc.user_id").OrderExpr("tc.at DESC").Limit(int64(f.Limit))
	for col, v := range map[string]string{"tc.user_id": f.UserID, "tc.token_name": f.TokenName, "tc.tool": f.Tool, "tc.outcome": f.Outcome} {
		if v != "" {
			q = q.Where("? = ?", bun.Ident(col), v)
		}
	}
	err := q.Scan(ctx)
	return calls, err
}
