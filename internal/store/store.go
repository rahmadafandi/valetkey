// Package store is valetkey's Postgres access layer.
package store

import (
	"context"
	_ "embed"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed schema.sql
var schema string

var ErrNotFound = errors.New("not found")

type Store struct{ db *pgxpool.Pool }

type User struct{ ID, Email string }

type Client struct {
	ID, Name     string
	RedirectURIs []string
}

type Code struct {
	Hash                                     []byte
	ClientID, UserID, RedirectURI, Challenge string
	ExpiresAt                                time.Time
}

type Token struct {
	Hash                   []byte
	Kind, ClientID, UserID string
	ExpiresAt              time.Time
}

func Open(ctx context.Context, url string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	return open(ctx, cfg)
}

// ponytail: schema.sql is idempotent and runs on every start; adopt a migration tool when a column must change.
func open(ctx context.Context, cfg *pgxpool.Config) (*Store, error) {
	db, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(ctx, schema); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() { s.db.Close() }

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func (s *Store) UpsertUser(ctx context.Context, email string) (User, error) {
	var u User
	err := s.db.QueryRow(ctx, `INSERT INTO users (email) VALUES ($1)
		ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
		RETURNING id::text, email`, email).Scan(&u.ID, &u.Email)
	return u, err
}

func (s *Store) CreateClient(ctx context.Context, c Client) error {
	_, err := s.db.Exec(ctx, `INSERT INTO oauth_clients (id, name, redirect_uris) VALUES ($1, $2, $3)`,
		c.ID, c.Name, c.RedirectURIs)
	return err
}

func (s *Store) GetClient(ctx context.Context, id string) (Client, error) {
	c := Client{ID: id}
	err := s.db.QueryRow(ctx, `SELECT name, redirect_uris FROM oauth_clients WHERE id = $1`, id).
		Scan(&c.Name, &c.RedirectURIs)
	return c, notFound(err)
}

func (s *Store) SaveCode(ctx context.Context, c Code) error {
	_, err := s.db.Exec(ctx, `INSERT INTO oauth_codes
		(code_hash, client_id, user_id, redirect_uri, code_challenge, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		c.Hash, c.ClientID, c.UserID, c.RedirectURI, c.Challenge, c.ExpiresAt)
	return err
}

// TakeCode deletes and returns a code, so each code is redeemed at most once.
func (s *Store) TakeCode(ctx context.Context, hash []byte) (Code, error) {
	c := Code{Hash: hash}
	err := s.db.QueryRow(ctx, `DELETE FROM oauth_codes WHERE code_hash = $1
		RETURNING client_id, user_id::text, redirect_uri, code_challenge, expires_at`, hash).
		Scan(&c.ClientID, &c.UserID, &c.RedirectURI, &c.Challenge, &c.ExpiresAt)
	return c, notFound(err)
}

func (s *Store) SaveToken(ctx context.Context, t Token) error {
	_, err := s.db.Exec(ctx, `INSERT INTO oauth_tokens (token_hash, kind, client_id, user_id, expires_at)
		VALUES ($1, $2, $3, $4, $5)`, t.Hash, t.Kind, t.ClientID, t.UserID, t.ExpiresAt)
	return err
}

// TakeToken deletes and returns a token; used to rotate refresh tokens.
func (s *Store) TakeToken(ctx context.Context, hash []byte, kind string) (Token, error) {
	t := Token{Hash: hash, Kind: kind}
	err := s.db.QueryRow(ctx, `DELETE FROM oauth_tokens WHERE token_hash = $1 AND kind = $2
		RETURNING client_id, user_id::text, expires_at`, hash, kind).
		Scan(&t.ClientID, &t.UserID, &t.ExpiresAt)
	return t, notFound(err)
}

// LookupToken returns an unexpired token and its user.
func (s *Store) LookupToken(ctx context.Context, hash []byte, kind string) (Token, User, error) {
	t := Token{Hash: hash, Kind: kind}
	var u User
	err := s.db.QueryRow(ctx, `SELECT t.client_id, t.expires_at, u.id::text, u.email
		FROM oauth_tokens t JOIN users u ON u.id = t.user_id
		WHERE t.token_hash = $1 AND t.kind = $2 AND t.expires_at > now()`, hash, kind).
		Scan(&t.ClientID, &t.ExpiresAt, &u.ID, &u.Email)
	t.UserID = u.ID
	return t, u, notFound(err)
}

func (s *Store) PutCredential(ctx context.Context, userID, system string, sealed []byte) error {
	_, err := s.db.Exec(ctx, `INSERT INTO credentials (user_id, system, sealed) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, system) DO UPDATE SET sealed = EXCLUDED.sealed, updated_at = now()`,
		userID, system, sealed)
	return err
}

func (s *Store) GetCredential(ctx context.Context, userID, system string) ([]byte, error) {
	var b []byte
	err := s.db.QueryRow(ctx, `SELECT sealed FROM credentials WHERE user_id = $1 AND system = $2`,
		userID, system).Scan(&b)
	return b, notFound(err)
}

func (s *Store) DeleteCredential(ctx context.Context, userID, system string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM credentials WHERE user_id = $1 AND system = $2`, userID, system)
	return err
}

func (s *Store) ConnectedSystems(ctx context.Context, userID string) (map[string]bool, error) {
	rows, err := s.db.Query(ctx, `SELECT system FROM credentials WHERE user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	systems, err := pgx.CollectRows(rows, pgx.RowTo[string])
	m := make(map[string]bool, len(systems))
	for _, sys := range systems {
		m[sys] = true
	}
	return m, err
}

func (s *Store) DeleteExpired(ctx context.Context) error {
	_, err := s.db.Exec(ctx, `DELETE FROM oauth_codes WHERE expires_at < now();
		DELETE FROM oauth_tokens WHERE expires_at < now();
		DELETE FROM personal_tokens WHERE expires_at < now()`)
	return err
}

// PersonalToken is a static bearer token that acts as its owner, limited to
// Tools and Scope (raw JSON, interpreted by the tools package).
type PersonalToken struct {
	ID, UserID, Name string
	Tools            []string
	Scope            []byte
	ExpiresAt        *time.Time // nil means it never expires
	CreatedAt        time.Time
	LastUsedAt       *time.Time
}

func (s *Store) CreatePersonalToken(ctx context.Context, t PersonalToken, hash []byte) (string, error) {
	var id string
	err := s.db.QueryRow(ctx, `INSERT INTO personal_tokens (user_id, name, token_hash, tools, scope, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id::text`,
		t.UserID, t.Name, hash, t.Tools, t.Scope, t.ExpiresAt).Scan(&id)
	return id, err
}

// UsePersonalToken returns an unexpired token and its owner, and records the use.
func (s *Store) UsePersonalToken(ctx context.Context, hash []byte) (PersonalToken, User, error) {
	var t PersonalToken
	var u User
	err := s.db.QueryRow(ctx, `UPDATE personal_tokens p SET last_used_at = now()
		FROM users u WHERE u.id = p.user_id AND p.token_hash = $1
		  AND (p.expires_at IS NULL OR p.expires_at > now())
		RETURNING p.id::text, p.name, p.tools, p.scope, p.expires_at, p.created_at, u.id::text, u.email`, hash).
		Scan(&t.ID, &t.Name, &t.Tools, &t.Scope, &t.ExpiresAt, &t.CreatedAt, &u.ID, &u.Email)
	t.UserID = u.ID
	return t, u, notFound(err)
}

func (s *Store) ListPersonalTokens(ctx context.Context, userID string) ([]PersonalToken, error) {
	rows, err := s.db.Query(ctx, `SELECT id::text, user_id::text, name, tools, scope, expires_at, created_at, last_used_at
		FROM personal_tokens WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (PersonalToken, error) {
		var t PersonalToken
		err := r.Scan(&t.ID, &t.UserID, &t.Name, &t.Tools, &t.Scope, &t.ExpiresAt, &t.CreatedAt, &t.LastUsedAt)
		return t, err
	})
}

// DeletePersonalToken revokes one of the user's tokens; other users' tokens are untouched.
func (s *Store) DeletePersonalToken(ctx context.Context, userID, id string) error {
	tag, err := s.db.Exec(ctx, `DELETE FROM personal_tokens WHERE user_id = $1 AND id::text = $2`, userID, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
