package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/uptrace/bun"
)

// MaxUpstreams is how many upstream MCP servers one user may register.
const MaxUpstreams = 20

var (
	ErrLimit     = errors.New("upstream limit reached")
	ErrNameTaken = errors.New("upstream name already used")
)

// Upstream is a remote MCP server a user registered. Auth names the scheme;
// its secrets live in the credentials row "upstream:<ID>".
type Upstream struct {
	bun.BaseModel   `bun:"table:upstreams"`
	ID              string     `bun:"id,pk"`
	UserID          string     `bun:"user_id"`
	Name            string     `bun:"name"`
	URL             string     `bun:"url"`
	Auth            string     `bun:"auth"`
	CreatedAt       time.Time  `bun:"created_at"`
	ToolsApprovedAt *time.Time `bun:"tools_approved_at"` // nil until the user approves a snapshot
}

// UpstreamTool is one tool definition the user approved for an upstream.
type UpstreamTool struct {
	bun.BaseModel `bun:"table:upstream_tools"`
	UpstreamID    string    `bun:"upstream_id,pk"`
	Name          string    `bun:"name,pk"`
	Description   string    `bun:"description"`
	InputSchema   string    `bun:"input_schema"`
	Writes        bool      `bun:"writes"`
	ApprovedAt    time.Time `bun:"approved_at"`
}

// UserTool is an approved tool together with the upstream that serves it.
type UserTool struct {
	Upstream Upstream
	Tool     UpstreamTool
}

func (s *Store) CreateUpstream(ctx context.Context, u Upstream) (Upstream, error) {
	u.ID, u.CreatedAt, u.ToolsApprovedAt = newID(), now(), nil
	err := s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		n, err := tx.NewSelect().Model((*Upstream)(nil)).Where("user_id = ?", u.UserID).Count(ctx)
		if err != nil {
			return err
		}
		// ponytail: two concurrent creates can reach 21; acceptable for a per-user soft limit
		if n >= MaxUpstreams {
			return ErrLimit
		}
		taken, err := tx.NewSelect().Model((*Upstream)(nil)).Where("user_id = ? AND name = ?", u.UserID, u.Name).Exists(ctx)
		if err != nil {
			return err
		}
		if taken {
			return ErrNameTaken
		}
		_, err = tx.NewInsert().Model(&u).Exec(ctx)
		return err
	})
	return u, err
}

func (s *Store) ListUpstreams(ctx context.Context, userID string) ([]Upstream, error) {
	var us []Upstream
	err := s.db.NewSelect().Model(&us).Where("user_id = ?", userID).Order("name").Scan(ctx)
	return us, err
}

func (s *Store) GetUpstream(ctx context.Context, userID, id string) (Upstream, error) {
	var u Upstream
	err := s.db.NewSelect().Model(&u).Where("id = ? AND user_id = ?", id, userID).Scan(ctx)
	return u, notFound(err)
}

// ownsUpstream returns ErrNotFound unless the upstream belongs to userID.
func ownsUpstream(ctx context.Context, db bun.IDB, userID, id string) error {
	ok, err := db.NewSelect().Model((*Upstream)(nil)).Where("id = ? AND user_id = ?", id, userID).Exists(ctx)
	if err != nil {
		return err
	}
	if !ok {
		return ErrNotFound
	}
	return nil
}

// DeleteUpstream removes the upstream, its approved tools and its credentials row.
func (s *Store) DeleteUpstream(ctx context.Context, userID, id string) error {
	return s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if err := ownsUpstream(ctx, tx, userID, id); err != nil {
			return err
		}
		if _, err := tx.NewDelete().Model((*UpstreamTool)(nil)).Where("upstream_id = ?", id).Exec(ctx); err != nil {
			return err
		}
		if _, err := tx.NewDelete().Model((*credential)(nil)).Where("user_id = ? AND system = ?", userID, "upstream:"+id).Exec(ctx); err != nil {
			return err
		}
		return notFound(deleteOne(tx.NewDelete().Model((*Upstream)(nil)).Where("id = ? AND user_id = ?", id, userID).Exec(ctx)))
	})
}

// ApproveTools replaces the upstream's approved set with tools.
func (s *Store) ApproveTools(ctx context.Context, userID, upstreamID string, tools []UpstreamTool) error {
	return s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if err := ownsUpstream(ctx, tx, userID, upstreamID); err != nil {
			return err
		}
		if _, err := tx.NewDelete().Model((*UpstreamTool)(nil)).Where("upstream_id = ?", upstreamID).Exec(ctx); err != nil {
			return err
		}
		t := now()
		if len(tools) > 0 {
			rows := make([]UpstreamTool, len(tools))
			for i, tl := range tools {
				tl.UpstreamID, tl.ApprovedAt = upstreamID, t
				rows[i] = tl
			}
			if _, err := tx.NewInsert().Model(&rows).Exec(ctx); err != nil {
				return err
			}
		}
		_, err := tx.NewUpdate().Model((*Upstream)(nil)).Set("tools_approved_at = ?", t).Where("id = ?", upstreamID).Exec(ctx)
		return err
	})
}

func (s *Store) RemoveTools(ctx context.Context, userID, upstreamID string, names []string) error {
	return s.db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error {
		if err := ownsUpstream(ctx, tx, userID, upstreamID); err != nil {
			return err
		}
		if len(names) == 0 {
			return nil
		}
		_, err := tx.NewDelete().Model((*UpstreamTool)(nil)).
			Where("upstream_id = ? AND name IN (?)", upstreamID, bun.In(names)).Exec(ctx)
		return err
	})
}

func (s *Store) ApprovedTools(ctx context.Context, userID, upstreamID string) ([]UpstreamTool, error) {
	var ts []UpstreamTool
	err := s.db.NewSelect().Model(&ts).
		Where("upstream_id IN (SELECT id FROM upstreams WHERE id = ? AND user_id = ?)", upstreamID, userID).
		Order("name").Scan(ctx)
	return ts, err
}

type userToolRow struct {
	UID            string     `bun:"uid"`
	UUserID        string     `bun:"u_user_id"`
	UName          string     `bun:"u_name"`
	UURL           string     `bun:"u_url"`
	UAuth          string     `bun:"u_auth"`
	UCreatedAt     time.Time  `bun:"u_created_at"`
	UToolsApproved *time.Time `bun:"u_tools_approved_at"`
	Name           string     `bun:"t_name"`
	Description    string     `bun:"t_description"`
	InputSchema    string     `bun:"t_input_schema"`
	Writes         bool       `bun:"t_writes"`
	ApprovedAt     time.Time  `bun:"t_approved_at"`
}

// UserTools lists every approved tool of the user's upstreams in one query.
func (s *Store) UserTools(ctx context.Context, userID string) ([]UserTool, error) {
	var rows []userToolRow
	err := s.db.NewSelect().
		TableExpr("upstreams AS u").
		Join("JOIN upstream_tools AS t ON t.upstream_id = u.id").
		ColumnExpr("u.id AS uid, u.user_id AS u_user_id, u.name AS u_name, u.url AS u_url, u.auth AS u_auth, u.created_at AS u_created_at, u.tools_approved_at AS u_tools_approved_at").
		ColumnExpr("t.name AS t_name, t.description AS t_description, t.input_schema AS t_input_schema, t.writes AS t_writes, t.approved_at AS t_approved_at").
		Where("u.user_id = ?", userID).
		OrderExpr("u.name, t.name").
		Scan(ctx, &rows)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	out := make([]UserTool, len(rows))
	for i, r := range rows {
		out[i] = UserTool{
			Upstream: Upstream{ID: r.UID, UserID: r.UUserID, Name: r.UName, URL: r.UURL, Auth: r.UAuth, CreatedAt: r.UCreatedAt, ToolsApprovedAt: r.UToolsApproved},
			Tool:     UpstreamTool{UpstreamID: r.UID, Name: r.Name, Description: r.Description, InputSchema: r.InputSchema, Writes: r.Writes, ApprovedAt: r.ApprovedAt},
		}
	}
	return out, nil
}
