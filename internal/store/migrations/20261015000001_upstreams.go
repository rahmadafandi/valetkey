package migrations

import (
	"context"
	"errors"
	"time"

	"github.com/uptrace/bun"
)

type upstream0002 struct {
	bun.BaseModel   `bun:"table:upstreams"`
	ID              string     `bun:"id,pk"`
	UserID          string     `bun:"user_id,notnull"`
	Name            string     `bun:"name,notnull"`
	URL             string     `bun:"url,notnull"`
	Auth            string     `bun:"auth,notnull"`
	CreatedAt       time.Time  `bun:"created_at,notnull"`
	ToolsApprovedAt *time.Time `bun:"tools_approved_at"`
}

type upstreamTool0002 struct {
	bun.BaseModel `bun:"table:upstream_tools"`
	UpstreamID    string    `bun:"upstream_id,pk"`
	Name          string    `bun:"name,pk"`
	Description   string    `bun:"description,notnull"`
	InputSchema   string    `bun:"input_schema,notnull"`
	Writes        bool      `bun:"writes,notnull"`
	ApprovedAt    time.Time `bun:"approved_at,notnull"`
}

func init() {
	Migrations.MustRegister(InTx(func(ctx context.Context, db bun.IDB) error {
		if _, err := db.NewCreateTable().Model((*upstream0002)(nil)).ForeignKey(cascadeUser).Exec(ctx); err != nil {
			return err
		}
		if _, err := db.NewCreateTable().Model((*upstreamTool0002)(nil)).
			ForeignKey(`(upstream_id) REFERENCES upstreams (id) ON DELETE CASCADE`).Exec(ctx); err != nil {
			return err
		}
		_, err := db.NewCreateIndex().Model((*upstream0002)(nil)).Index("upstreams_user_name_idx").Unique().Column("user_id", "name").Exec(ctx)
		return err
	}), func(context.Context, *bun.DB) error { return errors.New("0002_upstreams cannot be undone") })
}
