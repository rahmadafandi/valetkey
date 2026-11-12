package migrations

import (
	"context"
	"errors"

	"github.com/uptrace/bun"
)

func init() {
	Migrations.MustRegister(InTx(func(ctx context.Context, db bun.IDB) error {
		for _, col := range []string{"tools_changed_at", "drift_checked_at"} {
			if _, err := db.NewRaw("ALTER TABLE upstreams ADD COLUMN " + col + " TIMESTAMPTZ").Exec(ctx); err != nil {
				return err
			}
		}
		return nil
	}), func(context.Context, *bun.DB) error { return errors.New("0003_upstream_drift cannot be undone") })
}
