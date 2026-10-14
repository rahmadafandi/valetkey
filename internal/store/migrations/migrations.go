// Package migrations holds valetkey's schema history. Each migration keeps its
// own frozen copy of the tables it creates, so later model changes cannot
// rewrite history.
package migrations

import (
	"context"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/migrate"
)

var Migrations = migrate.NewMigrations()

// Up applies every pending migration under bun's migration lock.
func Up(ctx context.Context, db *bun.DB) error {
	m := migrate.NewMigrator(db, Migrations)
	if err := m.Init(ctx); err != nil {
		return err
	}
	if err := m.Lock(ctx); err != nil {
		return err
	}
	defer m.Unlock(ctx)
	_, err := m.Migrate(ctx)
	return err
}
