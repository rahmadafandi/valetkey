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

// NewMigrator marks a migration applied only after its body succeeds; bun's
// default marks it first, so a failed migration would never run again.
func NewMigrator(db *bun.DB, ms *migrate.Migrations) *migrate.Migrator {
	return migrate.NewMigrator(db, ms, migrate.WithMarkAppliedOnSuccess(true))
}

// InTx runs a migration body in one transaction, so a failure halfway leaves
// no partial schema. SQLite and Postgres both roll back DDL.
func InTx(fn func(ctx context.Context, db bun.IDB) error) migrate.MigrationFunc {
	return func(ctx context.Context, db *bun.DB) error {
		return db.RunInTx(ctx, nil, func(ctx context.Context, tx bun.Tx) error { return fn(ctx, tx) })
	}
}

// Up applies every pending migration under bun's migration lock.
func Up(ctx context.Context, db *bun.DB) error { return up(ctx, db, Migrations) }

func up(ctx context.Context, db *bun.DB, ms *migrate.Migrations) error {
	m := NewMigrator(db, ms)
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
