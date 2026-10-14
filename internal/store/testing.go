package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/driver/pgdriver"

	"github.com/rahmadafandi/valetkey/internal/store/migrations"
)

// OpenTest opens a migrated Store for one test: a SQLite file in t.TempDir(),
// or a fresh Postgres schema of TEST_DATABASE_URL when it is set.
func OpenTest(t testing.TB) *Store {
	t.Helper()
	ctx := context.Background()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		s, err := Open(ctx, "sqlite://"+filepath.Join(t.TempDir(), "test.db"))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(s.Close)
		return s
	}
	name := "t_" + strings.ToLower(rand.Text())
	admin := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(url)))
	defer admin.Close()
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+name); err != nil {
		t.Fatal(err)
	}
	db := bun.NewDB(sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(url),
		pgdriver.WithConnParams(map[string]any{"search_path": name}))), pgdialect.New())
	if err := migrations.Up(ctx, db); err != nil {
		t.Fatal(err)
	}
	s := &Store{db: db}
	t.Cleanup(func() {
		s.Close()
		c := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(url)))
		defer c.Close()
		c.ExecContext(context.Background(), "DROP SCHEMA "+name+" CASCADE")
	})
	return s
}
