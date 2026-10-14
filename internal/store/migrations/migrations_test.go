package migrations

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/dialect/sqlitedialect"
	"github.com/uptrace/bun/driver/pgdriver"
	"github.com/uptrace/bun/migrate"
	_ "modernc.org/sqlite"
)

// testDB is an empty SQLite file, or a fresh Postgres schema of TEST_DATABASE_URL when it is set.
func testDB(t *testing.T) *bun.DB {
	t.Helper()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		sqldb, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "m.db"))
		if err != nil {
			t.Fatal(err)
		}
		sqldb.SetMaxOpenConns(1)
		db := bun.NewDB(sqldb, sqlitedialect.New())
		t.Cleanup(func() { db.Close() })
		return db
	}
	name := "m_" + strings.ToLower(rand.Text())
	admin := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(url)))
	defer admin.Close()
	if _, err := admin.Exec("CREATE SCHEMA " + name); err != nil {
		t.Fatal(err)
	}
	db := bun.NewDB(sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(url),
		pgdriver.WithConnParams(map[string]any{"search_path": name}))), pgdialect.New())
	t.Cleanup(func() {
		db.Close()
		c := sql.OpenDB(pgdriver.NewConnector(pgdriver.WithDSN(url)))
		defer c.Close()
		c.Exec("DROP SCHEMA " + name + " CASCADE")
	})
	return db
}

func TestFailedMigrationLeavesNothingApplied(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	fail := true
	body := InTx(func(ctx context.Context, db bun.IDB) error {
		if _, err := db.ExecContext(ctx, "CREATE TABLE half (id INTEGER)"); err != nil {
			return err
		}
		if fail {
			return errors.New("boom")
		}
		return nil
	})
	ms := migrate.NewMigrations()
	ms.Add(migrate.Migration{Name: "20990101000001", Comment: "half",
		Up: func(ctx context.Context, m *migrate.Migrator, _ *migrate.Migration) error { return body(ctx, m.DB()) }})

	if err := up(ctx, db, ms); err == nil {
		t.Fatal("the failing migration reported success")
	}
	st, err := NewMigrator(db, ms).MigrationsWithStatus(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if applied := st.Applied(); len(applied) != 0 {
		t.Errorf("applied after a failure: %v", applied)
	}
	if _, err := db.ExecContext(ctx, "SELECT 1 FROM half"); err == nil {
		t.Error("table half survived the failed migration")
	}

	fail = false
	if err := up(ctx, db, ms); err != nil {
		t.Fatalf("retry: %v", err)
	}
	if _, err := db.ExecContext(ctx, "SELECT 1 FROM half"); err != nil {
		t.Errorf("retry did not create the table: %v", err)
	}
}

func TestInitCreatesToolCallsAtIndex(t *testing.T) {
	ctx := context.Background()
	db := testDB(t)
	if err := Up(ctx, db); err != nil {
		t.Fatal(err)
	}
	q := "SELECT count(*) FROM sqlite_master WHERE type = 'index' AND name = ?"
	if db.Dialect().Name().String() == "pg" {
		q = "SELECT count(*) FROM pg_indexes WHERE schemaname = current_schema() AND indexname = ?"
	}
	var n int
	if err := db.QueryRowContext(ctx, q, "tool_calls_at_idx").Scan(&n); err != nil || n != 1 {
		t.Errorf("tool_calls_at_idx: count %d, err %v", n, err)
	}
}
