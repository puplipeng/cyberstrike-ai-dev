// Package testpostgres supplies isolated PostgreSQL databases to integration tests.
// The configured role needs CREATEDB; no objects in the supplied database are changed.
package testpostgres

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// DSN creates a database per call and drops only that database on test cleanup.
// Set CYBERSTRIKE_TEST_POSTGRES_DSN to a postgres:// URL for a test server.
func DSN(t testing.TB) string {
	t.Helper()
	base := strings.TrimSpace(os.Getenv("CYBERSTRIKE_TEST_POSTGRES_DSN"))
	if base == "" {
		t.Skip("PostgreSQL integration test: set CYBERSTRIKE_TEST_POSTGRES_DSN (role requires CREATEDB)")
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") || u.Host == "" {
		t.Fatal("CYBERSTRIKE_TEST_POSTGRES_DSN must be a postgres:// or postgresql:// URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect to PostgreSQL test server: %v", err)
	}
	defer admin.Close(context.Background())
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	name := "csai_test_" + hex.EncodeToString(random[:])
	identifier := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+identifier+" TEMPLATE template0"); err != nil {
		t.Fatalf("create isolated test database (CREATEDB is required): %v", err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cleanupCancel()
		conn, err := pgx.Connect(cleanupCtx, base)
		if err != nil {
			t.Errorf("connect for test database cleanup: %v", err)
			return
		}
		defer conn.Close(context.Background())
		if _, err := conn.Exec(cleanupCtx, "DROP DATABASE "+identifier+" WITH (FORCE)"); err != nil {
			t.Errorf("drop isolated test database %s: %v", name, err)
		}
	})
	u.Path = "/" + name
	u.RawPath = ""
	return u.String()
}
