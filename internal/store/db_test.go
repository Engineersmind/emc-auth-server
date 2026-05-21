package store_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/engineersmind/emc-auth-server/internal/store"
	"github.com/engineersmind/emc-auth-server/internal/testhelper"
)

func TestNewDB_ConnectsSuccessfully(t *testing.T) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		t.Skip("DATABASE_URL not set — skipping DB connection test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := testhelper.TestLogger()
	pool, err := store.NewDB(ctx, url, logger)
	if err != nil {
		t.Fatalf("NewDB() error = %v", err)
	}
	if pool == nil {
		t.Fatal("NewDB() returned nil pool")
	}

	if err := pool.Ping(ctx); err != nil {
		t.Errorf("pool.Ping() error = %v", err)
	}

	store.CloseDB(pool)
}

func TestNewDB_InvalidURL(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	logger := testhelper.TestLogger()
	// A completely unparseable URL should fail at parse time.
	_, err := store.NewDB(ctx, "not-a-valid-url!!@#$", logger)
	if err == nil {
		t.Fatal("NewDB() expected error for invalid URL, got nil")
	}
}
