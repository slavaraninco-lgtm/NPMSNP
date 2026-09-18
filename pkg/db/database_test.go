package db

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDatabaseOperations(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "npmsnp_test_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tempDir)

	dbFile := filepath.Join(tempDir, "test.db")
	db, err := NewDatabase(dbFile, "test_salt_123")
	if err != nil {
		t.Fatalf("NewDatabase failed: %v", err)
	}
	defer db.Close()

	// 1. Create user
	u, err := db.CreateUser("alice@msn.local", "secret123", "Alice")
	if err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}
	if u.Email != "alice@msn.local" || u.FriendlyName != "Alice" || u.Password != "secret123" {
		t.Fatalf("unexpected user: %+v", u)
	}

	// 2. Get user
	fetched, err := db.GetUser("alice@msn.local")
	if err != nil {
		t.Fatalf("GetUser failed: %v", err)
	}
	if fetched == nil || fetched.Password != "secret123" {
		t.Fatalf("expected secret123, got %+v", fetched)
	}

	// 3. Add contact
	c, err := db.AddOrUpdateContact("alice@msn.local", "bob@msn.local", 1, 0, "Bob")
	if err != nil {
		t.Fatalf("AddOrUpdateContact failed: %v", err)
	}
	if c.ContactEmail != "bob@msn.local" || c.ListFlags&1 == 0 {
		t.Fatalf("unexpected contact: %+v", c)
	}

	// Reverse contact should exist for Bob
	rev, err := db.GetContact("bob@msn.local", "alice@msn.local")
	if err != nil || rev == nil {
		t.Fatalf("expected reverse contact, got: %v", rev)
	}
	if rev.ListFlags&8 == 0 {
		t.Fatalf("expected RL flag (8), got: %d", rev.ListFlags)
	}

	// 4. Ban and Mute
	err = db.BanUser("alice@msn.local", 60, "Spam")
	if err != nil {
		t.Fatalf("BanUser failed: %v", err)
	}
	pen, err := db.GetUserPenaltyStatus("alice@msn.local")
	if err != nil || pen == nil || !pen.IsBanned {
		t.Fatalf("expected user to be banned, got: %+v", pen)
	}

	err = db.UnbanUser("alice@msn.local")
	if err != nil {
		t.Fatalf("UnbanUser failed: %v", err)
	}
	pen, _ = db.GetUserPenaltyStatus("alice@msn.local")
	if pen.IsBanned {
		t.Fatalf("expected user to be unbanned")
	}
}
