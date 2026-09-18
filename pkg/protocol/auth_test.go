package protocol

import (
	"crypto/md5"
	"encoding/hex"
	"testing"
	"time"
)

func TestAuthManagerMD5(t *testing.T) {
	mgr := NewAuthManager("test_secret_key_12345")
	email := "alice@msn.local"
	password := "Secret123"

	challenge := mgr.CreateMD5Challenge(email)
	if challenge == "" {
		t.Fatalf("expected non-empty challenge")
	}

	// Correct client MD5 hash calculation: md5(challenge + password)
	hasher := md5.New()
	hasher.Write([]byte(challenge + password))
	correctHash := hex.EncodeToString(hasher.Sum(nil))

	if !mgr.VerifyMD5Response(email, correctHash, password) {
		t.Errorf("MD5 auth verification failed for valid password")
	}

	// Challenge should be consumed/one-time
	if mgr.VerifyMD5Response(email, correctHash, password) {
		t.Errorf("MD5 challenge replay should have failed")
	}

	// Wrong password
	challenge2 := mgr.CreateMD5Challenge(email)
	hasher2 := md5.New()
	hasher2.Write([]byte(challenge2 + "WrongPassword"))
	wrongHash := hex.EncodeToString(hasher2.Sum(nil))
	if mgr.VerifyMD5Response(email, wrongHash, password) {
		t.Errorf("MD5 auth should fail with wrong password")
	}
}

func TestAuthManagerTWN(t *testing.T) {
	mgr := NewAuthManager("test_secret_key_12345")
	email := "bob@msn.local"

	ticket := mgr.CreateTWNTicket(email, 5*time.Minute)
	if ticket == "" {
		t.Fatalf("expected non-empty ticket")
	}

	if !mgr.VerifyTWNTicket(ticket, email) {
		t.Errorf("TWN ticket verification failed")
	}

	if mgr.VerifyTWNTicket(ticket, "other@msn.local") {
		t.Errorf("TWN ticket should not verify for a different email")
	}
}

func TestAuthManagerSBCookie(t *testing.T) {
	mgr := NewAuthManager("test_secret_key_12345")
	email := "carol@msn.local"
	sessID := 101

	cookie := mgr.CreateSBCookie(email, sessID, "caller", 5*time.Minute)
	if cookie == "" {
		t.Fatalf("expected non-empty cookie")
	}

	retSessID, role, ok := mgr.VerifyAndConsumeSBCookie(cookie, email)
	if !ok || retSessID != sessID || role != "caller" {
		t.Errorf("cookie verification failed: ok=%v, sess=%d, role=%s", ok, retSessID, role)
	}

	// Cookie should be consumed
	_, _, ok2 := mgr.VerifyAndConsumeSBCookie(cookie, email)
	if ok2 {
		t.Errorf("cookie replay should have failed")
	}
}
