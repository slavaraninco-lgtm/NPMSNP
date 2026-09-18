package services

import (
	"path/filepath"
	"testing"

	"npmsnp/pkg/db"
	"npmsnp/pkg/protocol"
)

type mockSession struct {
	email        string
	friendlyName string
	status       string
	clientID     string
	sentCommands []string
}

func (m *mockSession) GetEmail() string                                                      { return m.email }
func (m *mockSession) GetFriendlyName() string                                               { return m.friendlyName }
func (m *mockSession) GetStatus() string                                                     { return m.status }
func (m *mockSession) GetClientID() string                                                   { return m.clientID }
func (m *mockSession) GetCustomMessage() string                                              { return "" }
func (m *mockSession) GetMSNObj() string                                                     { return "" }
func (m *mockSession) GetPeerName() string                                                   { return "127.0.0.1:12345" }
func (m *mockSession) GetEffectiveHost() string                                              { return "127.0.0.1" }
func (m *mockSession) IsANSI() bool                                                          { return false }
func (m *mockSession) SendCmd(cmd string, args ...interface{})                               { m.sentCommands = append(m.sentCommands, cmd) }
func (m *mockSession) SendPayload(cmd string, payload []byte, args ...interface{})          { m.sentCommands = append(m.sentCommands, cmd) }
func (m *mockSession) SendNLN(status, email, friendlyName, clientID, msnObj string)          { m.sentCommands = append(m.sentCommands, "NLN") }
func (m *mockSession) SendFLN(email string)                                                  { m.sentCommands = append(m.sentCommands, "FLN") }
func (m *mockSession) SendILN(trid, status, email, friendlyName, clientID, msnObj string)    { m.sentCommands = append(m.sentCommands, "ILN") }
func (m *mockSession) SendRNG(sessionID int, sbHost string, sbPort int, cookie, callerEmail, callerFriendlyName string) {
	m.sentCommands = append(m.sentCommands, "RNG")
}
func (m *mockSession) SendSystemNotification(msg, senderEmail, senderName string) bool {
	m.sentCommands = append(m.sentCommands, "MSG")
	return true
}
func (m *mockSession) Close() {}

func TestSessionManager(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_session.db")
	database, err := db.NewDatabase(dbPath, "testkey")
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}
	defer database.Close()

	sm := NewSessionManager(database)

	sess1 := &mockSession{email: "user1@msn.local", friendlyName: "User 1", status: protocol.StatusOnline}
	sm.RegisterSession("user1@msn.local", sess1)

	if !sm.IsOnline("user1@msn.local") {
		t.Errorf("user1 should be online")
	}
	if sm.IsOnline("unknown@msn.local") {
		t.Errorf("unknown should be offline")
	}

	retrieved := sm.GetSession("user1@msn.local")
	if retrieved == nil || retrieved.GetEmail() != "user1@msn.local" {
		t.Errorf("failed to retrieve session")
	}

	sm.UnregisterSession("user1@msn.local")
	if sm.IsOnline("user1@msn.local") {
		t.Errorf("user1 should be offline after unregister")
	}
}

func TestSwitchboardManager(t *testing.T) {
	authMgr := protocol.NewAuthManager("testkey")
	sbm := NewSwitchboardManager(authMgr)

	sessID, cookie := sbm.AllocateSession("host@msn.local")
	if sessID <= 0 || cookie == "" {
		t.Fatalf("invalid session allocation: id=%d, cookie=%s", sessID, cookie)
	}

	room := sbm.GetRoom(sessID)
	if room == nil {
		t.Fatalf("room not found for sessID %d", sessID)
	}

	inviteCookie := sbm.PrepareInvite(sessID, "guest@msn.local")
	if inviteCookie == "" {
		t.Fatalf("failed to prepare invite")
	}

	sbm.QueueServiceMessage("guest@msn.local", "Welcome!")
	pending := sbm.PopPendingServiceMessages("guest@msn.local")
	if len(pending) != 1 || pending[0] != "Welcome!" {
		t.Errorf("pending service messages mismatch: %v", pending)
	}
}
