package services

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"npmsnp/pkg/db"
	"npmsnp/pkg/protocol"
)

// SBParticipant represents a user connected to a Switchboard room.
type SBParticipant interface {
	GetEmail() string
	GetFriendlyName() string
	SendIRO(trid string, index, total int, email, friendlyName string)
	SendJOI(email, friendlyName string)
	SendBYE(email string)
	SendMsgRelay(senderEmail, senderFriendlyName string, payload []byte)
	SendNotRelay(senderEmail string, payload []byte)
}

type SwitchboardRoom struct {
	SessionID      int
	Initiator      string
	CreatedAt      time.Time
	HasServiceBot  bool
	Participants   map[string]SBParticipant
	PendingInvites map[string]string // callee_email -> cookie
}

type SwitchboardManager struct {
	authManager            *protocol.AuthManager
	mu                     sync.RWMutex
	rooms                  map[int]*SwitchboardRoom
	nextSessionID          int
	pendingServiceMessages map[string][]string // target_email -> []message
}

func NewSwitchboardManager(authManager *protocol.AuthManager) *SwitchboardManager {
	return &SwitchboardManager{
		authManager:            authManager,
		rooms:                  make(map[int]*SwitchboardRoom),
		nextSessionID:          1000,
		pendingServiceMessages: make(map[string][]string),
	}
}

func (m *SwitchboardManager) AllocateSession(initiatorEmail string) (int, string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.nextSessionID++
	sessionID := m.nextSessionID

	cookie := m.authManager.CreateSBCookie(initiatorEmail, sessionID, "caller", 120*time.Second)

	room := &SwitchboardRoom{
		SessionID:      sessionID,
		Initiator:      strings.ToLower(initiatorEmail),
		CreatedAt:      time.Now(),
		Participants:   make(map[string]SBParticipant),
		PendingInvites: make(map[string]string),
	}
	m.rooms[sessionID] = room

	return sessionID, cookie
}

func (m *SwitchboardManager) PrepareInvite(sessionID int, calleeEmail string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	room, ok := m.rooms[sessionID]
	if !ok {
		return ""
	}

	cookie := m.authManager.CreateSBCookie(calleeEmail, sessionID, "callee", 120*time.Second)
	room.PendingInvites[strings.ToLower(calleeEmail)] = cookie
	return cookie
}

func (m *SwitchboardManager) GetRoom(sessionID int) *SwitchboardRoom {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rooms[sessionID]
}

func (m *SwitchboardManager) JoinRoom(sessionID int, participant SBParticipant) ([]SBParticipant, *SwitchboardRoom) {
	m.mu.Lock()
	defer m.mu.Unlock()

	room, ok := m.rooms[sessionID]
	if !ok {
		return nil, nil
	}

	email := strings.ToLower(participant.GetEmail())
	var existing []SBParticipant
	for pEmail, p := range room.Participants {
		if pEmail != email {
			existing = append(existing, p)
		}
	}

	room.Participants[email] = participant
	delete(room.PendingInvites, email)

	return existing, room
}

func (m *SwitchboardManager) LeaveRoom(sessionID int, email string) *SwitchboardRoom {
	m.mu.Lock()
	defer m.mu.Unlock()

	room, ok := m.rooms[sessionID]
	if !ok {
		return nil
	}

	lowerEmail := strings.ToLower(email)
	delete(room.Participants, lowerEmail)

	// Notify remaining participants
	for _, p := range room.Participants {
		p.SendBYE(email)
	}

	// Close room if empty
	if len(room.Participants) == 0 {
		delete(m.rooms, sessionID)
		return nil
	}

	return room
}

func (m *SwitchboardManager) BroadcastMessage(sessionID int, senderEmail, senderFriendlyName string, payload []byte, database *db.Database) []string {
	m.mu.RLock()
	room, ok := m.rooms[sessionID]
	m.mu.RUnlock()

	if !ok {
		return nil
	}

	lowerSender := strings.ToLower(senderEmail)
	var blockedUsers []string

	for email, p := range room.Participants {
		if email == lowerSender {
			continue
		}

		if database != nil {
			penalty, _ := database.GetUserPenaltyStatus(email)
			if penalty != nil && penalty.IsBanned {
				blockedUsers = append(blockedUsers, email)
				continue
			}
		}

		p.SendMsgRelay(senderEmail, senderFriendlyName, payload)
	}

	return blockedUsers
}

func (m *SwitchboardManager) BroadcastTyping(sessionID int, senderEmail string, payload []byte) {
	m.mu.RLock()
	room, ok := m.rooms[sessionID]
	m.mu.RUnlock()

	if !ok {
		return
	}

	lowerSender := strings.ToLower(senderEmail)
	for email, p := range room.Participants {
		if email == lowerSender {
			continue
		}
		p.SendNotRelay(senderEmail, payload)
	}
}

// Service Bot Integration

func (m *SwitchboardManager) QueueServiceMessage(targetEmail, message string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := strings.ToLower(targetEmail)
	m.pendingServiceMessages[key] = append(m.pendingServiceMessages[key], message)
}

func (m *SwitchboardManager) PopPendingServiceMessages(targetEmail string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := strings.ToLower(targetEmail)
	msgs := m.pendingServiceMessages[key]
	delete(m.pendingServiceMessages, key)
	return msgs
}

func (m *SwitchboardManager) SendSystemMessageToUserRooms(userEmail, senderEmail, senderName, message string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	lowerUser := strings.ToLower(userEmail)
	header := fmt.Sprintf(
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nX-MMS-IM-Format: FN=Segoe%%20UI; EF=; CO=0; CS=0; PF=0\r\n\r\n[%s]:\r\n%s\r\n",
		senderName, message,
	)
	payload := []byte(header)

	for _, room := range m.rooms {
		if room.HasServiceBot && len(room.Participants) == 1 {
			if targetP, ok := room.Participants[lowerUser]; ok {
				targetP.SendMsgRelay(senderEmail, senderName, payload)
				return true
			}
		}
	}
	return false
}

func (m *SwitchboardManager) DeliverServicePM(targetEmail, message string, sessMgr *SessionManager, externalHost string, sbPort int) bool {
	serviceEmail := "system@msn.local"
	serviceName := "Служба сообщений MSN"

	if m.SendSystemMessageToUserRooms(targetEmail, serviceEmail, serviceName, message) {
		return true
	}

	if sessMgr == nil || !sessMgr.IsOnline(targetEmail) {
		return false
	}

	m.QueueServiceMessage(targetEmail, message)

	sessionID, _ := m.AllocateSession(serviceEmail)
	room := m.GetRoom(sessionID)
	if room != nil {
		room.HasServiceBot = true
	}

	cookie := m.PrepareInvite(sessionID, targetEmail)
	if cookie != "" {
		host := externalHost
		if (host == "" || host == "127.0.0.1" || host == "localhost") && sessMgr != nil {
			targetSess := sessMgr.GetSession(targetEmail)
			if targetSess != nil && targetSess.GetEffectiveHost() != "" {
				host = targetSess.GetEffectiveHost()
			}
		}
		return sessMgr.SendSwitchboardRing(targetEmail, sessionID, host, sbPort, cookie, serviceEmail, serviceName)
	}

	return false
}
