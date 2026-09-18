package services

import (
	"strings"
	"sync"

	"npmsnp/pkg/db"
	"npmsnp/pkg/protocol"
)

// NSClientSession represents an active Notification Server client connection.
type NSClientSession interface {
	GetEmail() string
	GetFriendlyName() string
	GetStatus() string
	GetClientID() string
	GetCustomMessage() string
	GetMSNObj() string
	GetPeerName() string
	GetEffectiveHost() string
	IsANSI() bool
	SendCmd(cmd string, args ...interface{})
	SendPayload(cmd string, payload []byte, args ...interface{})
	SendNLN(status, email, friendlyName, clientID, msnObj string)
	SendFLN(email string)
	SendILN(trid, status, email, friendlyName, clientID, msnObj string)
	SendRNG(sessionID int, sbHost string, sbPort int, cookie, callerEmail, callerFriendlyName string)
	SendSystemNotification(msg, senderEmail, senderName string) bool
	Close()
}

type SessionManager struct {
	db       *db.Database
	mu       sync.RWMutex
	sessions map[string]NSClientSession
}

func NewSessionManager(database *db.Database) *SessionManager {
	return &SessionManager{
		db:       database,
		sessions: make(map[string]NSClientSession),
	}
}

func (s *SessionManager) RegisterSession(email string, sess NSClientSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[strings.ToLower(email)] = sess
}

func (s *SessionManager) UnregisterSession(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, strings.ToLower(email))
}

func (s *SessionManager) GetSession(email string) NSClientSession {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessions[strings.ToLower(email)]
}

func (s *SessionManager) DisconnectUser(email string) bool {
	s.mu.RLock()
	sess := s.sessions[strings.ToLower(email)]
	s.mu.RUnlock()
	if sess != nil {
		sess.SendCmd("207")
		sess.Close()
		s.UnregisterSession(email)
		return true
	}
	return false
}

func (s *SessionManager) IsOnline(email string) bool {
	serviceEmail := "system@msn.local"
	if strings.EqualFold(email, serviceEmail) {
		return true
	}
	sess := s.GetSession(email)
	if sess == nil {
		return false
	}
	st := sess.GetStatus()
	return st != protocol.StatusOffline && st != protocol.StatusHidden
}

func (s *SessionManager) GetActiveUsersCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.sessions)
}

type ActiveUserInfo struct {
	Email         string `json:"email"`
	FriendlyName  string `json:"friendly_name"`
	Status        string `json:"status"`
	ClientID      string `json:"client_id"`
	CustomMessage string `json:"custom_message"`
	Peer          string `json:"peer"`
}

func (s *SessionManager) GetActiveUsersList() []ActiveUserInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []ActiveUserInfo
	for _, sess := range s.sessions {
		result = append(result, ActiveUserInfo{
			Email:         sess.GetEmail(),
			FriendlyName:  sess.GetFriendlyName(),
			Status:        sess.GetStatus(),
			ClientID:      sess.GetClientID(),
			CustomMessage: sess.GetCustomMessage(),
			Peer:          sess.GetPeerName(),
		})
	}
	return result
}

// Presence Distribution

func (s *SessionManager) SendInitialPresence(sess NSClientSession, trid string) {
	userEmail := sess.GetEmail()
	contacts, err := s.db.GetContacts(userEmail)
	if err != nil {
		return
	}

	serviceEmail := "system@msn.local"
	serviceName := "Служба сообщений MSN"
	botSent := false

	for _, c := range contacts {
		if c.ListFlags&protocol.ListFL != 0 {
			if strings.EqualFold(c.ContactEmail, serviceEmail) {
				fname := c.FriendlyName
				if fname == "" {
					fname = serviceName
				}
				sess.SendILN(trid, protocol.StatusOnline, serviceEmail, fname, "0", "")
				botSent = true
				continue
			}

			contactSess := s.GetSession(c.ContactEmail)
			if contactSess != nil && contactSess.GetStatus() != protocol.StatusOffline && contactSess.GetStatus() != protocol.StatusHidden {
				// Check that contact hasn't blocked the user
				contactRecord, _ := s.db.GetContact(c.ContactEmail, userEmail)
				if !(contactRecord != nil && contactRecord.ListFlags&protocol.ListBL != 0) {
					fname := c.FriendlyName
					if fname == "" {
						fname = contactSess.GetFriendlyName()
					}
					sess.SendILN(trid, contactSess.GetStatus(), contactSess.GetEmail(), fname, contactSess.GetClientID(), contactSess.GetMSNObj())
				}
			}
		}
	}

	if !botSent {
		sess.SendILN(trid, protocol.StatusOnline, serviceEmail, serviceName, "0", "")
	}
}

func (s *SessionManager) BroadcastStatusChange(sess NSClientSession) {
	userEmail := strings.ToLower(sess.GetEmail())
	status := sess.GetStatus()
	friendlyName := sess.GetFriendlyName()
	clientID := sess.GetClientID()
	msnObj := sess.GetMSNObj()

	effectiveStatus := status
	if status == protocol.StatusHidden {
		effectiveStatus = protocol.StatusOffline
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	for contactEmail, targetSess := range s.sessions {
		if contactEmail == userEmail {
			continue
		}

		c, _ := s.db.GetContact(targetSess.GetEmail(), userEmail)
		if c != nil && c.ListFlags&protocol.ListFL != 0 {
			userContact, _ := s.db.GetContact(userEmail, targetSess.GetEmail())
			if userContact != nil && userContact.ListFlags&protocol.ListBL != 0 {
				targetSess.SendFLN(userEmail)
			} else if effectiveStatus == protocol.StatusOffline {
				targetSess.SendFLN(userEmail)
			} else {
				targetSess.SendNLN(effectiveStatus, userEmail, friendlyName, clientID, msnObj)
			}
		}
	}
}

func (s *SessionManager) BroadcastFriendlyNameChange(userEmail, newFriendlyName string) {
	sess := s.GetSession(userEmail)
	if sess != nil {
		s.BroadcastStatusChange(sess)
	}
}

func (s *SessionManager) BroadcastOffline(userEmail string) {
	lowerEmail := strings.ToLower(userEmail)
	s.mu.RLock()
	defer s.mu.RUnlock()

	for contactEmail, sess := range s.sessions {
		if contactEmail == lowerEmail {
			continue
		}
		c, _ := s.db.GetContact(sess.GetEmail(), userEmail)
		if c != nil && c.ListFlags&protocol.ListFL != 0 {
			sess.SendFLN(userEmail)
		}
	}
}

// Switchboard Invitation Dispatch

func (s *SessionManager) SendSwitchboardRing(calleeEmail string, sessionID int, sbHost string, sbPort int,
	cookie, callerEmail, callerFriendlyName string) bool {
	calleeSess := s.GetSession(calleeEmail)
	if calleeSess == nil {
		return false
	}
	calleeSess.SendRNG(sessionID, sbHost, sbPort, cookie, callerEmail, callerFriendlyName)
	return true
}

// System Notifications

func (s *SessionManager) SendSystemNotification(email, message, senderEmail, senderName string) bool {
	sess := s.GetSession(email)
	if sess == nil {
		return false
	}
	return sess.SendSystemNotification(message, senderEmail, senderName)
}

func (s *SessionManager) BroadcastSystemNotification(message, senderEmail, senderName string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, sess := range s.sessions {
		if sess.SendSystemNotification(message, senderEmail, senderName) {
			count++
		}
	}
	return count
}
