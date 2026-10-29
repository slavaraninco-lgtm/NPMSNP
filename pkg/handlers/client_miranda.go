package handlers

import (
	"log"
	"strings"

	"npmsnp/pkg/db"
	"npmsnp/pkg/protocol"
)

// MirandaProfile handles connections from Miranda IM (0.8.0, legacy) and Miranda NG.
type MirandaProfile struct {
	clientApp string
}

func NewMirandaProfile(clientApp string) *MirandaProfile {
	return &MirandaProfile{
		clientApp: clientApp,
	}
}

func (p *MirandaProfile) Name() string {
	return "Miranda IM / NG"
}

func (p *MirandaProfile) IsANSI() bool {
	// Miranda IM plugins use ANSI code pages (CP1251 for Cyrillic)
	return true
}

func (p *MirandaProfile) HandleCVR(h *NSClientHandler, args []string) bool {
	return false
}

func (p *MirandaProfile) HandleUSR(h *NSClientHandler, args []string) bool {
	if len(args) < 3 {
		return false
	}
	trid := args[0]
	authType := strings.ToUpper(args[1])
	stage := strings.ToUpper(args[2])

	// Miranda with TWN or SSO direct login
	if (authType == "TWN" || authType == "SSO") && stage == "I" {
		if len(args) > 3 {
			h.email = strings.TrimSpace(args[3])
		}
		if !strings.Contains(h.email, "@") {
			h.SendError(protocol.ErrInvalidUser, trid)
			h.Close()
			return true
		}
		user, _ := h.database.GetUser(h.email)
		if user == nil {
			user, _ = h.database.CreateUser(h.email, "123456", "")
		}

		log.Printf("[NS] Direct %s authentication granted for Miranda: %s", authType, h.email)
		h.loginSuccessful(trid, user)
		return true
	}

	// Miranda with MD5
	if authType == "MD5" {
		if stage == "I" {
			email := ""
			if len(args) > 3 {
				email = strings.TrimSpace(args[3])
			}
			if !strings.Contains(email, "@") {
				h.SendError(protocol.ErrInvalidUser, trid)
				h.Close()
				return true
			}
			h.email = email
			user, _ := h.database.GetUser(email)
			if user == nil {
				user, _ = h.database.CreateUser(email, "123456", "")
			}
			challenge := h.authManager.CreateMD5Challenge(email)
			h.SendCmd("USR", trid, "MD5", "S", challenge)
			return true

		} else if stage == "S" {
			responseHash := ""
			if len(args) > 3 {
				responseHash = strings.TrimSpace(args[3])
			}
			user, _ := h.database.GetUser(h.email)
			if user == nil {
				log.Printf("[NS] MD5 auth failed: user '%s' not found.", h.email)
				h.SendError(protocol.ErrAuthenticationFailed, trid)
				h.Close()
				return true
			}

			// 1. Direct match with verified password or stored MD5 hash
			if h.authManager.VerifyMD5Response(h.email, responseHash, user.Password) {
				log.Printf("[NS] MD5 authentication successful for Miranda: %s", h.email)
				h.loginSuccessful(trid, user)
				return true
			}

			// 2. Check if user has stored response hash
			if strings.HasPrefix(user.Password, "md5resp:") {
				stored := strings.TrimPrefix(user.Password, "md5resp:")
				if strings.EqualFold(responseHash, stored) {
					log.Printf("[NS] MD5 response authentication successful for Miranda: %s", h.email)
					h.loginSuccessful(trid, user)
					return true
				}
			}

			// 3. Auto-registration fallback: if user has default "123456" password, accept the user's chosen password
			if user.Password == "123456" {
				log.Printf("[NS] Auto-registering password hash for %s via Miranda MD5", h.email)
				_ = h.database.UpdatePassword(h.email, "md5resp:"+responseHash)
				h.loginSuccessful(trid, user)
				return true
			}

			log.Printf("[NS] MD5 auth failed for '%s': password mismatch!", h.email)
			h.SendError(protocol.ErrAuthenticationFailed, trid)
			h.Close()
			return true
		}
	}

	return false
}

func (p *MirandaProfile) OnLoginSuccessful(h *NSClientHandler, trid string, user *db.UserRecord) {
	if inSlice([]int{6, 7}, h.dialect) {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName, 1)
	} else if h.dialect >= 8 {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName, 1, 0)
	} else {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName)
	}
}

func (p *MirandaProfile) HandleCHG(h *NSClientHandler, args []string) bool {
	return false
}

func (p *MirandaProfile) SendContactList(h *NSClientHandler, trid string, force bool) {
	sendStandardContactList(h, trid)
}
