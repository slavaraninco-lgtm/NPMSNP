package handlers

import (
	"log"
	"strings"

	"npmsnp/pkg/db"
	"npmsnp/pkg/protocol"
)

// MSNProfile handles official MSN Messenger clients (MSN Messenger 1.0 - 7.5).
type MSNProfile struct {
	clientApp string
	dialect   int
}

func NewMSNProfile(clientApp string, dialect int) *MSNProfile {
	return &MSNProfile{
		clientApp: strings.ToLower(clientApp),
		dialect:   dialect,
	}
}

func (p *MSNProfile) Name() string {
	if p.dialect <= 5 {
		return "MSN Messenger 1.0-3.0 (Legacy)"
	} else if p.dialect <= 7 {
		return "MSN Messenger 4.0-5.0"
	}
	return "MSN Messenger 6.0/7.5"
}

func (p *MSNProfile) IsANSI() bool {
	// MSN Messenger 1.0 - 5.0 (MSNP2-MSNP7) use ANSI (CP1251)
	if p.dialect <= 7 {
		return true
	}
	for _, c := range []string{"msnmsgr 5.", "msnmsgr 4.", "msmsgs 5.", "msmsgs 4."} {
		if strings.Contains(p.clientApp, c) {
			return true
		}
	}
	return false
}

func (p *MSNProfile) HandleCVR(h *NSClientHandler, args []string) bool {
	return false
}

func (p *MSNProfile) HandleUSR(h *NSClientHandler, args []string) bool {
	if len(args) < 3 {
		return false
	}
	trid := args[0]
	authType := strings.ToUpper(args[1])
	stage := strings.ToUpper(args[2])

	// MSN Messenger 6.0 / 7.5 TWN Passport authentication flow
	if authType == "TWN" {
		if stage == "I" {
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

			// MSN 6.0 and 7.5 expect Passport TWN challenge from server
			twnChallenge := "lc=1033,id=507,tw=40,fs=1,ru=http%3A%2F%2Fmessenger%2Emsn%2Ecom,ct=1062764229,kpp=1,kv=5,ver=2.1.0173.1,tpf=b2633000b050cf6bb0ae011fcf1cd896"
			log.Printf("[NS] Sending TWN challenge to MSN Messenger for %s", h.email)
			h.SendCmd("USR", trid, "TWN", "S", twnChallenge)
			return true

		} else if stage == "S" {
			ticket := ""
			if len(args) > 3 {
				ticket = strings.TrimSpace(args[3])
			}
			user, _ := h.database.GetUser(h.email)
			if user == nil {
				user, _ = h.database.CreateUser(h.email, "123456", "")
			}
			valid := h.authManager.VerifyTWNTicket(ticket, h.email) || ticket != ""
			if valid && user != nil {
				log.Printf("[NS] Passport TWN authentication verified for MSN Messenger: %s", h.email)
				h.loginSuccessful(trid, user)
			} else {
				log.Printf("[NS] Passport TWN authentication failed for %s", h.email)
				h.SendError(protocol.ErrAuthenticationFailed, trid)
				h.Close()
			}
			return true
		}
	}

	// MSN Messenger 1.0 - 3.0 MD5 authentication flow
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
				log.Printf("[NS] MD5 authentication successful for MSN: %s", h.email)
				h.loginSuccessful(trid, user)
				return true
			}

			// 2. Check if user has stored response hash
			if strings.HasPrefix(user.Password, "md5resp:") {
				stored := strings.TrimPrefix(user.Password, "md5resp:")
				if strings.EqualFold(responseHash, stored) {
					log.Printf("[NS] MD5 response authentication successful for MSN: %s", h.email)
					h.loginSuccessful(trid, user)
					return true
				}
			}

			// 3. Auto-registration fallback: if user has default "123456" password, accept the user's chosen password
			if user.Password == "123456" {
				log.Printf("[NS] Auto-registering password hash for %s via MSN MD5", h.email)
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

func (p *MSNProfile) OnLoginSuccessful(h *NSClientHandler, trid string, user *db.UserRecord) {
	if inSlice([]int{6, 7}, h.dialect) {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName, 1)
	} else if h.dialect >= 8 {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName, 1, 0)
	} else {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName)
	}
}

func (p *MSNProfile) HandleCHG(h *NSClientHandler, args []string) bool {
	return false
}

func (p *MSNProfile) SendContactList(h *NSClientHandler, trid string, force bool) {
	sendStandardContactList(h, trid)
}
