package handlers

import (
	"log"
	"strings"

	"npmsnp/pkg/db"
	"npmsnp/pkg/protocol"
)

// GaimProfile handles connections from Gaim and Pidgin.
type GaimProfile struct{}

func NewGaimProfile() *GaimProfile {
	return &GaimProfile{}
}

func (p *GaimProfile) Name() string {
	return "Gaim / Pidgin"
}

func (p *GaimProfile) IsANSI() bool {
	// Gaim/Pidgin natively handles modern UTF-8
	return false
}

func (p *GaimProfile) HandleCVR(h *NSClientHandler, args []string) bool {
	// Standard CVR handling is sufficient
	return false
}

func (p *GaimProfile) HandleUSR(h *NSClientHandler, args []string) bool {
	if len(args) < 3 {
		return false
	}
	trid := args[0]
	authType := strings.ToUpper(args[1])
	stage := strings.ToUpper(args[2])

	if authType == "TWN" && stage == "I" {
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

		log.Printf("[NS] Direct TWN authentication granted for Gaim/Pidgin: %s", h.email)
		h.loginSuccessful(trid, user)
		return true
	}
	return false
}

func (p *GaimProfile) OnLoginSuccessful(h *NSClientHandler, trid string, user *db.UserRecord) {
	if inSlice([]int{6, 7}, h.dialect) {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName, 1)
	} else if h.dialect >= 8 {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName, 1, 0)
	} else {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName)
	}
}

func (p *GaimProfile) HandleCHG(h *NSClientHandler, args []string) bool {
	return false
}

func (p *GaimProfile) SendContactList(h *NSClientHandler, trid string, force bool) {
	sendStandardContactList(h, trid)
}
