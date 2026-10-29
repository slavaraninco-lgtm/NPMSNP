package handlers

import (
	"fmt"
	"log"
	"strings"

	"npmsnp/pkg/db"
	"npmsnp/pkg/protocol"
)

// IM2Profile handles connections and timing quirks for IM2 (Instant Messenger 2).
type IM2Profile struct{}

func NewIM2Profile() *IM2Profile {
	return &IM2Profile{}
}

func (p *IM2Profile) Name() string {
	return "IM2 (Instant Messenger 2)"
}

func (p *IM2Profile) IsANSI() bool {
	// IM2 expects Windows-1251 Cyrillic characters
	return true
}

func (p *IM2Profile) HandleCVR(h *NSClientHandler, args []string) bool {
	return false
}

func (p *IM2Profile) HandleUSR(h *NSClientHandler, args []string) bool {
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

		log.Printf("[NS] Direct TWN authentication granted for IM2: %s", h.email)
		h.loginSuccessful(trid, user)
		return true
	}
	return false
}

func (p *IM2Profile) OnLoginSuccessful(h *NSClientHandler, trid string, user *db.UserRecord) {
	// IM2 receives standard USR OK, but MUST NOT receive unsolicited SYN before CHG!
	if inSlice([]int{6, 7}, h.dialect) {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName, 1)
	} else if h.dialect >= 8 {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName, 1, 0)
	} else {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName)
	}
	// Note: We deliberately do NOT call sendContactList here.
	// IM2 sends CHG next, and the contact list will be delivered during CHG.
}

func (p *IM2Profile) HandleCHG(h *NSClientHandler, args []string) bool {
	// IM2 frequently sends `CHG NLN 0` without a transaction ID
	statusValues := map[string]bool{
		"NLN": true, "BSY": true, "IDL": true, "BRB": true,
		"AWY": true, "PHN": true, "LUN": true, "HDN": true, "FLN": true,
	}

	trid := "0"
	newStatus := "NLN"
	clientID := "0"
	msnObj := ""

	if len(args) > 0 && statusValues[strings.ToUpper(args[0])] {
		trid = "0"
		newStatus = strings.ToUpper(args[0])
		if len(args) > 1 {
			clientID = args[1]
		}
		if len(args) > 2 {
			msnObj = strings.Join(args[2:], " ")
		}
	} else if len(args) >= 2 {
		trid = args[0]
		newStatus = strings.ToUpper(args[1])
		if len(args) > 2 {
			clientID = args[2]
		}
		if len(args) > 3 {
			msnObj = strings.Join(args[3:], " ")
		}
	} else if len(args) > 0 {
		trid = args[0]
		newStatus = "NLN"
	}

	h.status = newStatus
	h.clientID = clientID
	h.msnObj = msnObj

	_ = h.database.UpdateUserStatus(h.email, h.status, &h.clientID, &h.customMessage, &h.msnObj)

	if h.dialect >= 9 && h.msnObj != "" {
		h.SendCmd("CHG", trid, h.status, h.clientID, h.msnObj)
	} else if h.dialect >= 8 {
		h.SendCmd("CHG", trid, h.status, h.clientID)
	} else {
		h.SendCmd("CHG", trid, h.status)
	}

	// Deliver contact list now that IM2 is ready in CHG state
	if !h.contactListSent {
		h.sendContactList(trid, false)
	}

	if !h.initialPresenceSent {
		h.initialPresenceSent = true
		h.sessionManager.SendInitialPresence(h, trid)
		h.deliverOfflineMessages()

		penalty, _ := h.database.GetUserPenaltyStatus(h.email)
		if penalty != nil {
			serviceEmail := "system@msn.local"
			serviceName := "Служба сообщений MSN"
			if penalty.IsBanned {
				reason := ""
				if penalty.BanReason != "" {
					reason = fmt.Sprintf(" Причина: %s.", penalty.BanReason)
				}
				warn := fmt.Sprintf("Внимание: Ваша учетная запись заблокирована (бан).%s До окончания блокировки осталось: %s.", reason, penalty.BanRemaining)
				h.SendSystemNotification(warn, serviceEmail, serviceName)
			} else if penalty.IsMuted {
				reason := ""
				if penalty.MuteReason != "" {
					reason = fmt.Sprintf(" Причина: %s.", penalty.MuteReason)
				}
				warn := fmt.Sprintf("Внимание: Вам временно ограничен доступ к отправке сообщений (мут).%s До окончания мута осталось: %s.", reason, penalty.MuteRemaining)
				h.SendSystemNotification(warn, serviceEmail, serviceName)
			}
		}
	}

	h.sessionManager.BroadcastStatusChange(h)
	return true
}

func (p *IM2Profile) SendContactList(h *NSClientHandler, trid string, force bool) {
	sendStandardContactList(h, trid)
}
