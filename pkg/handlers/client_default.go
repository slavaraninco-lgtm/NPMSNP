package handlers

import (
	"strings"

	"npmsnp/pkg/db"
	"npmsnp/pkg/protocol"
)

// DefaultProfile provides standard, unadapted MSNP behavior for generic clients.
type DefaultProfile struct{}

func NewDefaultProfile() *DefaultProfile {
	return &DefaultProfile{}
}

func (p *DefaultProfile) Name() string {
	return "Standard MSNP"
}

func (p *DefaultProfile) IsANSI() bool {
	return false
}

func (p *DefaultProfile) HandleCVR(h *NSClientHandler, args []string) bool {
	return false
}

func (p *DefaultProfile) HandleUSR(h *NSClientHandler, args []string) bool {
	return false
}

func (p *DefaultProfile) OnLoginSuccessful(h *NSClientHandler, trid string, user *db.UserRecord) {
	if inSlice([]int{6, 7}, h.dialect) {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName, 1)
	} else if h.dialect >= 8 {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName, 1, 0)
	} else {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName)
	}
}

func (p *DefaultProfile) HandleCHG(h *NSClientHandler, args []string) bool {
	return false
}

func (p *DefaultProfile) SendContactList(h *NSClientHandler, trid string, force bool) {
	sendStandardContactList(h, trid)
}

func sendStandardContactList(h *NSClientHandler, trid string) {
	contacts, _ := h.database.GetContacts(h.email)

	serviceEmail := "system@msn.local"
	serviceName := "Служба сообщений MSN"
	if !strings.EqualFold(h.email, serviceEmail) {
		found := false
		for _, c := range contacts {
			if strings.EqualFold(c.ContactEmail, serviceEmail) {
				found = true
				break
			}
		}
		if !found {
			cRec, err := h.database.AddOrUpdateContact(h.email, serviceEmail, protocol.ListFL|protocol.ListAL|protocol.ListRL, 0, serviceName)
			if err == nil && cRec != nil {
				contacts = append(contacts, cRec)
			}
		}
	}

	groups, _ := h.database.GetGroups(h.email)
	totalGroups := len(groups) + 1
	user, _ := h.database.GetUser(h.email)

	h.syncSerial++

	if h.dialect < 6 {
		// MSNP2 - MSNP5
		h.SendCmd("SYN", trid, h.syncSerial)
		h.SendCmd("GTC", trid, h.syncSerial, "A")
		h.SendCmd("BLP", trid, h.syncSerial, "AL")

		listSpecs := []struct {
			name string
			mask int
		}{
			{"FL", protocol.ListFL},
			{"AL", protocol.ListAL},
			{"BL", protocol.ListBL},
			{"RL", protocol.ListRL},
		}
		for _, spec := range listSpecs {
			var cs []*db.ContactRecord
			for _, c := range contacts {
				if c.ListFlags&spec.mask != 0 {
					cs = append(cs, c)
				}
			}
			if len(cs) > 0 {
				for i, c := range cs {
					fname := c.FriendlyName
					if fname == "" {
						fname = c.ContactEmail
					}
					h.SendCmd("LST", trid, spec.name, h.syncSerial, i+1, len(cs), c.ContactEmail, fname)
				}
			} else {
				h.SendCmd("LST", trid, spec.name, h.syncSerial, 0, 0)
			}
		}
	} else if h.dialect < 8 {
		// MSNP6 - MSNP7
		h.SendCmd("SYN", trid, h.syncSerial)
		h.SendCmd("GTC", trid, h.syncSerial, "A")
		h.SendCmd("BLP", trid, h.syncSerial, "AL")

		h.SendCmd("LSG", trid, h.syncSerial, 1, totalGroups, 0, "Other Contacts", 0)
		for i, g := range groups {
			h.SendCmd("LSG", trid, h.syncSerial, i+2, totalGroups, g.ID, g.Name, 0)
		}

		listSpecs := []struct {
			name string
			mask int
		}{
			{"FL", protocol.ListFL},
			{"AL", protocol.ListAL},
			{"BL", protocol.ListBL},
			{"RL", protocol.ListRL},
		}
		for _, spec := range listSpecs {
			var cs []*db.ContactRecord
			for _, c := range contacts {
				if c.ListFlags&spec.mask != 0 {
					cs = append(cs, c)
				}
			}
			if len(cs) > 0 {
				for i, c := range cs {
					fname := c.FriendlyName
					if fname == "" {
						fname = c.ContactEmail
					}
					gid := 0
					if spec.name == "FL" {
						gid = c.GroupID
					}
					h.SendCmd("LST", trid, spec.name, h.syncSerial, i+1, len(cs), c.ContactEmail, fname, gid)
				}
			} else {
				h.SendCmd("LST", trid, spec.name, h.syncSerial, 0, 0)
			}
		}
	} else {
		// MSNP8+
		h.SendCmd("SYN", trid, h.syncSerial, len(contacts), totalGroups)
		h.SendCmd("GTC", "A")
		h.SendCmd("BLP", "AL")

		if user != nil {
			if user.PhoneHome != "" {
				h.SendCmd("PRP", "PHH", user.PhoneHome)
			}
			if user.PhoneWork != "" {
				h.SendCmd("PRP", "PHW", user.PhoneWork)
			}
			if user.PhoneMobile != "" {
				h.SendCmd("PRP", "PHM", user.PhoneMobile)
			}
		}

		h.SendCmd("LSG", 0, "Other Contacts", 0)
		for _, g := range groups {
			h.SendCmd("LSG", g.ID, g.Name, 0)
		}

		for _, c := range contacts {
			fname := c.FriendlyName
			if fname == "" {
				fname = c.ContactEmail
			}
			if c.ListFlags&protocol.ListFL != 0 {
				h.SendCmd("LST", c.ContactEmail, fname, c.ListFlags, c.GroupID)
			} else {
				h.SendCmd("LST", c.ContactEmail, fname, c.ListFlags)
			}
		}
	}
}
