package handlers

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"npmsnp/pkg/config"
	"npmsnp/pkg/db"
	"npmsnp/pkg/protocol"
	"npmsnp/pkg/services"
)

type NSClientHandler struct {
	conn               net.Conn
	reader             *bufio.Reader
	writerMu           sync.Mutex
	database           *db.Database
	authManager        *protocol.AuthManager
	sessionManager     *services.SessionManager
	switchboardManager *services.SwitchboardManager
	externalHost       string
	nsPort             int
	sbPort             int
	httpPort           int

	dialect             int
	authenticated       bool
	email               string
	friendlyName        string
	status              string
	clientID            string
	customMessage       string
	msnObj              string
	syncSerial          int
	initialPresenceSent bool
	contactListSent     bool
	clientApp           string
	authType            string
	peerName            string
	closed              bool
	closeOnce           sync.Once
}

func NewNSClientHandler(conn net.Conn, database *db.Database, authManager *protocol.AuthManager,
	sessionManager *services.SessionManager, switchboardManager *services.SwitchboardManager,
	externalHost string, nsPort, sbPort, httpPort int) *NSClientHandler {

	peer := "0.0.0.0:0"
	if conn != nil && conn.RemoteAddr() != nil {
		peer = conn.RemoteAddr().String()
	}

	return &NSClientHandler{
		conn:               conn,
		reader:             bufio.NewReader(conn),
		database:           database,
		authManager:        authManager,
		sessionManager:     sessionManager,
		switchboardManager: switchboardManager,
		externalHost:       externalHost,
		nsPort:             nsPort,
		sbPort:             sbPort,
		httpPort:           httpPort,
		dialect:            9, // Default MSNP9
		status:             protocol.StatusOffline,
		clientID:           "0",
		syncSerial:         1,
		peerName:           peer,
	}
}

// NSClientSession interface implementation

func (h *NSClientHandler) GetEmail() string {
	return h.email
}

func (h *NSClientHandler) GetFriendlyName() string {
	return h.friendlyName
}

func (h *NSClientHandler) GetStatus() string {
	return h.status
}

func (h *NSClientHandler) GetClientID() string {
	return h.clientID
}

func (h *NSClientHandler) GetCustomMessage() string {
	return h.customMessage
}

func (h *NSClientHandler) GetMSNObj() string {
	return h.msnObj
}

func (h *NSClientHandler) GetPeerName() string {
	return h.peerName
}

func (h *NSClientHandler) IsIM2() bool {
	app := strings.ToLower(h.clientApp)
	return strings.Contains(app, "im2") || strings.Contains(app, "instantmessenger2") || strings.Contains(app, "im 2")
}

func (h *NSClientHandler) IsANSI() bool {
	app := strings.ToLower(h.clientApp)
	for _, c := range []string{"trillian", "miranda", "im2", "im 2", "qip", "kopete", "sim", "msnmsgr 5.", "msnmsgr 4."} {
		if strings.Contains(app, c) {
			return true
		}
	}
	if h.dialect < 8 {
		return true
	}
	if h.authType == "MD5" && !strings.Contains(app, "gaim") && !strings.Contains(app, "pidgin") {
		return true
	}
	return false
}

func (h *NSClientHandler) GetEffectiveHost() string {
	if h.externalHost != "" && h.externalHost != "127.0.0.1" && h.externalHost != "0.0.0.0" && h.externalHost != "localhost" {
		return h.externalHost
	}

	if h.conn != nil {
		localAddr := h.conn.LocalAddr()
		if tcpAddr, ok := localAddr.(*net.TCPAddr); ok && tcpAddr.IP != nil {
			ip := tcpAddr.IP.String()
			if ip != "0.0.0.0" && ip != "127.0.0.1" && ip != "::1" && !strings.HasPrefix(ip, "127.") {
				return ip
			}
		}

		remoteAddr := h.conn.RemoteAddr()
		if tcpAddr, ok := remoteAddr.(*net.TCPAddr); ok && tcpAddr.IP != nil {
			ip := tcpAddr.IP.String()
			if ip != "127.0.0.1" && ip != "::1" && !strings.HasPrefix(ip, "127.") {
				detected := config.DetectDefaultExternalHost()
				if detected != "" {
					return detected
				}
			}
		}
	}

	if h.externalHost != "" {
		return h.externalHost
	}
	return "127.0.0.1"
}

func (h *NSClientHandler) SendCmd(cmd string, args ...interface{}) {
	raw := protocol.FormatCommand(cmd, h.IsANSI(), args...)
	h.writerMu.Lock()
	defer h.writerMu.Unlock()
	if !h.closed && h.conn != nil {
		_, _ = h.conn.Write([]byte(raw))
	}
}

func (h *NSClientHandler) SendPayload(cmd string, payload []byte, args ...interface{}) {
	raw := protocol.FormatPayloadCommand(cmd, payload, h.IsANSI(), args...)
	h.writerMu.Lock()
	defer h.writerMu.Unlock()
	if !h.closed && h.conn != nil {
		_, _ = h.conn.Write(raw)
	}
}

func (h *NSClientHandler) SendError(code int, trid string) {
	h.SendCmd(fmt.Sprintf("%d", code), trid)
}

func (h *NSClientHandler) Close() {
	h.closeOnce.Do(func() {
		h.closed = true
		if h.authenticated && h.email != "" {
			h.sessionManager.UnregisterSession(h.email)
			h.sessionManager.BroadcastOffline(h.email)
			_ = h.database.UpdateUserStatus(h.email, protocol.StatusOffline, nil, nil, nil)
		}
		if h.conn != nil {
			_ = h.conn.Close()
		}
	})
}

func (h *NSClientHandler) SendNLN(status, email, friendlyName, clientID, msnObj string) {
	if friendlyName == "" {
		friendlyName = email
	}
	if h.dialect >= 9 {
		h.SendCmd("NLN", status, email, friendlyName, clientID, msnObj)
	} else if h.dialect == 8 {
		h.SendCmd("NLN", status, email, friendlyName, clientID)
	} else {
		h.SendCmd("NLN", status, email, friendlyName)
	}
}

func (h *NSClientHandler) SendFLN(email string) {
	h.SendCmd("FLN", email)
}

func (h *NSClientHandler) SendILN(trid, status, email, friendlyName, clientID, msnObj string) {
	if friendlyName == "" {
		friendlyName = email
	}
	if h.dialect >= 9 {
		h.SendCmd("ILN", trid, status, email, friendlyName, clientID, msnObj)
	} else if h.dialect == 8 {
		h.SendCmd("ILN", trid, status, email, friendlyName, clientID)
	} else {
		h.SendCmd("ILN", trid, status, email, friendlyName)
	}
}

func (h *NSClientHandler) SendRNG(sessionID int, sbHost string, sbPort int, cookie, callerEmail, callerFriendlyName string) {
	effectiveSBHost := sbHost
	if effectiveSBHost == "" || effectiveSBHost == "127.0.0.1" || effectiveSBHost == "localhost" || effectiveSBHost == "0.0.0.0" {
		effectiveSBHost = h.GetEffectiveHost()
	}
	sbAddr := fmt.Sprintf("%s:%d", effectiveSBHost, sbPort)
	if callerFriendlyName == "" {
		callerFriendlyName = callerEmail
	}
	h.SendCmd("RNG", sessionID, sbAddr, "CKI", cookie, callerEmail, callerFriendlyName)
}

func (h *NSClientHandler) SendSystemNotification(msg, senderEmail, senderName string) bool {
	if !h.authenticated {
		return false
	}
	payload := fmt.Sprintf(
		"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nX-MMS-IM-Format: FN=Segoe%%20UI; EF=; CO=0; CS=0; PF=0\r\n\r\n[%s]:\r\n%s\r\n",
		senderName, msg,
	)
	h.SendPayload("MSG", []byte(payload), senderEmail, senderName)
	return true
}

// Receive loop

func (h *NSClientHandler) Run() {
	defer h.Close()

	for !h.closed {
		packet, err := protocol.ReadPacket(h.reader)
		if err != nil {
			if err != io.EOF && !h.closed {
				log.Printf("[NS] Read error from %s: %v", h.peerName, err)
			}
			return
		}

		if packet.Command == "" {
			continue
		}

		h.handleCommand(packet)
	}
}

func (h *NSClientHandler) handleCommand(pkt *protocol.Packet) {
	args := pkt.Args

	switch pkt.Command {
	case "VER":
		// VER <trid> <dialects...>
		if len(args) < 1 {
			h.Close()
			return
		}
		trid := args[0]
		offered := make([]string, 0, len(args)-1)
		for _, a := range args[1:] {
			offered = append(offered, strings.ToUpper(a))
		}

		chosen := ""
		for _, d := range protocol.OrderedDialects {
			for _, o := range offered {
				if d == o {
					chosen = d
					break
				}
			}
			if chosen != "" {
				break
			}
		}

		if chosen == "" {
			h.SendCmd("VER", trid, "0")
			h.Close()
			return
		}

		if num, ok := protocol.SupportedDialects[chosen]; ok {
			h.dialect = num
		} else {
			h.dialect = 9
		}

		respArgs := []interface{}{trid, chosen}
		for _, o := range offered {
			if strings.HasPrefix(o, "CVR") {
				respArgs = append(respArgs, o)
				break
			}
		}
		h.SendCmd("VER", respArgs...)

	case "CVR":
		// CVR <trid> <locale> <os_type> <os_ver> <arch> <app_name> <app_ver> ...
		trid := "1"
		if len(args) > 0 {
			trid = args[0]
		}
		if len(args) > 5 {
			h.clientApp = fmt.Sprintf("%s %s", args[5], strings.Join(args[6:], " "))
		}
		host := h.GetEffectiveHost()
		url := fmt.Sprintf("http://%s:%d/", host, h.httpPort)
		h.SendCmd("CVR", trid, "6.0.0602", "6.0.0602", "6.0.0602", url, url)

	case "INF":
		// INF <trid> -> respond with auth type (MD5)
		trid := "1"
		if len(args) > 0 {
			trid = args[0]
		}
		h.SendCmd("INF", trid, "MD5")

	case "USR":
		// USR <trid> <auth_type> <stage> ...
		h.handleUSR(args)

	case "CHG":
		// CHG <trid> <status> [client_id] [msn_obj]
		if len(args) < 2 {
			return
		}
		trid := args[0]
		newStatus := strings.ToUpper(args[1])
		h.status = newStatus

		if len(args) > 2 {
			h.clientID = args[2]
		}
		if len(args) > 3 {
			h.msnObj = strings.Join(args[3:], " ")
		}

		_ = h.database.UpdateUserStatus(h.email, h.status, &h.clientID, &h.customMessage, &h.msnObj)

		// Send CHG response
		if len(args) > 3 && h.dialect >= 9 && h.msnObj != "" {
			h.SendCmd("CHG", trid, h.status, h.clientID, h.msnObj)
		} else if len(args) > 2 && h.dialect >= 8 {
			h.SendCmd("CHG", trid, h.status, h.clientID)
		} else {
			h.SendCmd("CHG", trid, h.status)
		}

		// Push contact list for IM2 if not sent
		if h.IsIM2() && !h.contactListSent {
			h.sendContactList(trid, false)
		}

		if !h.initialPresenceSent {
			h.initialPresenceSent = true
			h.sessionManager.SendInitialPresence(h, trid)
			h.deliverOfflineMessages()

			// Check active penalties and inform user via Service Account
			penalty, _ := h.database.GetUserPenaltyStatus(h.email)
			if penalty != nil {
				serviceEmail := "system@msn.local"
				serviceName := "Служба сообщений MSN"
				if penalty.IsBanned {
					reason := ""
					if penalty.BanReason != "" {
						reason = fmt.Sprintf(" Причина: %s.", penalty.BanReason)
					}
					warn := fmt.Sprintf("Внимание: Ваша учетная запись заблокирована (бан).%s До окончания блокировки осталось: %s. Вы не можете отправлять и принимать сообщения.", reason, penalty.BanRemaining)
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

	case "SYN":
		// SYN <trid> <sync_serial>
		trid := "1"
		if len(args) > 0 {
			trid = args[0]
		}
		h.sendContactList(trid, true)

	case "XFR":
		// XFR <trid> SB (or NS)
		if len(args) < 2 {
			return
		}
		trid := args[0]
		dest := strings.ToUpper(args[1])

		if dest == "SB" {
			_, cookie := h.switchboardManager.AllocateSession(h.email)
			host := h.GetEffectiveHost()
			sbAddr := fmt.Sprintf("%s:%d", host, h.sbPort)
			h.SendCmd("XFR", trid, "SB", sbAddr, "CKI", cookie)
		} else if dest == "NS" {
			host := h.GetEffectiveHost()
			nsAddr := fmt.Sprintf("%s:%d", host, h.nsPort)
			h.SendCmd("XFR", trid, "NS", nsAddr, "0", nsAddr)
		} else {
			h.SendError(protocol.ErrInvalidParameter, trid)
		}

	case "ADD":
		// ADD <trid> <list_type> <contact_email> <friendly_name> [group_id]
		h.handleADD(args)

	case "REM":
		// REM <trid> <list_type> <contact_email>
		h.handleREM(args)

	case "REA":
		// REA <trid> [email] <friendly_name>
		h.handleREA(args)

	case "ADG":
		// ADG <trid> <group_name>
		if len(args) < 2 {
			return
		}
		trid := args[0]
		gName := args[1]
		g, err := h.database.AddGroup(h.email, gName)
		if err == nil && g != nil {
			h.syncSerial++
			h.SendCmd("ADG", trid, h.syncSerial, g.Name, g.ID)
		}

	case "RMG":
		// RMG <trid> <group_id>
		if len(args) < 2 {
			return
		}
		trid := args[0]
		gid, _ := strconv.Atoi(args[1])
		_ = h.database.RemoveGroup(h.email, gid)
		h.syncSerial++
		h.SendCmd("RMG", trid, h.syncSerial, gid)

	case "REG":
		// REG <trid> <group_id> <new_name>
		if len(args) < 3 {
			return
		}
		trid := args[0]
		gid, _ := strconv.Atoi(args[1])
		newName := args[2]
		_ = h.database.RenameGroup(h.email, gid, newName)
		h.syncSerial++
		h.SendCmd("REG", trid, h.syncSerial, gid, newName)

	case "PRP":
		// PRP [trid] <prop_name> <value...>
		h.handlePRP(args)

	case "GTC":
		// GTC <trid> <val>
		trid := "0"
		val := "A"
		if len(args) > 1 {
			trid = args[0]
			val = strings.ToUpper(args[1])
		} else if len(args) > 0 {
			val = strings.ToUpper(args[0])
		}
		h.syncSerial++
		h.SendCmd("GTC", trid, h.syncSerial, val)

	case "BLP":
		// BLP <trid> <val>
		trid := "0"
		val := "AL"
		if len(args) > 1 {
			trid = args[0]
			val = strings.ToUpper(args[1])
		} else if len(args) > 0 {
			val = strings.ToUpper(args[0])
		}
		h.syncSerial++
		h.SendCmd("BLP", trid, h.syncSerial, val)

	case "UUX":
		// UUX <trid> <len>\r\n<payload>
		trid := "1"
		if len(args) > 0 {
			trid = args[0]
		}
		if len(pkt.Payload) > 0 {
			text := string(pkt.Payload)
			if strings.Contains(text, "<PSM>") && strings.Contains(text, "</PSM>") {
				psm := strings.Split(strings.Split(text, "<PSM>")[1], "</PSM>")[0]
				h.customMessage = psm
				_ = h.database.UpdateUserStatus(h.email, h.status, nil, &psm, nil)
			}
		}
		h.SendCmd("UUX", trid, 0)
		h.broadcastUBX()

	case "PNG":
		h.SendCmd("QNG", 60)

	case "QRY":
		// QRY <trid> [challenge_response]
		trid := "1"
		if len(args) > 0 {
			trid = args[0]
		}
		h.SendCmd("QRY", trid)

	case "URL":
		// URL <trid> [type]
		trid := "1"
		if len(args) > 0 {
			trid = args[0]
		}
		host := h.GetEffectiveHost()
		h.SendCmd("URL", trid, fmt.Sprintf("http://%s:%d/", host, h.httpPort), "0")

	case "BPR":
		// BPR ...
		bprArgs := make([]interface{}, len(args))
		for i, a := range args {
			bprArgs[i] = a
		}
		h.SendCmd("BPR", bprArgs...)

	case "CHL", "SDC", "SDG", "PUT", "NOT", "UUN", "UUM", "VAS", "GCF", "QNG":
		return

	case "OUT":
		h.Close()
	}
}

func (h *NSClientHandler) handleUSR(args []string) {
	if len(args) < 3 {
		h.Close()
		return
	}
	trid := args[0]
	authType := strings.ToUpper(args[1])
	h.authType = authType
	stage := strings.ToUpper(args[2])

	if authType == "MD5" {
		if stage == "I" {
			// USR <trid> MD5 I <email>
			email := ""
			if len(args) > 3 {
				email = strings.TrimSpace(args[3])
			}
			if !strings.Contains(email, "@") {
				h.SendError(protocol.ErrInvalidUser, trid)
				h.Close()
				return
			}
			h.email = email
			user, _ := h.database.GetUser(email)
			if user == nil {
				user, _ = h.database.CreateUser(email, "123456", "")
			}
			challenge := h.authManager.CreateMD5Challenge(email)
			h.SendCmd("USR", trid, "MD5", "S", challenge)

		} else if stage == "S" {
			// USR <trid> MD5 S <response_hash>
			responseHash := ""
			if len(args) > 3 {
				responseHash = strings.TrimSpace(args[3])
			}
			user, _ := h.database.GetUser(h.email)
			if user == nil {
				log.Printf("[NS] MD5 auth failed: user '%s' not found in database.", h.email)
				h.SendError(protocol.ErrAuthenticationFailed, trid)
				h.Close()
				return
			}

			if strings.HasPrefix(user.Password, "enc:") {
				log.Printf("[NS] MD5 auth failed: user '%s' password could not be decrypted!", h.email)
				h.SendError(protocol.ErrAuthenticationFailed, trid)
				h.Close()
				return
			}

			if h.authManager.VerifyMD5Response(h.email, responseHash, user.Password) {
				log.Printf("[NS] MD5 authentication successful for %s", h.email)
				h.loginSuccessful(trid, user)
			} else {
				log.Printf("[NS] MD5 auth failed for '%s': password mismatch!", h.email)
				h.SendError(protocol.ErrAuthenticationFailed, trid)
				h.Close()
			}
		}
	} else if authType == "TWN" {
		if stage == "I" {
			// USR <trid> TWN I <email>
			if len(args) > 3 {
				h.email = strings.TrimSpace(args[3])
			}
			if !strings.Contains(h.email, "@") {
				h.SendError(protocol.ErrInvalidUser, trid)
				h.Close()
				return
			}
			user, _ := h.database.GetUser(h.email)
			if user == nil {
				user, _ = h.database.CreateUser(h.email, "123456", "")
			}

			// Direct login for TWN clients (MSN Messenger / Windows Messenger)
			log.Printf("[NS] Direct TWN authentication granted for %s", h.email)
			h.loginSuccessful(trid, user)

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
				h.loginSuccessful(trid, user)
			} else {
				h.SendError(protocol.ErrAuthenticationFailed, trid)
				h.Close()
			}
		}
	} else {
		h.SendError(protocol.ErrAuthenticationFailed, trid)
		h.Close()
	}
}

func (h *NSClientHandler) loginSuccessful(trid string, user *db.UserRecord) {
	h.authenticated = true
	h.email = user.Email
	if user.FriendlyName != "" {
		h.friendlyName = user.FriendlyName
	} else {
		h.friendlyName = strings.Split(user.Email, "@")[0]
	}

	h.sessionManager.RegisterSession(h.email, h)

	if inSlice([]int{6, 7}, h.dialect) {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName, 1)
	} else if h.dialect >= 8 {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName, 1, 0)
	} else {
		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName)
	}

	if h.IsIM2() {
		h.sendContactList("0", false)
	}
}

func (h *NSClientHandler) sendContactList(trid string, force bool) {
	if h.contactListSent && !force {
		return
	}
	h.contactListSent = true

	contacts, _ := h.database.GetContacts(h.email)

	// Ensure service account is auto-added to contacts
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
	totalGroups := len(groups) + 1 // 0 = Other Contacts

	user, _ := h.database.GetUser(h.email)

	h.syncSerial++

	if h.dialect < 6 {
		// MSNP2 - MSNP5: SYN trid sync_serial
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
		// MSNP6 - MSNP7: SYN trid sync_serial
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
		// MSNP8 - MSNP9+: SYN trid sync_serial total_contacts total_groups
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
			h.SendCmd("LST", c.ContactEmail, fname, c.ListFlags, c.GroupID)
		}
	}
}

func (h *NSClientHandler) handleADD(args []string) {
	if len(args) < 3 {
		return
	}
	trid := args[0]
	listType := strings.ToUpper(args[1])
	contactEmail := strings.TrimSpace(args[2])

	fName := strings.Split(contactEmail, "@")[0]
	groupID := 0
	if len(args) > 4 {
		fName = args[3]
		groupID, _ = strconv.Atoi(args[4])
	} else if len(args) == 4 {
		if listType == "FL" && isNumeric(args[3]) {
			groupID, _ = strconv.Atoi(args[3])
		} else {
			fName = args[3]
		}
	}

	flagMap := map[string]int{
		"FL": protocol.ListFL,
		"AL": protocol.ListAL,
		"BL": protocol.ListBL,
		"RL": protocol.ListRL,
	}
	flag := flagMap[listType]
	if flag == 0 {
		flag = protocol.ListFL
	}

	c, err := h.database.AddOrUpdateContact(h.email, contactEmail, flag, groupID, fName)
	if err != nil || c == nil {
		h.SendError(protocol.ErrDatabaseServerError, trid)
		return
	}

	h.syncSerial++
	friendlyDisp := c.FriendlyName
	if friendlyDisp == "" {
		friendlyDisp = fName
	}

	if listType == "FL" {
		if h.dialect >= 8 {
			h.SendCmd("ADD", trid, listType, h.syncSerial, contactEmail, friendlyDisp, c.GroupID)
		} else {
			h.SendCmd("ADD", trid, listType, h.syncSerial, contactEmail, friendlyDisp)
		}

		serviceEmail := "system@msn.local"
		serviceName := "Служба сообщений MSN"
		if strings.EqualFold(contactEmail, serviceEmail) {
			disp := friendlyDisp
			if disp == "" {
				disp = serviceName
			}
			h.SendILN(trid, protocol.StatusOnline, serviceEmail, disp, "0", "")
		} else {
			if contactSess := h.sessionManager.GetSession(contactEmail); contactSess != nil && contactSess.GetStatus() != protocol.StatusOffline && contactSess.GetStatus() != protocol.StatusHidden {
				h.SendILN(trid, contactSess.GetStatus(), contactEmail, contactSess.GetFriendlyName(), contactSess.GetClientID(), contactSess.GetMSNObj())
			}
			if contactSess := h.sessionManager.GetSession(contactEmail); contactSess != nil {
				contactSess.SendCmd("ADD", "0", "RL", 1, h.email, h.friendlyName)
			}
		}
	} else {
		h.SendCmd("ADD", trid, listType, h.syncSerial, contactEmail, friendlyDisp)
	}
}

func (h *NSClientHandler) handleREM(args []string) {
	if len(args) < 3 {
		return
	}
	trid := args[0]
	listType := strings.ToUpper(args[1])
	contactEmail := strings.TrimSpace(args[2])

	flagMap := map[string]int{
		"FL": protocol.ListFL,
		"AL": protocol.ListAL,
		"BL": protocol.ListBL,
		"RL": protocol.ListRL,
	}
	flag := flagMap[listType]
	if flag == 0 {
		flag = protocol.ListFL
	}

	_ = h.database.RemoveContact(h.email, contactEmail, flag)
	h.syncSerial++
	h.SendCmd("REM", trid, listType, h.syncSerial, contactEmail)

	if listType == "FL" {
		h.SendFLN(contactEmail)
	}
}

func (h *NSClientHandler) handleREA(args []string) {
	if len(args) < 2 {
		return
	}
	trid := args[0]
	targetEmail := h.email
	rawName := ""

	if len(args) >= 3 && strings.Contains(args[1], "@") {
		targetEmail = strings.TrimSpace(args[1])
		rawName = strings.Join(args[2:], " ")
	} else if len(args) == 2 && !strings.Contains(args[1], "@") {
		rawName = args[1]
	} else if len(args) == 2 && strings.Contains(args[1], "@") {
		targetEmail = strings.TrimSpace(args[1])
		rawName = strings.Split(targetEmail, "@")[0]
	} else {
		rawName = strings.Join(args[1:], " ")
	}

	newName, _ := url.QueryUnescape(rawName)
	newName = strings.TrimSpace(newName)
	if newName == "" {
		newName = strings.Split(targetEmail, "@")[0]
	}

	h.syncSerial++

	if strings.EqualFold(targetEmail, h.email) {
		h.friendlyName = newName
		_ = h.database.UpdateFriendlyName(h.email, newName)
		h.SendCmd("REA", trid, h.syncSerial, h.email, h.friendlyName)
		h.sessionManager.BroadcastFriendlyNameChange(h.email, h.friendlyName)
	} else {
		_ = h.database.UpdateContactFriendlyName(h.email, targetEmail, newName)
		h.SendCmd("REA", trid, h.syncSerial, targetEmail, newName)
	}
}

func (h *NSClientHandler) handlePRP(args []string) {
	if len(args) == 0 {
		return
	}
	trid := "0"
	propName := ""
	var valArgs []string

	if isNumeric(args[0]) && len(args) >= 2 {
		trid = args[0]
		propName = strings.ToUpper(args[1])
		valArgs = args[2:]
	} else {
		propName = strings.ToUpper(args[0])
		valArgs = args[1:]
	}

	if propName == "MFN" {
		rawVal := strings.Join(valArgs, " ")
		newName, _ := url.QueryUnescape(rawVal)
		newName = strings.TrimSpace(newName)
		if newName == "" {
			newName = strings.Split(h.email, "@")[0]
		}
		h.friendlyName = newName
		_ = h.database.UpdateFriendlyName(h.email, newName)
		h.syncSerial++
		if trid != "0" {
			h.SendCmd("PRP", trid, "MFN", h.friendlyName)
		} else {
			h.SendCmd("PRP", "MFN", h.friendlyName)
		}
		h.sessionManager.BroadcastFriendlyNameChange(h.email, h.friendlyName)
		return
	}

	propVal := ""
	if len(valArgs) > 0 {
		propVal = valArgs[0]
	}
	_ = h.database.UpdatePhone(h.email, propName, propVal)
	if trid != "0" {
		h.SendCmd("PRP", trid, propName, propVal)
	} else {
		h.SendCmd("PRP", propName, propVal)
	}
}

func (h *NSClientHandler) broadcastUBX() {
	payload := fmt.Sprintf("<Data><PSM>%s</PSM><CurrentMedia></CurrentMedia></Data>", h.customMessage)
	contacts, _ := h.database.GetContacts(h.email)
	for _, c := range contacts {
		if c.ListFlags&protocol.ListFL != 0 {
			if sess := h.sessionManager.GetSession(c.ContactEmail); sess != nil {
				sess.SendPayload("UBX", []byte(payload), h.email)
			}
		}
	}
}

func (h *NSClientHandler) deliverOfflineMessages() {
	pen, _ := h.database.GetUserPenaltyStatus(h.email)
	if pen != nil && pen.IsBanned {
		return
	}

	msgs, err := h.database.GetPendingOfflineMessages(h.email)
	if err != nil || len(msgs) == 0 {
		return
	}

	for _, m := range msgs {
		sUser, _ := h.database.GetUser(m.Sender)
		sName := m.Sender
		if sUser != nil && sUser.FriendlyName != "" {
			sName = sUser.FriendlyName
		}
		payload := fmt.Sprintf(
			"MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nX-MMS-IM-Format: FN=Segoe%%20UI; EF=; CO=0; CS=0; PF=0\r\n\r\n[Offline Message from %s at %s]:\r\n%s\r\n",
			sName, m.Timestamp, m.Message,
		)
		h.SendPayload("MSG", []byte(payload), m.Sender, sName)
	}

	_ = h.database.MarkOfflineMessagesDelivered(h.email)
}

func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

func inSlice(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}
