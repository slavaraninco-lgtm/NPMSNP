package handlers

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	"npmsnp/pkg/config"
	"npmsnp/pkg/db"
	"npmsnp/pkg/protocol"
	"npmsnp/pkg/services"
)

type SBClientHandler struct {
	conn               net.Conn
	reader             *bufio.Reader
	writerMu           sync.Mutex
	database           *db.Database
	authManager        *protocol.AuthManager
	sessionManager     *services.SessionManager
	switchboardManager *services.SwitchboardManager
	externalHost       string
	sbPort             int
	httpPort           int

	authenticated bool
	email         string
	friendlyName  string
	sessionID     int
	room          *services.SwitchboardRoom
	closed        bool
	closeOnce     sync.Once
}

func NewSBClientHandler(conn net.Conn, database *db.Database, authManager *protocol.AuthManager,
	sessionManager *services.SessionManager, switchboardManager *services.SwitchboardManager,
	externalHost string, sbPort, httpPort int) *SBClientHandler {

	return &SBClientHandler{
		conn:               conn,
		reader:             bufio.NewReader(conn),
		database:           database,
		authManager:        authManager,
		sessionManager:     sessionManager,
		switchboardManager: switchboardManager,
		externalHost:       externalHost,
		sbPort:             sbPort,
		httpPort:           httpPort,
	}
}

func (h *SBClientHandler) GetEmail() string {
	return h.email
}

func (h *SBClientHandler) GetFriendlyName() string {
	return h.friendlyName
}

func (h *SBClientHandler) IsANSI() bool {
	if h.email != "" {
		nsSess := h.sessionManager.GetSession(h.email)
		if nsSess != nil {
			return nsSess.IsANSI()
		}
	}
	return false
}

func (h *SBClientHandler) GetEffectiveHost() string {
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

func (h *SBClientHandler) SendCmd(cmd string, args ...interface{}) {
	raw := protocol.FormatCommand(cmd, h.IsANSI(), args...)
	h.writerMu.Lock()
	defer h.writerMu.Unlock()
	if !h.closed && h.conn != nil {
		_, _ = h.conn.Write([]byte(raw))
	}
}

func (h *SBClientHandler) SendPayload(cmd string, payload []byte, args ...interface{}) {
	raw := protocol.FormatPayloadCommand(cmd, payload, h.IsANSI(), args...)
	h.writerMu.Lock()
	defer h.writerMu.Unlock()
	if !h.closed && h.conn != nil {
		_, _ = h.conn.Write(raw)
	}
}

func (h *SBClientHandler) SendError(code int, trid string) {
	h.SendCmd(fmt.Sprintf("%d", code), trid)
}

func (h *SBClientHandler) Close() {
	h.closeOnce.Do(func() {
		h.closed = true
		if h.room != nil && h.email != "" {
			h.switchboardManager.LeaveRoom(h.sessionID, h.email)
		}
		if h.conn != nil {
			_ = h.conn.Close()
		}
	})
}

// SBParticipant interface implementation

func (h *SBClientHandler) SendIRO(trid string, index, total int, email, friendlyName string) {
	if friendlyName == "" {
		friendlyName = email
	}
	h.SendCmd("IRO", trid, index, total, email, friendlyName)
}

func (h *SBClientHandler) SendJOI(email, friendlyName string) {
	if friendlyName == "" {
		friendlyName = email
	}
	h.SendCmd("JOI", email, friendlyName)
}

func (h *SBClientHandler) SendBYE(email string) {
	h.SendCmd("BYE", email)
}

func (h *SBClientHandler) SendMsgRelay(senderEmail, senderFriendlyName string, payload []byte) {
	if senderFriendlyName == "" {
		senderFriendlyName = senderEmail
	}
	h.SendPayload("MSG", payload, senderEmail, senderFriendlyName)
}

func (h *SBClientHandler) SendNotRelay(senderEmail string, payload []byte) {
	h.SendPayload("NOT", payload, senderEmail)
}

func (h *SBClientHandler) SendServiceNotice(text string) {
	body := fmt.Sprintf("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nX-MMS-IM-Format: FN=Segoe%%20UI; EF=; CO=0; CS=0; PF=0\r\n\r\n[Служба сообщений MSN]:\r\n%s\r\n", text)
	h.SendPayload("MSG", []byte(body), "system@msn.local", "Служба сообщений MSN")
}

// Main Connection Loop

func (h *SBClientHandler) Run() {
	defer h.Close()

	for !h.closed {
		packet, err := protocol.ReadPacket(h.reader)
		if err != nil {
			if err != io.EOF && !h.closed {
				log.Printf("[SB] Read error from %s: %v", h.conn.RemoteAddr(), err)
			}
			return
		}

		if packet.Command == "" {
			continue
		}

		h.handleCommand(packet)
	}
}

func (h *SBClientHandler) handleCommand(pkt *protocol.Packet) {
	args := pkt.Args

	switch pkt.Command {
	case "VER":
		// Handshake VER <trid> <dialects...>
		trid := "1"
		if len(args) > 0 {
			trid = args[0]
		}
		var matched string
		for _, d := range args[1:] {
			dUpper := strings.ToUpper(d)
			if _, ok := protocol.SupportedDialects[dUpper]; ok {
				matched = dUpper
				break
			}
		}
		if matched == "" {
			matched = "MSNP9"
		}
		h.SendCmd("VER", trid, matched, "CVR0")

	case "CVR":
		trid := "1"
		if len(args) > 0 {
			trid = args[0]
		}
		host := h.GetEffectiveHost()
		url := fmt.Sprintf("http://%s:%d/", host, h.httpPort)
		h.SendCmd("CVR", trid, "6.0.0602", "6.0.0602", "6.0.0602", url, url)

	case "USR":
		// Caller authentication: USR <trid> <email> <cookie>
		if len(args) < 3 {
			return
		}
		trid := args[0]
		email := args[1]
		cookie := args[2]

		sessID, _, valid := h.authManager.VerifyAndConsumeSBCookie(cookie, email)
		if !valid {
			h.SendError(protocol.ErrAuthenticationFailed, trid)
			h.Close()
			return
		}

		h.authenticated = true
		h.email = email
		h.sessionID = sessID

		u, _ := h.database.GetUser(email)
		if u != nil && u.FriendlyName != "" {
			h.friendlyName = u.FriendlyName
		} else {
			parts := strings.Split(email, "@")
			h.friendlyName = parts[0]
		}

		_, room := h.switchboardManager.JoinRoom(sessID, h)
		h.room = room

		h.SendCmd("USR", trid, "OK", h.email, h.friendlyName)

	case "ANS":
		// Callee answer: ANS <trid> <email> <cookie> <session_id>
		if len(args) < 4 {
			return
		}
		trid := args[0]
		email := args[1]
		cookie := args[2]

		sessID, _, valid := h.authManager.VerifyAndConsumeSBCookie(cookie, email)
		if !valid {
			h.SendError(protocol.ErrAuthenticationFailed, trid)
			h.Close()
			return
		}

		h.authenticated = true
		h.email = email
		h.sessionID = sessID

		u, _ := h.database.GetUser(email)
		if u != nil && u.FriendlyName != "" {
			h.friendlyName = u.FriendlyName
		} else {
			parts := strings.Split(email, "@")
			h.friendlyName = parts[0]
		}

		existing, room := h.switchboardManager.JoinRoom(sessID, h)
		if room == nil {
			h.SendError(protocol.ErrSwitchboardFailed, trid)
			h.Close()
			return
		}
		h.room = room
		h.SendCmd("ANS", trid, "OK")

		// In MSNP, IRO describes existing participants ALREADY in the room prior to callee joining.
		// Sending callee themselves or total > 1 causes clients to convert 1-on-1 chats into a conference.
		serviceEmail := "system@msn.local"
		serviceName := "Служба сообщений MSN"
		if (h.room.HasServiceBot || strings.EqualFold(h.room.Initiator, serviceEmail)) && len(existing) == 0 {
			h.room.HasServiceBot = true
			h.SendIRO(trid, 1, 1, serviceEmail, serviceName)
		} else {
			totalCount := len(existing)
			for idx, p := range existing {
				h.SendIRO(trid, idx+1, totalCount, p.GetEmail(), p.GetFriendlyName())
			}
		}

		// Notify existing participants that this callee joined
		for _, p := range existing {
			p.SendJOI(h.email, h.friendlyName)
		}

		// Deliver any queued service messages
		pending := h.switchboardManager.PopPendingServiceMessages(h.email)
		for _, msg := range pending {
			h.SendServiceNotice(msg)
		}

	case "CAL":
		// CAL <trid> <callee_email>
		if len(args) < 2 || h.sessionID == 0 {
			return
		}
		trid := args[0]
		calleeEmail := strings.TrimSpace(args[1])

		if !strings.Contains(calleeEmail, "@") {
			h.SendError(protocol.ErrInvalidUser, trid)
			return
		}

		// Caller ban check
		callerPen, _ := h.database.GetUserPenaltyStatus(h.email)
		if callerPen != nil && callerPen.IsBanned {
			reason := ""
			if callerPen.BanReason != "" {
				reason = fmt.Sprintf(" Причина: %s.", callerPen.BanReason)
			}
			msg := fmt.Sprintf("Вы не можете совершать вызовы, так как ваша учетная запись заблокирована (бан).%s До окончания блокировки осталось: %s.", reason, callerPen.BanRemaining)
			h.switchboardManager.DeliverServicePM(h.email, msg, h.sessionManager, h.GetEffectiveHost(), h.sbPort)
			h.SendError(protocol.ErrNotAllowed, trid)
			return
		}

		// Callee ban check
		calleePen, _ := h.database.GetUserPenaltyStatus(calleeEmail)
		if calleePen != nil && calleePen.IsBanned {
			msg := fmt.Sprintf("Пользователь %s заблокирован администрацией и не может принимать вызовы.", calleeEmail)
			h.switchboardManager.DeliverServicePM(h.email, msg, h.sessionManager, h.GetEffectiveHost(), h.sbPort)
			h.SendError(protocol.ErrPrincipalNotOnline, trid)
			return
		}

		serviceEmail := "system@msn.local"
		serviceName := "Служба сообщений MSN"

		if strings.EqualFold(calleeEmail, serviceEmail) {
			if h.room != nil && len(h.room.Participants) > 1 {
				h.SendError(protocol.ErrNotAllowed, trid)
				return
			}
			h.SendCmd("CAL", trid, "RINGING", h.sessionID)
			if h.room != nil {
				h.room.HasServiceBot = true
			}
			h.SendJOI(serviceEmail, serviceName)
			pending := h.switchboardManager.PopPendingServiceMessages(h.email)
			for _, pmsg := range pending {
				h.SendServiceNotice(pmsg)
			}
			return
		}

		cookie := h.switchboardManager.PrepareInvite(h.sessionID, calleeEmail)
		if cookie == "" {
			h.SendError(protocol.ErrSwitchboardFailed, trid)
			return
		}

		if !h.sessionManager.IsOnline(calleeEmail) {
			h.SendError(protocol.ErrPrincipalNotOnline, trid)
			return
		}

		h.SendCmd("CAL", trid, "RINGING", h.sessionID)

		ringSent := h.sessionManager.SendSwitchboardRing(calleeEmail, h.sessionID, h.GetEffectiveHost(), h.sbPort,
			cookie, h.email, h.friendlyName)
		if !ringSent {
			h.SendError(protocol.ErrPrincipalNotOnline, trid)
		}

	case "MSG":
		// MSG <trid> <ack_type> <len>\r\n<payload>
		if len(args) < 2 || len(pkt.Payload) == 0 || h.sessionID == 0 {
			return
		}
		trid := args[0]
		ackType := strings.ToUpper(args[1])

		if ackType == "A" || ackType == "D" {
			h.SendCmd("ACK", trid)
		}

		// Sender ban check
		pen, _ := h.database.GetUserPenaltyStatus(h.email)
		if pen != nil && pen.IsBanned {
			reason := ""
			if pen.BanReason != "" {
				reason = fmt.Sprintf(" Причина: %s.", pen.BanReason)
			}
			msg := fmt.Sprintf("Ваша учетная запись заблокирована (бан).%s До окончания блокировки осталось: %s.", reason, pen.BanRemaining)
			h.switchboardManager.DeliverServicePM(h.email, msg, h.sessionManager, h.GetEffectiveHost(), h.sbPort)
			return
		}

		if pen != nil && pen.IsMuted {
			reason := ""
			if pen.MuteReason != "" {
				reason = fmt.Sprintf(" Причина: %s.", pen.MuteReason)
			}
			msg := fmt.Sprintf("Вам временно ограничен доступ к отправке сообщений (мут).%s До окончания мута осталось: %s.", reason, pen.MuteRemaining)
			h.switchboardManager.DeliverServicePM(h.email, msg, h.sessionManager, h.GetEffectiveHost(), h.sbPort)
			return
		}

		// Service bot alone in room
		if h.room != nil && h.room.HasServiceBot && len(h.room.Participants) == 1 {
			h.SendServiceNotice("Здравствуйте! Это автоматическая служба сообщений MSN. Данная учетная запись используется для системных оповещений.")
			return
		}

		// Offline message saving if caller alone in room
		if h.room != nil && len(h.room.Participants) == 1 {
			for target := range h.room.PendingInvites {
				tPen, _ := h.database.GetUserPenaltyStatus(target)
				if tPen != nil && tPen.IsBanned {
					h.switchboardManager.DeliverServicePM(h.email, fmt.Sprintf("Сообщение не доставлено: пользователь %s заблокирован.", target),
						h.sessionManager, h.GetEffectiveHost(), h.sbPort)
					return
				}

				text := string(pkt.Payload)
				bodyText := text
				if strings.Contains(text, "\r\n\r\n") {
					parts := strings.SplitN(text, "\r\n\r\n", 2)
					bodyText = parts[1]
				}
				_ = h.database.SaveOfflineMessage(h.email, target, strings.TrimSpace(bodyText))
				break
			}
		}

		// Broadcast message to other room participants
		blocked := h.switchboardManager.BroadcastMessage(h.sessionID, h.email, h.friendlyName, pkt.Payload, h.database)
		for _, bUser := range blocked {
			h.switchboardManager.DeliverServicePM(h.email, fmt.Sprintf("Сообщение не доставлено: пользователь %s заблокирован.", bUser),
				h.sessionManager, h.GetEffectiveHost(), h.sbPort)
		}

	case "NOT":
		if len(pkt.Payload) == 0 || h.sessionID == 0 {
			return
		}
		pen, _ := h.database.GetUserPenaltyStatus(h.email)
		if pen != nil && (pen.IsBanned || pen.IsMuted) {
			return
		}
		h.switchboardManager.BroadcastTyping(h.sessionID, h.email, pkt.Payload)

	case "OUT":
		h.Close()

	case "CHL", "PNG", "QNG", "QRY", "VAS", "SDC", "SDG", "PUT":
		return
	}
}
