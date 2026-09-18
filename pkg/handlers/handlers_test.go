package handlers

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"npmsnp/pkg/db"
	"npmsnp/pkg/protocol"
	"npmsnp/pkg/services"
)

func setupTestServer(t *testing.T) (*db.Database, *protocol.AuthManager, *services.SessionManager, *services.SwitchboardManager, net.Listener, int) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test.db")
	database, err := db.NewDatabase(dbPath, "testkey")
	if err != nil {
		t.Fatalf("failed to init db: %v", err)
	}

	_ = database.EnsureServiceAccount("system@msn.local", "Служба сообщений MSN")
	_, _ = database.CreateUser("user1@msn.local", "password123", "Тестовый Пользователь")

	authMgr := protocol.NewAuthManager("testkey")
	sessionMgr := services.NewSessionManager(database)
	sbMgr := services.NewSwitchboardManager(authMgr)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			h := NewNSClientHandler(conn, database, authMgr, sessionMgr, sbMgr, "127.0.0.1", port, 1864, 1865)
			go h.Run()
		}
	}()

	return database, authMgr, sessionMgr, sbMgr, ln, port
}

func TestTrillianHandshakeAndQRY(t *testing.T) {
	database, _, _, _, ln, port := setupTestServer(t)
	defer database.Close()
	defer ln.Close()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	readLine := func() string {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("failed to read line: %v", err)
		}
		return strings.TrimRight(line, "\r\n")
	}
	writeLine := func(s string) {
		_, _ = conn.Write([]byte(s + "\r\n"))
	}

	// 1. Trillian sends VER MSNP8 CVR0 (MUST negotiate MSNP8, NOT force MSNP9!)
	writeLine("VER 1 MSNP8 CVR0")
	verResp := readLine()
	if !strings.HasPrefix(verResp, "VER 1 MSNP8") {
		t.Fatalf("expected VER 1 MSNP8, got: %s", verResp)
	}
	if !strings.Contains(verResp, "CVR0") {
		t.Fatalf("expected CVR0 preserved in VER response, got: %s", verResp)
	}

	// 2. CVR
	writeLine("CVR 2 0x0409 winnt 5.1 i386 TRILLIAN 0.74 MSMSGS user1@msn.local")
	cvrResp := readLine()
	if !strings.HasPrefix(cvrResp, "CVR 2") {
		t.Fatalf("expected CVR 2, got: %s", cvrResp)
	}

	// 3. USR MD5 I
	writeLine("USR 3 MD5 I user1@msn.local")
	usrChallenge := readLine()
	if !strings.HasPrefix(usrChallenge, "USR 3 MD5 S ") {
		t.Fatalf("expected USR 3 MD5 S, got: %s", usrChallenge)
	}
	parts := strings.Split(usrChallenge, " ")
	challenge := parts[4]

	// 4. USR MD5 S
	hasher := md5.New()
	hasher.Write([]byte(challenge + "password123"))
	respHash := hex.EncodeToString(hasher.Sum(nil))

	writeLine(fmt.Sprintf("USR 4 MD5 S %s", respHash))
	usrOk := readLine()
	if !strings.HasPrefix(usrOk, "USR 4 OK user1@msn.local") {
		t.Fatalf("expected USR 4 OK, got: %s", usrOk)
	}

	// 5. SYN - verify service account is auto-added
	writeLine("SYN 5 0")
	synResp := readLine()
	if !strings.HasPrefix(synResp, "SYN 5 ") {
		t.Fatalf("expected SYN 5, got: %s", synResp)
	}

	foundBot := false
	for i := 0; i < 20; i++ {
		line := readLine()
		if strings.Contains(line, "system@msn.local") {
			foundBot = true
			break
		}
	}
	if !foundBot {
		t.Fatalf("expected service account system@msn.local in contact list after SYN")
	}

	// 6. CHG NLN - verify initial presence includes service account ILN
	writeLine("CHG 6 NLN 0")
	chgResp := readLine()
	if !strings.HasPrefix(chgResp, "CHG 6 NLN") {
		t.Fatalf("expected CHG 6 NLN, got: %s", chgResp)
	}

	foundBotILN := false
	for i := 0; i < 10; i++ {
		line := readLine()
		if strings.HasPrefix(line, "ILN") && strings.Contains(line, "system@msn.local") {
			foundBotILN = true
			break
		}
	}
	if !foundBotILN {
		t.Fatalf("expected ILN for service account system@msn.local after CHG")
	}

	// 7. QRY with 32-byte payload (Trillian challenge)
	qryPayload := "0123456789abcdef0123456789abcdef" // 32 bytes
	_, _ = conn.Write([]byte(fmt.Sprintf("QRY 7 PROD0038W!61ZTF9 32\r\n%s", qryPayload)))

	qryResp := readLine()
	if qryResp != "QRY 7" {
		t.Fatalf("expected 'QRY 7', got: %s", qryResp)
	}

	// 8. Verify connection stays alive and doesn't close or crash
	writeLine("PNG")
	pngResp := readLine()
	if pngResp != "QNG 60" {
		t.Fatalf("expected 'QNG 60', got: %s", pngResp)
	}
}

func TestSwitchboardServiceBot(t *testing.T) {
	database, authMgr, sessionMgr, sbMgr, lnNS, _ := setupTestServer(t)
	defer database.Close()
	defer lnNS.Close()

	// Create a SB room
	_, cookie := sbMgr.AllocateSession("user1@msn.local")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen SB: %v", err)
	}
	defer ln.Close()
	sbPort := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			h := NewSBClientHandler(conn, database, authMgr, sessionMgr, sbMgr, "127.0.0.1", sbPort, 1865)
			go h.Run()
		}
	}()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sbPort))
	if err != nil {
		t.Fatalf("failed to dial SB: %v", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)
	readLine := func() string {
		line, _ := reader.ReadString('\n')
		return strings.TrimRight(line, "\r\n")
	}
	writeLine := func(s string) {
		_, _ = conn.Write([]byte(s + "\r\n"))
	}

	// USR with cookie
	writeLine(fmt.Sprintf("USR 1 user1@msn.local %s", cookie))
	usrResp := readLine()
	if !strings.HasPrefix(usrResp, "USR 1 OK") {
		t.Fatalf("expected USR 1 OK, got: %s", usrResp)
	}

	// CAL to service bot: CAL 2 system@msn.local
	writeLine("CAL 2 system@msn.local")
	calResp := readLine()
	if !strings.HasPrefix(calResp, "CAL 2 RINGING") {
		t.Fatalf("expected CAL 2 RINGING, got: %s", calResp)
	}

	joiResp := readLine()
	if !strings.HasPrefix(joiResp, "JOI system@msn.local") {
		t.Fatalf("expected JOI for service bot, got: %s", joiResp)
	}

	// Send message to service bot in room
	msgPayload := "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\nПривет бот!"
	_, _ = conn.Write([]byte(fmt.Sprintf("MSG 3 U %d\r\n%s", len(msgPayload), msgPayload)))

	// Bot should reply with service notice
	botMsgHeader := readLine()
	if !strings.HasPrefix(botMsgHeader, "MSG system@msn.local") {
		t.Fatalf("expected MSG reply from system@msn.local, got: %s", botMsgHeader)
	}
}

func TestRetroDashboardRendering(t *testing.T) {
	database, authMgr, sessionMgr, sbMgr, lnNS, _ := setupTestServer(t)
	defer database.Close()
	defer lnNS.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	hPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	srv := services.NewHTTPServer("127.0.0.1", hPort, "127.0.0.1", database, authMgr, sessionMgr, sbMgr, true, "admin123")
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start srv: %v", err)
	}
	defer srv.Stop()

	time.Sleep(50 * time.Millisecond)

	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", hPort))
	if err != nil {
		t.Fatalf("GET / failed: %v", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	html := string(bodyBytes)

	// Check authentic Windows 2000/XP styles & elements
	if !strings.Contains(html, "SysTabControl32") && !strings.Contains(html, "tab-btn") {
		t.Fatalf("dashboard missing classic SysTabControl32 tab classes")
	}
	if !strings.Contains(html, "Панель управления") {
		t.Fatalf("dashboard missing 'Панель управления'")
	}
	if !strings.Contains(html, "Управление учетными записями") {
		t.Fatalf("dashboard missing tab 'Управление учетными записями'")
	}
	if !strings.Contains(html, "Оповещения") {
		t.Fatalf("dashboard missing tab 'Оповещения'")
	}
	if !strings.Contains(html, "Состояние сервера") {
		t.Fatalf("dashboard missing tab 'Состояние сервера'")
	}
	if !strings.Contains(html, "Служба сообщений MSN") {
		t.Fatalf("dashboard missing 'Служба сообщений MSN'")
	}
}

func TestSwitchboardOneOnOneNoConference(t *testing.T) {
	database, authMgr, sessionMgr, sbMgr, lnNS, _ := setupTestServer(t)
	defer database.Close()
	defer lnNS.Close()

	// Register users in DB
	_, _ = database.CreateUser("alice@msn.local", "pass", "Alice")
	_, _ = database.CreateUser("bob@msn.local", "pass", "Bob")

	sessionID, callerCookie := sbMgr.AllocateSession("alice@msn.local")
	calleeCookie := sbMgr.PrepareInvite(sessionID, "bob@msn.local")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen SB: %v", err)
	}
	defer ln.Close()
	sbPort := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			h := NewSBClientHandler(conn, database, authMgr, sessionMgr, sbMgr, "127.0.0.1", sbPort, 1865)
			go h.Run()
		}
	}()

	// 1. Caller (Alice) connects
	callerConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sbPort))
	if err != nil {
		t.Fatalf("failed to dial SB caller: %v", err)
	}
	defer callerConn.Close()

	callerReader := bufio.NewReader(callerConn)
	callerReadLine := func() string {
		line, _ := callerReader.ReadString('\n')
		return strings.TrimRight(line, "\r\n")
	}

	_, _ = callerConn.Write([]byte(fmt.Sprintf("USR 1 alice@msn.local %s\r\n", callerCookie)))
	usrResp := callerReadLine()
	if !strings.HasPrefix(usrResp, "USR 1 OK alice@msn.local") {
		t.Fatalf("expected USR 1 OK for alice, got: %s", usrResp)
	}

	// 2. Callee (Bob) connects and answers with ANS
	calleeConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sbPort))
	if err != nil {
		t.Fatalf("failed to dial SB callee: %v", err)
	}
	defer calleeConn.Close()

	calleeReader := bufio.NewReader(calleeConn)
	calleeReadLine := func() string {
		line, _ := calleeReader.ReadString('\n')
		return strings.TrimRight(line, "\r\n")
	}

	_, _ = calleeConn.Write([]byte(fmt.Sprintf("ANS 10 bob@msn.local %s %d\r\n", calleeCookie, sessionID)))
	ansResp := calleeReadLine()
	if ansResp != "ANS 10 OK" {
		t.Fatalf("expected 'ANS 10 OK', got: %s", ansResp)
	}

	// Callee must receive EXACTLY ONE IRO for Alice: IRO 10 1 1 alice@msn.local Alice
	// and NEVER an IRO for Bob or total > 1
	iroResp := calleeReadLine()
	if !strings.HasPrefix(iroResp, "IRO 10 1 1 alice@msn.local") {
		t.Fatalf("expected 'IRO 10 1 1 alice@msn.local ...' (total 1, private chat), got: %s", iroResp)
	}

	// Caller (Alice) must receive JOI for Bob
	joiResp := callerReadLine()
	if !strings.HasPrefix(joiResp, "JOI bob@msn.local") {
		t.Fatalf("expected 'JOI bob@msn.local ...', got: %s", joiResp)
	}
}

func TestAdminAPILoginAndCheck(t *testing.T) {
	database, authMgr, sessionMgr, sbMgr, lnNS, _ := setupTestServer(t)
	defer database.Close()
	defer lnNS.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	hPort := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	srv := services.NewHTTPServer("127.0.0.1", hPort, "127.0.0.1", database, authMgr, sessionMgr, sbMgr, true, "admin123")
	if err := srv.Start(); err != nil {
		t.Fatalf("failed to start srv: %v", err)
	}
	defer srv.Stop()

	baseURL := fmt.Sprintf("http://127.0.0.1:%d", hPort)

	// 1. Login with wrong password
	badBody := strings.NewReader(`{"password":"wrong"}`)
	resp, err := http.Post(baseURL+"/api/admin/login", "application/json", badBody)
	if err != nil {
		t.Fatalf("POST /api/admin/login failed: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong password, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 2. Login with correct password
	goodBody := strings.NewReader(`{"password":"admin123"}`)
	resp, err = http.Post(baseURL+"/api/admin/login", "application/json", goodBody)
	if err != nil {
		t.Fatalf("POST /api/admin/login failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for good password, got %d", resp.StatusCode)
	}
	var loginData map[string]interface{}
	_ = json.NewDecoder(resp.Body).Decode(&loginData)
	resp.Body.Close()

	if loginData["success"] != true {
		t.Fatalf("expected success true, got %v", loginData)
	}
	token, ok := loginData["token"].(string)
	if !ok || token == "" {
		t.Fatalf("expected non-empty token, got %v", loginData["token"])
	}

	// 3. Check admin status with token
	req, _ := http.NewRequest("GET", baseURL+"/api/admin/check", nil)
	req.Header.Set("X-Admin-Token", token)
	checkResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/admin/check failed: %v", err)
	}
	var checkData map[string]interface{}
	_ = json.NewDecoder(checkResp.Body).Decode(&checkData)
	checkResp.Body.Close()

	if checkData["authenticated"] != true {
		t.Fatalf("expected authenticated true, got %v", checkData)
	}
}


