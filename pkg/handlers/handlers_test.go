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

func TestTrillianProSingleArgQRYAndSB(t *testing.T) {
	database, authMgr, sessionMgr, sbMgr, ln, port := setupTestServer(t)
	defer database.Close()
	defer ln.Close()

	// Setup SB listener
	sbLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on SB: %v", err)
	}
	defer sbLn.Close()
	sbPort := sbLn.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := sbLn.Accept()
			if err != nil {
				return
			}
			h := NewSBClientHandler(conn, database, authMgr, sessionMgr, sbMgr, "127.0.0.1", sbPort, 1865)
			go h.Run()
		}
	}()

	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to dial NS: %v", err)
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

	writeLine("VER 1 MSNP8 CVR0")
	verResp := readLine()
	if !strings.HasPrefix(verResp, "VER 1 MSNP8") {
		t.Fatalf("unexpected VER resp: %s", verResp)
	}

	writeLine("CVR 2 0x0409 winnt 5.1 i386 TRILLIAN 3.1.0.121 msmsgs user1@msn.local")
	cvrResp := readLine()
	if !strings.Contains(cvrResp, "3.1.0.121") {
		t.Fatalf("expected clientVer 3.1.0.121 in CVR resp, got: %s", cvrResp)
	}

	// Login
	writeLine("USR 3 MD5 I user1@msn.local")
	challenge := strings.Split(readLine(), " ")[4]
	hasher := md5.New()
	hasher.Write([]byte(challenge + "password123"))
	writeLine(fmt.Sprintf("USR 4 MD5 S %s", hex.EncodeToString(hasher.Sum(nil))))
	_ = readLine() // USR 4 OK

	// Trillian Pro sends QRY 1\r\n directly without payload
	writeLine("QRY 1")
	qryResp := readLine()
	if qryResp != "QRY 1" {
		t.Fatalf("expected QRY 1 response, got: %s", qryResp)
	}

	// Immediately send CHG command - if QRY 1 incorrectly consumed 1 byte, this would fail!
	writeLine("CHG 5 NLN 0")
	chgResp := readLine()
	if !strings.HasPrefix(chgResp, "CHG 5 NLN") {
		t.Fatalf("expected CHG 5 NLN, got: %s (stream desync?)", chgResp)
	}

	// Switchboard test for Trillian Pro
	sessID, cookie := sbMgr.AllocateSession("user1@msn.local")
	_ = sessID

	sbConn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sbPort))
	if err != nil {
		t.Fatalf("failed to dial SB: %v", err)
	}
	defer sbConn.Close()

	sbReader := bufio.NewReader(sbConn)
	sbReadLine := func() string {
		line, err := sbReader.ReadString('\n')
		if err != nil {
			t.Fatalf("failed to read line from SB: %v", err)
		}
		return strings.TrimRight(line, "\r\n")
	}
	sbWriteLine := func(s string) {
		_, _ = sbConn.Write([]byte(s + "\r\n"))
	}

	// Trillian Pro sends VER and CVR to SB as well
	sbWriteLine("VER 1 MSNP8 CVR0")
	sbVerResp := sbReadLine()
	if !strings.HasPrefix(sbVerResp, "VER 1 MSNP8") {
		t.Fatalf("expected SB VER 1 MSNP8, got: %s", sbVerResp)
	}

	sbWriteLine("CVR 2 0x0409 winnt 5.1 i386 TRILLIAN 3.1.0.121 msmsgs user1@msn.local")
	sbCvrResp := sbReadLine()
	if !strings.HasPrefix(sbCvrResp, "CVR 2") {
		t.Fatalf("expected SB CVR 2, got: %s", sbCvrResp)
	}

	// Trillian Pro sends QRY 3 on SB
	sbWriteLine("QRY 3")
	sbQryResp := sbReadLine()
	if sbQryResp != "QRY 3" {
		t.Fatalf("expected SB QRY 3, got: %s", sbQryResp)
	}

	// USR on SB
	sbWriteLine(fmt.Sprintf("USR 4 user1@msn.local %s", cookie))
	sbUsrResp := sbReadLine()
	if !strings.HasPrefix(sbUsrResp, "USR 4 OK user1@msn.local") {
		t.Fatalf("expected SB USR OK, got: %s", sbUsrResp)
	}
}

func TestTrillianAstraHandshakeAndADL(t *testing.T) {
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

	// 1. Handshake
	writeLine("VER 1 MSNP11 MSNP10 CVR0")
	verResp := readLine()
	if !strings.HasPrefix(verResp, "VER 1 MSNP11") {
		t.Fatalf("expected VER 1 MSNP11, got: %s", verResp)
	}

	writeLine("CVR 2 0x0409 winnt 6.1 i386 astra 4.0.0.117 trillian astra@msn.local")
	cvrResp := readLine()
	if !strings.Contains(cvrResp, "4.0.0.117") {
		t.Fatalf("expected 4.0.0.117 in CVR response, got: %s", cvrResp)
	}

	// 2. Direct login or MD5 login
	writeLine("USR 3 TWN I astra@msn.local")
	usrResp := readLine()
	if !strings.HasPrefix(usrResp, "USR 3 OK astra@msn.local") {
		t.Fatalf("expected USR 3 OK, got: %s", usrResp)
	}

	// 3. ADL XML command
	adlXML := `<ml l="1"><d n="msn.local"><c n="buddy1" l="3" t="1"/><c n="buddy2" l="1" t="1"/></d></ml>`
	_, _ = conn.Write([]byte(fmt.Sprintf("ADL 4 %d\r\n%s", len(adlXML), adlXML)))

	adlResp := readLine()
	if adlResp != "ADL 4 OK" {
		t.Fatalf("expected ADL 4 OK, got: %s", adlResp)
	}

	// Verify contacts added in DB
	contacts, err := database.GetContacts("astra@msn.local")
	if err != nil {
		t.Fatalf("failed to get contacts: %v", err)
	}
	foundBuddy1 := false
	foundBuddy2 := false
	for _, c := range contacts {
		if c.ContactEmail == "buddy1@msn.local" {
			foundBuddy1 = true
		}
		if c.ContactEmail == "buddy2@msn.local" {
			foundBuddy2 = true
		}
	}
	if !foundBuddy1 || !foundBuddy2 {
		t.Fatalf("expected buddy1 and buddy2 in DB contacts, got: %v", contacts)
	}

	// 4. FQY command
	writeLine("FQY 5 0")
	fqyResp := readLine()
	if fqyResp != "FQY 5 0" {
		t.Fatalf("expected FQY 5 0, got: %s", fqyResp)
	}

	// 5. RML XML command
	rmlXML := `<ml><d n="msn.local"><c n="buddy1" l="1"/></d></ml>`
	_, _ = conn.Write([]byte(fmt.Sprintf("RML 6 %d\r\n%s", len(rmlXML), rmlXML)))
	foundRMLOK := false
	for i := 0; i < 5; i++ {
		line := readLine()
		if line == "RML 6 OK" {
			foundRMLOK = true
			break
		}
	}
	if !foundRMLOK {
		t.Fatalf("expected RML 6 OK")
	}
}

func TestMSNMessenger75(t *testing.T) {
	database, authMgr, sessionMgr, sbMgr, ln, port := setupTestServer(t)
	defer database.Close()
	defer ln.Close()

	// Test HTTP passport login endpoint with Authorization header
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		httpPort := httpLn.Addr().(*net.TCPAddr).Port
		_ = httpLn.Close()
		httpSrv := services.NewHTTPServer("127.0.0.1", httpPort, "127.0.0.1", database, authMgr, sessionMgr, sbMgr, true, "admin123")
		_ = httpSrv.Start()
		defer httpSrv.Stop()

		req, _ := http.NewRequest("GET", fmt.Sprintf("http://127.0.0.1:%d/login.srf", httpPort), nil)
		req.Header.Set("Authorization", "Passport1.4 OrgVerb=GET,OrgURL=http%3A%2F%2Fmessenger%2Emsn%2Ecom,sign-in=msn75%40msn.local,pwd=123456,lc=1033")
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			authInfo := resp.Header.Get("Authentication-Info")
			if !strings.Contains(authInfo, "da-status=success") || !strings.Contains(authInfo, "tkt=") {
				t.Fatalf("expected success ticket in Authentication-Info, got: %s", authInfo)
			}
		}
	}

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

	// Handshake
	writeLine("VER 1 MSNP11 MSNP10 CVR0")
	verResp := readLine()
	if !strings.HasPrefix(verResp, "VER 1 MSNP11") {
		t.Fatalf("expected VER 1 MSNP11, got: %s", verResp)
	}

	// CVR with MSN 7.5 version
	writeLine("CVR 2 0x0409 winnt 5.1 i386 MSNMSGR 7.5.0324 msmsgs msn75@msn.local")
	cvrResp := readLine()
	if !strings.Contains(cvrResp, "7.5.0324") {
		t.Fatalf("expected 7.5.0324 in CVR response, got: %s", cvrResp)
	}

	// Login: MSN 7.5 sends USR TWN I and receives TWN S challenge
	writeLine("USR 3 TWN I msn75@msn.local")
	usrResp := readLine()
	if !strings.HasPrefix(usrResp, "USR 3 TWN S ") {
		t.Fatalf("expected USR 3 TWN S challenge, got: %s", usrResp)
	}

	// Client sends ticket received from Passport HTTP endpoint
	writeLine("USR 4 TWN S t=test_ticket_msn75")
	usrResp2 := readLine()
	if !strings.HasPrefix(usrResp2, "USR 4 OK msn75@msn.local") {
		t.Fatalf("expected USR 4 OK, got: %s", usrResp2)
	}

	// SYN
	writeLine("SYN 5 0 0")
	synResp := readLine()
	if !strings.HasPrefix(synResp, "SYN 5 ") {
		t.Fatalf("expected SYN 5, got: %s", synResp)
	}
	// Drain rest of SYN lines (GTC, BLP, LSG, LST)
	for i := 0; i < 10; i++ {
		line := readLine()
		if strings.HasPrefix(line, "LST") {
			break
		}
	}

	// Status change
	writeLine("CHG 5 NLN 0")
	chgResp := readLine()
	if !strings.HasPrefix(chgResp, "CHG 5 NLN") {
		t.Fatalf("expected CHG 5 NLN, got: %s", chgResp)
	}

	// UBX personal status message
	ubxPayload := "<Data><PSM>Listening to music</PSM><CurrentMedia></CurrentMedia></Data>"
	_, _ = conn.Write([]byte(fmt.Sprintf("UBX 6 %d\r\n%s", len(ubxPayload), ubxPayload)))
	foundUBX := false
	for i := 0; i < 5; i++ {
		line := readLine()
		if strings.HasPrefix(line, "UBX 6 0") {
			foundUBX = true
			break
		}
	}
	if !foundUBX {
		t.Fatalf("expected UBX 6 0")
	}
}

func TestTrillianProAutoRegisterPasswordMismatchFix(t *testing.T) {
	database, _, _, _, ln, port := setupTestServer(t)
	defer database.Close()
	defer ln.Close()

	userEmail := "hui@msn.local"
	customPassword := "my_secret_random_pass_123"

	// 1. First connection: user does not exist in DB, connects with custom password
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to dial NS: %v", err)
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

	writeLine("VER 1 MSNP8 CVR0")
	_ = readLine() // VER 1 MSNP8 CVR0

	writeLine(fmt.Sprintf("CVR 2 0x0409 winnt 5.1 i386 TRILLIAN 3.1.0.121 msmsgs %s", userEmail))
	_ = readLine() // CVR 2 ...

	writeLine(fmt.Sprintf("USR 3 MD5 I %s", userEmail))
	usrChallengeLine := readLine()
	challengeParts := strings.Split(usrChallengeLine, " ")
	if len(challengeParts) < 5 {
		t.Fatalf("expected challenge line with at least 5 parts, got: %s", usrChallengeLine)
	}
	challenge := challengeParts[4]

	// Compute MD5 hash with user-chosen custom password
	hasher := md5.New()
	hasher.Write([]byte(challenge + customPassword))
	clientHash := hex.EncodeToString(hasher.Sum(nil))

	writeLine(fmt.Sprintf("USR 4 MD5 S %s", clientHash))
	usrOKLine := readLine()
	if !strings.HasPrefix(usrOKLine, fmt.Sprintf("USR 4 OK %s", userEmail)) {
		t.Fatalf("expected USR 4 OK for auto-registered user, got: %s", usrOKLine)
	}
	_ = conn.Close()

	// 2. Second connection: authenticate again with the same custom password
	conn2, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("failed to dial NS again: %v", err)
	}
	defer conn2.Close()

	reader2 := bufio.NewReader(conn2)
	readLine2 := func() string {
		line, err := reader2.ReadString('\n')
		if err != nil {
			t.Fatalf("failed to read line 2: %v", err)
		}
		return strings.TrimRight(line, "\r\n")
	}
	writeLine2 := func(s string) {
		_, _ = conn2.Write([]byte(s + "\r\n"))
	}

	writeLine2("VER 1 MSNP8 CVR0")
	_ = readLine2()
	writeLine2(fmt.Sprintf("CVR 2 0x0409 winnt 5.1 i386 TRILLIAN 3.1.0.121 msmsgs %s", userEmail))
	_ = readLine2()
	writeLine2(fmt.Sprintf("USR 3 MD5 I %s", userEmail))
	usrChallengeLine2 := readLine2()
	challenge2 := strings.Split(usrChallengeLine2, " ")[4]

	hasher2 := md5.New()
	hasher2.Write([]byte(challenge2 + customPassword))
	clientHash2 := hex.EncodeToString(hasher2.Sum(nil))

	writeLine2(fmt.Sprintf("USR 4 MD5 S %s", clientHash2))
	usrOKLine2 := readLine2()
	if !strings.HasPrefix(usrOKLine2, fmt.Sprintf("USR 4 OK %s", userEmail)) {
		t.Fatalf("expected USR 4 OK on re-login with registered password, got: %s", usrOKLine2)
	}
}

func TestIM2HandshakeTimingAndNoTridCHG(t *testing.T) {
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

	writeLine("VER 1 MSNP8 CVR0")
	_ = readLine()

	writeLine("CVR 2 0x0409 winnt 5.1 i386 im2 2.0.0.100 msmsgs metela229@hotmail.com")
	_ = readLine()

	// Direct TWN login
	writeLine("USR 3 TWN I metela229@hotmail.com")
	usrResp := readLine()
	if !strings.HasPrefix(usrResp, "USR 3 OK metela229@hotmail.com") {
		t.Fatalf("expected USR 3 OK, got: %s", usrResp)
	}

	// Ensure connection does NOT receive unsolicited SYN before IM2 sends CHG!
	// Send CHG NLN 0 without trid (exact IM2 behavior)
	writeLine("CHG NLN 0")
	chgResp := readLine()
	if !strings.HasPrefix(chgResp, "CHG 0 NLN") {
		t.Fatalf("expected CHG 0 NLN, got: %s", chgResp)
	}

	// Contact list arrives in response to CHG
	synResp := readLine()
	if !strings.HasPrefix(synResp, "SYN 0") {
		t.Fatalf("expected SYN 0 in response to CHG, got: %s", synResp)
	}
}

func TestMirandaHTTPGatewaySessionAndPoll(t *testing.T) {
	database, authMgr, sessionMgr, sbMgr, ln, port := setupTestServer(t)
	defer database.Close()
	defer ln.Close()

	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on HTTP: %v", err)
	}
	httpPort := httpLn.Addr().(*net.TCPAddr).Port
	_ = httpLn.Close()

	httpSrv := services.NewHTTPServer("127.0.0.1", httpPort, "127.0.0.1", database, authMgr, sessionMgr, sbMgr, true, "admin123")
	httpSrv.SetNSHandlerFactory(func(conn net.Conn) func() {
		h := NewNSClientHandler(conn, database, authMgr, sessionMgr, sbMgr, "127.0.0.1", port, 1864, httpPort)
		return h.Run
	})
	if err := httpSrv.Start(); err != nil {
		t.Fatalf("failed to start http: %v", err)
	}
	defer httpSrv.Stop()

	// 1. Miranda sends Action=open with initial VER packet
	openURL := fmt.Sprintf("http://127.0.0.1:%d/gateway/gateway.dll?Action=open&Server=NS", httpPort)
	initBody := "VER 1 MSNP9 CVR0\r\n"
	resp, err := http.Post(openURL, "application/x-msn-messenger", strings.NewReader(initBody))
	if err != nil {
		t.Fatalf("failed to post gateway open: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK from gateway, got: %d", resp.StatusCode)
	}

	xHeader := resp.Header.Get("X-MSN-Messenger")
	if !strings.Contains(xHeader, "SessionID=") {
		t.Fatalf("expected SessionID in X-MSN-Messenger header, got: %s", xHeader)
	}

	respBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(respBody), "VER 1 MSNP9") {
		t.Fatalf("expected VER 1 MSNP9 in response body, got: %s", string(respBody))
	}

	// Extract session ID
	sessionID := ""
	for _, part := range strings.Split(xHeader, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToLower(part), "sessionid=") {
			sessionID = strings.TrimPrefix(part, part[:10])
			break
		}
	}

	// 2. Poll for updates
	pollURL := fmt.Sprintf("http://127.0.0.1:%d/gateway/gateway.dll?Action=poll&SessionID=%s", httpPort, sessionID)
	req, _ := http.NewRequest("POST", pollURL, nil)
	req.Header.Set("X-MSN-Messenger", fmt.Sprintf("SessionID=%s", sessionID))
	pollResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("failed to poll gateway: %v", err)
	}
	defer pollResp.Body.Close()
	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK on poll, got: %d", pollResp.StatusCode)
	}
}

func TestMSNMessenger10MD5AutoRegister(t *testing.T) {
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

	// MSNP2 Handshake (no CVR in MSNP2)
	writeLine("VER 1 MSNP2")
	verResp := readLine()
	if !strings.HasPrefix(verResp, "VER 1 MSNP2") {
		t.Fatalf("expected VER 1 MSNP2, got: %s", verResp)
	}

	writeLine("INF 2")
	infResp := readLine()
	if !strings.HasPrefix(infResp, "INF 2 MD5") {
		t.Fatalf("expected INF 2 MD5, got: %s", infResp)
	}

	writeLine("USR 3 MD5 I msn1user@msn.local")
	usrChallenge := readLine()
	if !strings.HasPrefix(usrChallenge, "USR 3 MD5 S ") {
		t.Fatalf("expected USR 3 MD5 S, got: %s", usrChallenge)
	}
	challenge := strings.Split(usrChallenge, " ")[4]

	hasher := md5.New()
	hasher.Write([]byte(challenge + "chosen_secret_password"))
	clientHash := hex.EncodeToString(hasher.Sum(nil))

	writeLine(fmt.Sprintf("USR 4 MD5 S %s", clientHash))
	usrOK := readLine()
	if !strings.HasPrefix(usrOK, "USR 4 OK msn1user@msn.local") {
		t.Fatalf("expected USR 4 OK for MSN 1.0, got: %s", usrOK)
	}
}



