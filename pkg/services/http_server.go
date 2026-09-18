package services

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"html"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"npmsnp/pkg/db"
	"npmsnp/pkg/protocol"
)

//go:embed dashboard.html
var dashboardTemplate string

type HTTPServer struct {
	host               string
	port               int
	externalHost       string
	database           *db.Database
	authManager        *protocol.AuthManager
	sessionManager     *SessionManager
	switchboardManager *SwitchboardManager
	autoRegister       bool
	adminPassword      string
	server             *http.Server
	adminSessions      map[string]time.Time
	sessionsMu         sync.RWMutex
	startTime          time.Time
}

func NewHTTPServer(host string, port int, externalHost string, database *db.Database,
	authManager *protocol.AuthManager, sessionManager *SessionManager,
	switchboardManager *SwitchboardManager, autoRegister bool, adminPassword string) *HTTPServer {

	s := &HTTPServer{
		host:               host,
		port:               port,
		externalHost:       externalHost,
		database:           database,
		authManager:        authManager,
		sessionManager:     sessionManager,
		switchboardManager: switchboardManager,
		autoRegister:       autoRegister,
		adminPassword:      adminPassword,
		adminSessions:      make(map[string]time.Time),
		startTime:          time.Now(),
	}
	return s
}

func (s *HTTPServer) Start() error {
	mux := http.NewServeMux()

	// Passport / Nexus endpoints
	mux.HandleFunc("/rdr/pprdr.asp", s.handlePassportNexus)
	mux.HandleFunc("/nexus-mock", s.handlePassportNexus)
	mux.HandleFunc("/login-mock", s.handlePassportLogin)
	mux.HandleFunc("/login.srf", s.handlePassportLogin)

	// Admin Web & API
	mux.HandleFunc("/", s.handleDashboard)
	mux.HandleFunc("/admin", s.handleDashboard)
	mux.HandleFunc("/index.html", s.handleDashboard)
	mux.HandleFunc("/api/login", s.handleAPILogin)
	mux.HandleFunc("/api/admin/login", s.handleAPILogin)
	mux.HandleFunc("/api/logout", s.handleAPILogout)
	mux.HandleFunc("/api/admin/logout", s.handleAPILogout)
	mux.HandleFunc("/api/admin/check", s.handleAPICheck)
	mux.HandleFunc("/api/register", s.handleAPIRegister)
	mux.HandleFunc("/api/status", s.handleAPIStatus)
	mux.HandleFunc("/api/stats", s.handleAPIStatus)
	mux.HandleFunc("/api/notify", s.handleAPINotify)
	mux.HandleFunc("/api/users", s.handleAPIUsers)
	mux.HandleFunc("/api/users/create", s.handleAPICreateUser)
	mux.HandleFunc("/api/users/add", s.handleAPICreateUser)
	mux.HandleFunc("/api/users/delete", s.handleAPIDeleteUser)
	mux.HandleFunc("/api/users/disconnect", s.handleAPIDisconnectUser)
	mux.HandleFunc("/api/users/password", s.handleAPIUpdatePassword)
	mux.HandleFunc("/api/users/update_password", s.handleAPIUpdatePassword)
	mux.HandleFunc("/api/users/update_name", s.handleAPIUpdateName)
	mux.HandleFunc("/api/users/ban", s.handleAPIBanUser)
	mux.HandleFunc("/api/users/unban", s.handleAPIUnbanUser)
	mux.HandleFunc("/api/users/mute", s.handleAPIMuteUser)
	mux.HandleFunc("/api/users/unmute", s.handleAPIUnmuteUser)
	mux.HandleFunc("/api/broadcast", s.handleAPIBroadcast)

	addr := fmt.Sprintf("%s:%d", s.host, s.port)
	s.server = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	go func() {
		_ = s.server.Serve(ln)
	}()

	return nil
}

func (s *HTTPServer) Stop() error {
	if s.server != nil {
		return s.server.Close()
	}
	return nil
}

// Passport / Nexus handlers

func (s *HTTPServer) handlePassportNexus(w http.ResponseWriter, r *http.Request) {
	host := s.externalHost
	if host == "" || host == "0.0.0.0" {
		host = "127.0.0.1"
	}
	loginURL := fmt.Sprintf("http://%s:%d/login.srf", host, s.port)
	passportHeader := fmt.Sprintf("DARes=%s,DALogin=%s,DAReg=http://%s:%d/",
		loginURL, loginURL, host, s.port)

	w.Header().Set("PassportURLs", passportHeader)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<html><body>Nexus Mock OK</body></html>"))
}

func (s *HTTPServer) handlePassportLogin(w http.ResponseWriter, r *http.Request) {
	ticket := s.authManager.CreateTWNTicket("auto@msn.local", 1*time.Hour)
	info := fmt.Sprintf("Passport1.4 da-status=success,tkt=%s,from-PP='%s&p=profile_test',ru=http://messenger.msn.com", ticket, ticket)

	w.Header().Set("Authentication-Info", info)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<html><body>Login Mock OK</body></html>"))
}

// Admin Auth Helper

func (s *HTTPServer) checkAdminAuth(r *http.Request) bool {
	token := r.Header.Get("X-Admin-Token")
	if token == "" {
		if cookie, err := r.Cookie("admin_session"); err == nil {
			token = cookie.Value
		}
	}
	if token == "" {
		if cookie, err := r.Cookie("admin_token"); err == nil {
			token = cookie.Value
		}
	}
	if token != "" {
		s.sessionsMu.RLock()
		exp, ok := s.adminSessions[token]
		s.sessionsMu.RUnlock()
		if ok && time.Now().Before(exp) {
			return true
		}
	}
	return false
}

// API Handlers

func (s *HTTPServer) handleAPILogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Compare plaintext with decrypted admin password
	actualAdminPassword := db.DecryptPassword(s.adminPassword, s.database.SecretKey())
	if actualAdminPassword == "" {
		actualAdminPassword = "admin123"
	}

	if req.Password != actualAdminPassword {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"error":   "Неверный пароль администратора",
		})
		return
	}

	token := s.authManager.CreateTWNTicket("admin@npmsnp", 24*time.Hour)
	s.sessionsMu.Lock()
	s.adminSessions[token] = time.Now().Add(24 * time.Hour)
	s.sessionsMu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "admin_session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "admin_token",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(24 * time.Hour),
		HttpOnly: true,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"token":   token,
	})
}

func (s *HTTPServer) handleAPILogout(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("X-Admin-Token")
	if cookie, err := r.Cookie("admin_session"); err == nil && token == "" {
		token = cookie.Value
	}
	if cookie, err := r.Cookie("admin_token"); err == nil && token == "" {
		token = cookie.Value
	}
	if token != "" {
		s.sessionsMu.Lock()
		delete(s.adminSessions, token)
		s.sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "admin_session", Value: "", Path: "/", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "admin_token", Value: "", Path: "/", MaxAge: -1})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *HTTPServer) handleAPICheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"authenticated": s.checkAdminAuth(r)})
}

func (s *HTTPServer) handleAPIRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Email           string `json:"email"`
		Password        string `json:"password"`
		ConfirmPassword string `json:"confirm_password"`
		FriendlyName    string `json:"friendly_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	req.Email = strings.TrimSpace(req.Email)
	if req.Email == "" || req.Password == "" || !strings.Contains(req.Email, "@") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "Некорректный адрес email или пустой пароль"})
		return
	}
	if req.ConfirmPassword != "" && req.ConfirmPassword != req.Password {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "Пароли не совпадают"})
		return
	}
	if u, _ := s.database.GetUser(req.Email); u != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": "Пользователь с таким email уже зарегистрирован"})
		return
	}
	user, err := s.database.CreateUser(req.Email, req.Password, req.FriendlyName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":       true,
		"email":         user.Email,
		"friendly_name": user.FriendlyName,
	})
}

func (s *HTTPServer) handleAPIStats(w http.ResponseWriter, r *http.Request) {
	users, _ := s.database.GetAllUsers()
	active := s.sessionManager.GetActiveUsersList()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"project_name": "NPMSNP",
		"server_name":  "NPMSNP Server",
		"status":       "running",
		"total_users":  len(users),
		"online_users": len(active),
		"active_users": active,
	})
}

func (s *HTTPServer) handleAPIUsers(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	users, err := s.database.GetAllUsersWithMeta()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for _, u := range users {
		email := u.Email
		isOn := s.sessionManager.IsOnline(email)
		sess := s.sessionManager.GetSession(email)
		u.IsOnline = isOn
		if sess != nil && isOn {
			u.LiveStatus = sess.GetStatus()
			u.Peer = sess.GetPeerName()
		} else {
			u.LiveStatus = "FLN"
			u.Peer = ""
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"users": users,
	})
}

func (s *HTTPServer) handleAPICreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email        string `json:"email"`
		Password     string `json:"password"`
		FriendlyName string `json:"friendly_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	email := strings.TrimSpace(req.Email)
	if !strings.Contains(email, "@") || req.Password == "" {
		http.Error(w, "Invalid email or password", http.StatusBadRequest)
		return
	}

	u, err := s.database.CreateUser(email, req.Password, req.FriendlyName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"user":    u,
	})
}

func (s *HTTPServer) handleAPIDeleteUser(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	if err := s.database.DeleteUser(req.Email); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *HTTPServer) handleAPIUpdatePassword(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		NewPassword string `json:"new_password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	newPwd := req.NewPassword
	if newPwd == "" {
		newPwd = req.Password
	}
	req.Email = strings.TrimSpace(req.Email)

	if req.Email == "" || newPwd == "" {
		http.Error(w, "Missing email or password", http.StatusBadRequest)
		return
	}

	if err := s.database.UpdatePassword(req.Email, newPwd); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *HTTPServer) handleAPIUpdateName(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Email        string `json:"email"`
		FriendlyName string `json:"friendly_name"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	req.Email = strings.TrimSpace(req.Email)

	if req.Email == "" {
		http.Error(w, "Missing email", http.StatusBadRequest)
		return
	}

	if err := s.database.UpdateFriendlyName(req.Email, req.FriendlyName); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if sess := s.sessionManager.GetSession(req.Email); sess != nil {
		s.sessionManager.BroadcastFriendlyNameChange(req.Email, req.FriendlyName)
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *HTTPServer) handleAPIBanUser(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Duration int    `json:"duration"`
		Reason   string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	_ = s.database.BanUser(req.Email, req.Duration, req.Reason)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *HTTPServer) handleAPIUnbanUser(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	_ = s.database.UnbanUser(req.Email)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *HTTPServer) handleAPIMuteUser(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Email    string `json:"email"`
		Duration int    `json:"duration"`
		Reason   string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	_ = s.database.MuteUser(req.Email, req.Duration, req.Reason)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *HTTPServer) handleAPIUnmuteUser(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	_ = s.database.UnmuteUser(req.Email)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func (s *HTTPServer) handleAPIBroadcast(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Message string `json:"message"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	delivered := s.sessionManager.BroadcastSystemNotification(req.Message, "system@msn.local", "Служба сообщений MSN")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"delivered": delivered,
	})
}

func (s *HTTPServer) handleAPIDisconnectUser(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Email string `json:"email"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	email := strings.TrimSpace(req.Email)
	if email == "" {
		http.Error(w, "Email required", http.StatusBadRequest)
		return
	}

	disconnected := s.sessionManager.DisconnectUser(email)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"disconnected": disconnected,
	})
}

func (s *HTTPServer) handleAPINotify(w http.ResponseWriter, r *http.Request) {
	if !s.checkAdminAuth(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		Target  string `json:"target"`
		Message string `json:"message"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	msg := strings.TrimSpace(req.Message)
	if msg == "" {
		http.Error(w, "Message required", http.StatusBadRequest)
		return
	}

	target := strings.ToLower(strings.TrimSpace(req.Target))
	if target == "" {
		target = "online"
	}

	serviceEmail := "system@msn.local"
	serviceName := "Служба сообщений MSN"
	deliveredOnline := 0
	savedOffline := 0

	deliverToUser := func(uEmail string) bool {
		if s.switchboardManager.DeliverServicePM(uEmail, msg, s.sessionManager, s.externalHost, 1864) {
			return true
		}
		return s.sessionManager.SendSystemNotification(uEmail, msg, serviceEmail, serviceName)
	}

	if target == "online" {
		for _, u := range s.sessionManager.GetActiveUsersList() {
			if strings.EqualFold(u.Email, serviceEmail) {
				continue
			}
			if deliverToUser(u.Email) {
				deliveredOnline++
			}
		}
	} else if target == "all" {
		for _, u := range s.sessionManager.GetActiveUsersList() {
			if strings.EqualFold(u.Email, serviceEmail) {
				continue
			}
			if deliverToUser(u.Email) {
				deliveredOnline++
			}
		}
		allUsers, _ := s.database.GetAllUsers()
		for _, u := range allUsers {
			if strings.EqualFold(u.Email, serviceEmail) {
				continue
			}
			if !s.sessionManager.IsOnline(u.Email) {
				_ = s.database.SaveOfflineMessage(serviceEmail, u.Email, msg)
				savedOffline++
			}
		}
	} else {
		if s.sessionManager.IsOnline(target) {
			if deliverToUser(target) {
				deliveredOnline = 1
			}
		} else {
			_ = s.database.SaveOfflineMessage(serviceEmail, target, msg)
			savedOffline = 1
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":          true,
		"target":           target,
		"delivered_online": deliveredOnline,
		"saved_offline":    savedOffline,
	})
}

func (s *HTTPServer) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	uptimeSec := int(time.Since(s.startTime).Seconds())
	stats, _ := s.database.GetDatabaseStats()
	activeUsers := s.sessionManager.GetActiveUsersList()

	totalUsers := 0
	if stats != nil {
		if tu, ok := stats["total_users"].(int); ok {
			totalUsers = tu
		}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"project":            "NPMSNP",
		"project_name":       "NPMSNP",
		"server_name":        "NPMSNP Server",
		"version":            "1.0.0",
		"status":             "online",
		"uptime_seconds":     uptimeSec,
		"total_users":        totalUsers,
		"online_users":       len(activeUsers),
		"external_host":      s.externalHost,
		"ports": map[string]int{
			"ns":   1863,
			"sb":   1864,
			"http": s.port,
		},
		"stats":              stats,
		"active_users_count": len(activeUsers),
		"active_users":       activeUsers,
	})
}

// Dashboard HTML

func (s *HTTPServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" && r.URL.Path != "/index.html" && r.URL.Path != "/admin" {
		http.NotFound(w, r)
		return
	}

	htmlContent := s.renderDashboard(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(htmlContent))
}

func (s *HTTPServer) renderDashboard(r *http.Request) string {
	isAdmin := s.checkAdminAuth(r)

	dbStats, _ := s.database.GetDatabaseStats()
	users, _ := s.database.GetAllUsersWithMeta()
	activeUsers := s.sessionManager.GetActiveUsersList()

	uptimeSec := int(time.Since(s.startTime).Seconds())
	uptimeHours := uptimeSec / 3600
	uptimeMins := (uptimeSec % 3600) / 60
	uptimeSecs := uptimeSec % 60
	uptimeStr := fmt.Sprintf("%d ч. %d мин. %d сек.", uptimeHours, uptimeMins, uptimeSecs)

	dbSizeKB := 0.0
	if dbStats != nil {
		if dbSize, ok := dbStats["db_size_bytes"].(int64); ok {
			dbSizeKB = float64(dbSize) / 1024.0
		} else if dbSizeI, ok := dbStats["db_size_bytes"].(int); ok {
			dbSizeKB = float64(dbSizeI) / 1024.0
		}
	}

	authBadgeHTML := `<span id="authStatusText" style="color: #666;">&#128274; Гостевой режим (регистрация)</span> <button type="button" id="authBtn" class="btn-classic btn-sm" onclick="openLoginModal()" style="margin-left: 6px;">Вход администратора</button>`
	if isAdmin {
		authBadgeHTML = `<span id="authStatusText" style="color: #008000; font-weight: bold;">&#128274; Администратор: Авторизован</span> <button type="button" id="authBtn" class="btn-classic btn-sm" onclick="submitAdminLogout()" style="margin-left: 6px;">Выйти</button>`
	}

	var userRows []string
	if isAdmin {
		for idx, u := range users {
			email := u.Email
			isOn := s.sessionManager.IsOnline(email)
			sess := s.sessionManager.GetSession(email)

			statusBadge := `<span style="color: #666666;">[ОФЛАЙН]</span>`
			if isOn {
				st := "NLN"
				if sess != nil && sess.GetStatus() != "" {
					st = sess.GetStatus()
				}
				statusBadge = fmt.Sprintf(`<span style="color: #008000; font-weight: bold;">[В СЕТИ: %s]</span>`, html.EscapeString(st))
			}

			var penaltiesHTML []string
			if u.IsBanned {
				penaltiesHTML = append(penaltiesHTML, fmt.Sprintf(`<span style="color: #cc0000; font-weight: bold; margin-left: 3px;" title="Бан: %s">[БАН: %s]</span>`, html.EscapeString(u.BanReason), html.EscapeString(u.BanRemaining)))
			}
			if u.IsMuted {
				penaltiesHTML = append(penaltiesHTML, fmt.Sprintf(`<span style="color: #b05a00; font-weight: bold; margin-left: 3px;" title="Мут: %s">[МУТ: %s]</span>`, html.EscapeString(u.MuteReason), html.EscapeString(u.MuteRemaining)))
			}
			penaltyStr := strings.Join(penaltiesHTML, " ")

			rowClass := ""
			if idx%2 == 1 {
				rowClass = ` class="row-alt"`
			}
			emailEsc := html.EscapeString(email)
			nameEsc := html.EscapeString(u.FriendlyName)
			emailJS := strings.ReplaceAll(email, "'", "\\'")
			nameJS := strings.ReplaceAll(u.FriendlyName, "'", "\\'")
			createdStr := u.CreatedAt
			if len(createdStr) > 19 {
				createdStr = createdStr[:19]
			}
			lastSeenStr := u.LastSeen
			if len(lastSeenStr) > 19 {
				lastSeenStr = lastSeenStr[:19]
			}

			actionDisconnect := ""
			if isOn {
				actionDisconnect = fmt.Sprintf(`<button type="button" class="btn-classic btn-sm btn-warn" onclick="disconnectUser('%s')" title="Разорвать текущую сессию">Сброс</button> `, emailJS)
			}

			btnBanText := "Бан"
			btnBanCls := "btn-classic btn-sm"
			banArg := 0
			if u.IsBanned {
				btnBanText = "Разбан"
				btnBanCls = "btn-classic btn-sm btn-danger"
				banArg = 1
			}

			btnMuteText := "Мут"
			btnMuteCls := "btn-classic btn-sm"
			muteArg := 0
			if u.IsMuted {
				btnMuteText = "Размут"
				btnMuteCls = "btn-classic btn-sm btn-warn"
				muteArg = 1
			}

			userRows = append(userRows, fmt.Sprintf(`
            <tr%s id="row-%s" data-email="%s" data-name="%s">
                <td><strong>%s</strong></td>
                <td id="name-cell-%s">%s</td>
                <td>%s %s</td>
                <td align="center"><strong>%d</strong></td>
                <td style="color: #555555;">%s</td>
                <td style="color: #555555;">%s</td>
                <td align="center">
                    <button type="button" class="%s" onclick="openBanModal('%s', %d)" title="Управление блокировкой">%s</button>
                    <button type="button" class="%s" onclick="openMuteModal('%s', %d)" title="Управление мутом">%s</button>
                    <button type="button" class="btn-classic btn-sm" onclick="openDirectMsgModal('%s')" title="Отправить сообщение от служебного аккаунта">ЛС</button>
                    <button type="button" class="btn-classic btn-sm" onclick="openPasswordModal('%s')" title="Сменить пароль">Пароль</button>
                    <button type="button" class="btn-classic btn-sm" onclick="openNameModal('%s', '%s')" title="Изменить имя">Имя</button>
                    %s
                    <button type="button" class="btn-classic btn-sm btn-danger" onclick="deleteUser('%s')" title="Удалить аккаунт">Удалить</button>
                </td>
            </tr>`,
				rowClass, emailEsc, strings.ToLower(emailEsc), strings.ToLower(nameEsc),
				emailEsc, emailEsc, nameEsc,
				statusBadge, penaltyStr,
				u.ContactCount,
				html.EscapeString(createdStr), html.EscapeString(lastSeenStr),
				btnBanCls, emailJS, banArg, btnBanText,
				btnMuteCls, emailJS, muteArg, btnMuteText,
				emailJS, emailJS, emailJS, nameJS,
				actionDisconnect, emailJS))
		}
	}

	var connRows []string
	if isAdmin {
		for idx, sess := range activeUsers {
			rowClass := ""
			if idx%2 == 1 {
				rowClass = ` class="row-alt"`
			}
			cEmail := html.EscapeString(sess.Email)
			cName := html.EscapeString(sess.FriendlyName)
			cPeer := html.EscapeString(sess.Peer)
			cStatus := html.EscapeString(sess.Status)
			cClientID := html.EscapeString(sess.ClientID)
			cEmailJS := strings.ReplaceAll(sess.Email, "'", "\\'")

			connRows = append(connRows, fmt.Sprintf(`
            <tr%s>
                <td><strong>%s</strong></td>
                <td>%s</td>
                <td><span class="code-font">%s</span></td>
                <td><span style="color: #008000; font-weight: bold;">%s</span></td>
                <td><span class="code-font">%s</span></td>
                <td align="center">
                    <button type="button" class="btn-classic btn-sm btn-warn" onclick="disconnectUser('%s')">Отключить</button>
                </td>
            </tr>`, rowClass, cEmail, cName, cPeer, cStatus, cClientID, cEmailJS))
		}
	}

	userRowsHTML := `<tr><td colspan='7' align='center' style='color: #666; padding: 25px;'><strong>Доступ к списку пользователей защищен паролем администратора.</strong><br><br><button type='button' class='btn-classic' onclick='openLoginModal()'>Ввести пароль администратора</button></td></tr>`
	connRowsHTML := `<tr><td colspan='6' align='center' style='color: #666; padding: 20px;'><strong>Доступ к списку подключений защищен паролем администратора.</strong><br><br><button type='button' class='btn-classic' onclick='openLoginModal()'>Ввести пароль администратора</button></td></tr>`

	if isAdmin {
		if len(userRows) > 0 {
			userRowsHTML = strings.Join(userRows, "\n")
		} else {
			userRowsHTML = `<tr><td colspan='7' align='center' style='color: #666; padding: 12px;'>В базе данных пока нет зарегистрированных пользователей</td></tr>`
		}
		if len(connRows) > 0 {
			connRowsHTML = strings.Join(connRows, "\n")
		} else {
			connRowsHTML = `<tr><td colspan='6' align='center' style='color: #666; padding: 12px;'>Нет активных подключений в данный момент</td></tr>`
		}
	}

	serviceEmail := "system@msn.local"
	serviceName := "Служба сообщений MSN"
	projectName := "NPMSNP"
	serverVersion := "1.0.0"

	adminBoolStr := "false"
	if isAdmin {
		adminBoolStr = "true"
	}

	res := dashboardTemplate
	res = strings.ReplaceAll(res, "__PROJECT_NAME__", projectName)
	res = strings.ReplaceAll(res, "__SERVER_VERSION__", serverVersion)
	res = strings.ReplaceAll(res, "__SERVICE_EMAIL__", serviceEmail)
	res = strings.ReplaceAll(res, "__SERVICE_NAME__", serviceName)
	res = strings.ReplaceAll(res, "__HTTP_PORT__", fmt.Sprintf("%d", s.port))
	res = strings.ReplaceAll(res, "__EXTERNAL_HOST__", s.externalHost)
	res = strings.ReplaceAll(res, "__AUTH_BADGE_HTML__", authBadgeHTML)
	res = strings.ReplaceAll(res, "__IS_ADMIN_BOOL__", adminBoolStr)
	res = strings.ReplaceAll(res, "__UPTIME_STR__", uptimeStr)
	res = strings.ReplaceAll(res, "__DB_SIZE_KB__", fmt.Sprintf("%.1f", dbSizeKB))
	res = strings.ReplaceAll(res, "__USER_ROWS_HTML__", userRowsHTML)
	res = strings.ReplaceAll(res, "__CONN_ROWS_HTML__", connRowsHTML)

	return res
}
