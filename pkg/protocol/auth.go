package protocol

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

type md5Challenge struct {
	Challenge string
	CreatedAt time.Time
}

type twnTicket struct {
	Email   string
	Expires time.Time
}

type sbCookie struct {
	Email     string
	SessionID int
	Role      string
	Expires   time.Time
}

type AuthManager struct {
	secretKey     string
	mu            sync.Mutex
	md5Challenges map[string]md5Challenge
	twnTickets    map[string]twnTicket
	sbCookies     map[string]sbCookie
}

func NewAuthManager(secretKey string) *AuthManager {
	if secretKey == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		secretKey = hex.EncodeToString(b)
	}
	return &AuthManager{
		secretKey:     secretKey,
		md5Challenges: make(map[string]md5Challenge),
		twnTickets:    make(map[string]twnTicket),
		sbCookies:     make(map[string]sbCookie),
	}
}

// MD5 Challenge-Response

func (a *AuthManager) CreateMD5Challenge(email string) string {
	a.mu.Lock()
	defer a.mu.Unlock()

	h := md5.New()
	h.Write([]byte(a.secretKey + ":" + strings.ToLower(email) + ":msnp_salt_2026"))
	sum := h.Sum(nil)
	val := uint32(sum[0])<<24 | uint32(sum[1])<<16 | uint32(sum[2])<<8 | uint32(sum[3])
	challenge := fmt.Sprintf("%d", val%900000000+100000000)

	a.md5Challenges[strings.ToLower(email)] = md5Challenge{
		Challenge: challenge,
		CreatedAt: time.Now(),
	}
	return challenge
}

func (a *AuthManager) VerifyMD5Response(email, responseHash, actualPassword string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := strings.ToLower(email)
	c, ok := a.md5Challenges[key]
	if !ok {
		return false
	}
	delete(a.md5Challenges, key)

	if time.Since(c.CreatedAt) > 2*time.Minute {
		return false
	}

	h := md5.New()
	h.Write([]byte(c.Challenge + actualPassword))
	expected := hex.EncodeToString(h.Sum(nil))

	return strings.EqualFold(responseHash, expected)
}

// TWN Passport Tickets

func (a *AuthManager) CreateTWNTicket(email string, lifetime time.Duration) string {
	a.mu.Lock()
	defer a.mu.Unlock()

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	rawToken := hex.EncodeToString(b)
	tokenStr := "t=" + rawToken

	expiry := time.Now().Add(lifetime)
	a.twnTickets[tokenStr] = twnTicket{Email: strings.ToLower(email), Expires: expiry}
	a.twnTickets[rawToken] = twnTicket{Email: strings.ToLower(email), Expires: expiry}

	return tokenStr
}

func (a *AuthManager) VerifyTWNTicket(token, expectedEmail string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	token = strings.TrimSpace(token)
	data, ok := a.twnTickets[token]
	if !ok {
		if strings.HasPrefix(token, "t=") {
			data, ok = a.twnTickets[token[2:]]
		} else {
			data, ok = a.twnTickets["t="+token]
		}
	}

	if !ok || time.Now().After(data.Expires) {
		return false
	}

	return strings.EqualFold(data.Email, expectedEmail)
}

// Switchboard Cookies (CKI)

func (a *AuthManager) CreateSBCookie(email string, sessionID int, role string, lifetime time.Duration) string {
	a.mu.Lock()
	defer a.mu.Unlock()

	b := make([]byte, 12)
	_, _ = rand.Read(b)
	cookie := hex.EncodeToString(b)

	a.sbCookies[cookie] = sbCookie{
		Email:     strings.ToLower(email),
		SessionID: sessionID,
		Role:      role,
		Expires:   time.Now().Add(lifetime),
	}
	return cookie
}

func (a *AuthManager) VerifyAndConsumeSBCookie(cookie, expectedEmail string) (int, string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	data, ok := a.sbCookies[cookie]
	if !ok {
		return 0, "", false
	}
	delete(a.sbCookies, cookie)

	if time.Now().After(data.Expires) {
		return 0, "", false
	}

	if expectedEmail != "" && !strings.EqualFold(data.Email, expectedEmail) {
		return 0, "", false
	}

	return data.SessionID, data.Role, true
}
