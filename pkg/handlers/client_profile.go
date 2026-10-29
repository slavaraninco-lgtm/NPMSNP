package handlers

import (
	"strings"

	"npmsnp/pkg/db"
)

// ClientProfile defines client-specific protocol behaviors, adaptations, and quirks.
type ClientProfile interface {
	Name() string
	IsANSI() bool
	HandleCVR(h *NSClientHandler, args []string) bool
	HandleUSR(h *NSClientHandler, args []string) bool
	OnLoginSuccessful(h *NSClientHandler, trid string, user *db.UserRecord)
	HandleCHG(h *NSClientHandler, args []string) bool
	SendContactList(h *NSClientHandler, trid string, force bool)
}

// DetectClientProfile identifies the client based on clientApp string and dialect.
func DetectClientProfile(clientApp string, dialect int) ClientProfile {
	app := strings.ToLower(clientApp)
	switch {
	case strings.Contains(app, "im2") || strings.Contains(app, "instantmessenger2") || strings.Contains(app, "im 2"):
		return NewIM2Profile()
	case strings.Contains(app, "trillian"):
		return NewTrillianProfile(app)
	case strings.Contains(app, "miranda"):
		return NewMirandaProfile(app)
	case strings.Contains(app, "gaim") || strings.Contains(app, "pidgin"):
		return NewGaimProfile()
	case strings.Contains(app, "msnmsgr") || strings.Contains(app, "msn messenger") || strings.Contains(app, "msmsgs"):
		return NewMSNProfile(app, dialect)
	case dialect <= 5:
		return NewMSNProfile(app, dialect)
	default:
		return NewDefaultProfile()
	}
}
