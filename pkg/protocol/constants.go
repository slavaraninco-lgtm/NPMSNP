package protocol

// MSNP Error Codes
const (
	ErrSyntaxError             = 200
	ErrInvalidParameter        = 201
	ErrInvalidUser             = 205
	ErrDomainNotProvided       = 206
	ErrAlreadyLoggedIn         = 207
	ErrInvalidUsername         = 208
	ErrInvalidFriendlyName     = 209
	ErrUserListFull            = 210
	ErrUserAlreadyThere        = 215
	ErrUserAlreadyOnList       = 216
	ErrNotOnList               = 217
	ErrAlreadyInMode           = 218
	ErrAlreadyInOppositeList   = 219
	ErrSwitchboardFailed       = 280
	ErrInternalServerError     = 500
	ErrDatabaseServerError     = 501
	ErrServerIsClosing         = 520
	ErrServerBusy              = 600
	ErrServerUnavailable        = 601
	ErrPeerConnectionFailed    = 707
	ErrNotAllowed              = 713
	ErrCannotCreateSwitchboard = 714
	ErrPrincipalNotOnline      = 715
	ErrUserOffline             = 731
	ErrAuthenticationFailed    = 911
	ErrServerTooBusy           = 920
)

// User presence statuses
const (
	StatusOnline  = "NLN"
	StatusOffline = "FLN"
	StatusHidden  = "HDN"
	StatusBusy    = "BSY"
	StatusIdle    = "IDL"
	StatusBRB     = "BRB"
	StatusAway    = "AWY"
	StatusPhone   = "PHN"
	StatusLunch   = "LUN"
)

// Contact list masks
const (
	ListFL = 1 // Forward List (Contacts buddy list)
	ListAL = 2 // Allow List (Allowed to see presence)
	ListBL = 4 // Block List (Blocked from seeing presence)
	ListRL = 8 // Reverse List (Contacts who have this user in their list)
)

// Supported MSNP protocol dialects
var SupportedDialects = map[string]int{
	"MSNP2":  2,
	"MSNP3":  3,
	"MSNP4":  4,
	"MSNP5":  5,
	"MSNP6":  6,
	"MSNP7":  7,
	"MSNP8":  8,
	"MSNP9":  9,
	"MSNP10": 10,
	"MSNP11": 11,
	"MSNP12": 12,
}

var OrderedDialects = []string{
	"MSNP12", "MSNP11", "MSNP10", "MSNP9", "MSNP8", "MSNP7", "MSNP6", "MSNP5", "MSNP4", "MSNP3", "MSNP2",
}

