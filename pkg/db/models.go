package db

// UserRecord represents a user in database.db.
type UserRecord struct {
	Email         string `json:"email"`
	Password      string `json:"password"`
	FriendlyName  string `json:"friendly_name"`
	Status        string `json:"status"`
	ClientID      string `json:"client_id"`
	CustomMessage string `json:"custom_message"`
	MSNObj        string `json:"msn_obj"`
	PhoneHome     string `json:"phone_home"`
	PhoneWork     string `json:"phone_work"`
	PhoneMobile   string `json:"phone_mobile"`
	CreatedAt     string `json:"created_at"`
	LastSeen      string `json:"last_seen"`
	BannedUntil   string `json:"banned_until"`
	BanReason     string `json:"ban_reason"`
	MutedUntil    string `json:"muted_until"`
	MuteReason    string `json:"mute_reason"`
}

// ContactRecord represents a buddy contact list entry.
type ContactRecord struct {
	UserEmail    string `json:"user_email"`
	ContactEmail string `json:"contact_email"`
	ListFlags    int    `json:"list_flags"`
	GroupID      int    `json:"group_id"`
	FriendlyName string `json:"friendly_name"`
	CreatedAt    string `json:"created_at"`
}

// GroupRecord represents a buddy list group.
type GroupRecord struct {
	ID        int    `json:"id"`
	UserEmail string `json:"user_email"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
}

// OfflineMessageRecord represents an unread offline message.
type OfflineMessageRecord struct {
	ID        int    `json:"id"`
	Sender    string `json:"sender"`
	Recipient string `json:"recipient"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
	Delivered int    `json:"delivered"`
}

// PenaltyStatus represents ban and mute state for a user.
type PenaltyStatus struct {
	IsBanned     bool   `json:"is_banned"`
	BanReason    string `json:"ban_reason"`
	BanRemaining string `json:"ban_remaining"`
	IsMuted      bool   `json:"is_muted"`
	MuteReason   string `json:"mute_reason"`
	MuteRemaining string `json:"mute_remaining"`
}
