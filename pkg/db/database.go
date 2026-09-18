package db

import (
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

type Database struct {
	dbPath    string
	secretKey string
	db        *sql.DB
	mu        sync.RWMutex
}

func NewDatabase(dbPath, secretKey string) (*Database, error) {
	if secretKey == "" {
		secretKey = DefaultFallbackKey
	}

	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(30000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open sqlite failed: %w", err)
	}

	d := &Database{
		dbPath:    dbPath,
		secretKey: secretKey,
		db:        db,
	}

	if err := d.initDB(); err != nil {
		db.Close()
		return nil, fmt.Errorf("init db failed: %w", err)
	}

	d.migratePlainPasswords()
	return d, nil
}

func (d *Database) Close() error {
	return d.db.Close()
}

func (d *Database) SecretKey() string {
	return d.secretKey
}

func (d *Database) initDB() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
			email TEXT PRIMARY KEY COLLATE NOCASE,
			password TEXT NOT NULL,
			friendly_name TEXT NOT NULL,
			status TEXT DEFAULT 'FLN',
			client_id TEXT DEFAULT '0',
			custom_message TEXT DEFAULT '',
			msn_obj TEXT DEFAULT '',
			phone_home TEXT DEFAULT '',
			phone_work TEXT DEFAULT '',
			phone_mobile TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			banned_until TEXT DEFAULT '',
			ban_reason TEXT DEFAULT '',
			muted_until TEXT DEFAULT '',
			mute_reason TEXT DEFAULT ''
		);`,
		`CREATE TABLE IF NOT EXISTS contacts (
			user_email TEXT NOT NULL COLLATE NOCASE,
			contact_email TEXT NOT NULL COLLATE NOCASE,
			list_flags INTEGER DEFAULT 1,
			group_id INTEGER DEFAULT 0,
			friendly_name TEXT DEFAULT '',
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (user_email, contact_email)
		);`,
		`CREATE TABLE IF NOT EXISTS groups (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			user_email TEXT NOT NULL COLLATE NOCASE,
			name TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);`,
		`CREATE TABLE IF NOT EXISTS offline_messages (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			sender TEXT NOT NULL COLLATE NOCASE,
			recipient TEXT NOT NULL COLLATE NOCASE,
			message TEXT NOT NULL,
			timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			delivered INTEGER DEFAULT 0
		);`,
	}

	for _, q := range queries {
		if _, err := d.db.Exec(q); err != nil {
			return err
		}
	}

	// Add penalty columns if missing in legacy schemas
	penaltyCols := []string{"banned_until", "ban_reason", "muted_until", "mute_reason"}
	for _, col := range penaltyCols {
		_, _ = d.db.Exec(fmt.Sprintf("ALTER TABLE users ADD COLUMN %s TEXT DEFAULT '';", col))
	}

	return nil
}

func (d *Database) migratePlainPasswords() {
	d.mu.Lock()
	defer d.mu.Unlock()

	rows, err := d.db.Query("SELECT email, password FROM users;")
	if err != nil {
		return
	}
	defer rows.Close()

	type toUpdate struct {
		email string
		enc   string
	}
	var updates []toUpdate

	for rows.Next() {
		var email, pwd string
		if err := rows.Scan(&email, &pwd); err == nil {
			if !IsEncrypted(pwd) && pwd != "" {
				updates = append(updates, toUpdate{
					email: email,
					enc:   EncryptPassword(pwd, d.secretKey),
				})
			}
		}
	}

	for _, u := range updates {
		_, _ = d.db.Exec("UPDATE users SET password = ? WHERE email = ?;", u.enc, u.email)
	}
}

// EnsureServiceAccount creates or updates the default system service account.
func (d *Database) EnsureServiceAccount(email, name string) error {
	email = strings.TrimSpace(email)
	name = strings.TrimSpace(name)
	user, err := d.GetUser(email)
	if err != nil {
		return err
	}
	if user == nil {
		_, err = d.CreateUser(email, "system_service_internal_password", name)
		return err
	}
	if user.FriendlyName != name {
		return d.UpdateFriendlyName(email, name)
	}
	return nil
}

// User Management

func (d *Database) GetUser(email string) (*UserRecord, error) {
	email = strings.TrimSpace(email)
	d.mu.RLock()
	defer d.mu.RUnlock()

	row := d.db.QueryRow(`
		SELECT email, password, friendly_name, status, client_id, custom_message,
		       msn_obj, phone_home, phone_work, phone_mobile, created_at, last_seen,
		       banned_until, ban_reason, muted_until, mute_reason
		FROM users WHERE email = ? COLLATE NOCASE;`, email)

	var u UserRecord
	var rawPassword string
	err := row.Scan(
		&u.Email, &rawPassword, &u.FriendlyName, &u.Status, &u.ClientID,
		&u.CustomMessage, &u.MSNObj, &u.PhoneHome, &u.PhoneWork, &u.PhoneMobile,
		&u.CreatedAt, &u.LastSeen, &u.BannedUntil, &u.BanReason, &u.MutedUntil, &u.MuteReason,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	u.Password = DecryptPassword(rawPassword, d.secretKey)
	return &u, nil
}

func (d *Database) CreateUser(email, password, friendlyName string) (*UserRecord, error) {
	email = strings.TrimSpace(email)
	if friendlyName == "" {
		parts := strings.Split(email, "@")
		friendlyName = parts[0]
	}
	encPwd := EncryptPassword(password, d.secretKey)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec(`
		INSERT OR REPLACE INTO users (
			email, password, friendly_name, status, client_id,
			custom_message, msn_obj, created_at, last_seen
		) VALUES (?, ?, ?, 'FLN', '0', '', '', ?, ?);`,
		email, encPwd, friendlyName, now, now,
	)
	if err != nil {
		return nil, err
	}

	// Auto-add service bot to contacts if regular user
	serviceEmail := "system@msn.local"
	serviceName := "Служба сообщений MSN"
	if !strings.EqualFold(email, serviceEmail) {
		_, _ = d.db.Exec(`
			INSERT OR REPLACE INTO contacts (user_email, contact_email, list_flags, group_id, friendly_name, created_at)
			VALUES (?, ?, 11, 0, ?, ?);`, email, serviceEmail, serviceName, now)
		_, _ = d.db.Exec(`
			INSERT OR REPLACE INTO contacts (user_email, contact_email, list_flags, group_id, friendly_name, created_at)
			VALUES (?, ?, 8, 0, ?, ?);`, serviceEmail, email, friendlyName, now)
	}

	return &UserRecord{
		Email:        email,
		Password:     password,
		FriendlyName: friendlyName,
		Status:       "FLN",
		ClientID:     "0",
		CreatedAt:    now,
		LastSeen:     now,
	}, nil
}

func (d *Database) UpdateUserStatus(email, status string, clientID, customMessage, msnObj *string) error {
	email = strings.TrimSpace(email)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	var sets []string
	var args []interface{}

	sets = append(sets, "status = ?", "last_seen = ?")
	args = append(args, status, now)

	if clientID != nil {
		sets = append(sets, "client_id = ?")
		args = append(args, *clientID)
	}
	if customMessage != nil {
		sets = append(sets, "custom_message = ?")
		args = append(args, *customMessage)
	}
	if msnObj != nil {
		sets = append(sets, "msn_obj = ?")
		args = append(args, *msnObj)
	}

	args = append(args, email)
	query := fmt.Sprintf("UPDATE users SET %s WHERE email = ? COLLATE NOCASE;", strings.Join(sets, ", "))

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec(query, args...)
	return err
}

func (d *Database) UpdateFriendlyName(email, friendlyName string) error {
	email = strings.TrimSpace(email)
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec("UPDATE users SET friendly_name = ? WHERE email = ? COLLATE NOCASE;", friendlyName, email)
	return err
}

func (d *Database) UpdatePhone(email, propName, value string) error {
	email = strings.TrimSpace(email)
	colMap := map[string]string{
		"PHH": "phone_home",
		"PHW": "phone_work",
		"PHM": "phone_mobile",
	}
	col, ok := colMap[strings.ToUpper(propName)]
	if !ok {
		return nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	query := fmt.Sprintf("UPDATE users SET %s = ? WHERE email = ? COLLATE NOCASE;", col)
	_, err := d.db.Exec(query, value, email)
	return err
}

func (d *Database) UpdatePassword(email, newPassword string) error {
	email = strings.TrimSpace(email)
	enc := EncryptPassword(newPassword, d.secretKey)

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec("UPDATE users SET password = ? WHERE email = ? COLLATE NOCASE;", enc, email)
	return err
}

func (d *Database) GetAllUsers() ([]*UserRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT email, password, friendly_name, status, client_id, custom_message,
		       msn_obj, phone_home, phone_work, phone_mobile, created_at, last_seen,
		       banned_until, ban_reason, muted_until, mute_reason
		FROM users ORDER BY email ASC;`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*UserRecord
	for rows.Next() {
		var u UserRecord
		var rawPassword string
		err := rows.Scan(
			&u.Email, &rawPassword, &u.FriendlyName, &u.Status, &u.ClientID,
			&u.CustomMessage, &u.MSNObj, &u.PhoneHome, &u.PhoneWork, &u.PhoneMobile,
			&u.CreatedAt, &u.LastSeen, &u.BannedUntil, &u.BanReason, &u.MutedUntil, &u.MuteReason,
		)
		if err == nil {
			u.Password = DecryptPassword(rawPassword, d.secretKey)
			result = append(result, &u)
		}
	}
	return result, nil
}

type UserMetaRecord struct {
	Email         string `json:"email"`
	FriendlyName  string `json:"friendly_name"`
	Status        string `json:"status"`
	ClientID      string `json:"client_id"`
	CustomMessage string `json:"custom_message"`
	CreatedAt     string `json:"created_at"`
	LastSeen      string `json:"last_seen"`
	ContactCount  int    `json:"contact_count"`
	IsBanned      bool   `json:"is_banned"`
	BanRemaining  string `json:"ban_remaining"`
	BanReason     string `json:"ban_reason"`
	IsMuted       bool   `json:"is_muted"`
	MuteRemaining string `json:"mute_remaining"`
	MuteReason    string `json:"mute_reason"`
	IsOnline      bool   `json:"is_online"`
	LiveStatus    string `json:"live_status"`
	Peer          string `json:"peer"`
}

func (d *Database) GetAllUsersWithMeta() ([]*UserMetaRecord, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT u.email, u.friendly_name, u.status, u.client_id, u.custom_message,
		       u.created_at, u.last_seen, u.banned_until, u.ban_reason, u.muted_until, u.mute_reason,
		       (SELECT COUNT(*) FROM contacts c 
		        WHERE c.user_email = u.email AND (c.list_flags & 1) 
		          AND LOWER(c.contact_email) != LOWER('system@msn.local')) AS contact_count
		FROM users u 
		ORDER BY u.email ASC;`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	now := time.Now().UTC()
	var result []*UserMetaRecord

	for rows.Next() {
		var u UserMetaRecord
		var bUntil, bReason, mUntil, mReason sql.NullString
		err := rows.Scan(
			&u.Email, &u.FriendlyName, &u.Status, &u.ClientID, &u.CustomMessage,
			&u.CreatedAt, &u.LastSeen, &bUntil, &bReason, &mUntil, &mReason,
			&u.ContactCount,
		)
		if err != nil {
			continue
		}

		if bReason.Valid {
			u.BanReason = bReason.String
		}
		if mReason.Valid {
			u.MuteReason = mReason.String
		}

		if bUntil.Valid && bUntil.String != "" {
			if strings.EqualFold(bUntil.String, "permanent") {
				u.IsBanned = true
				u.BanRemaining = "навсегда"
			} else if t, err := time.Parse(time.RFC3339Nano, bUntil.String); err == nil {
				if t.After(now) {
					u.IsBanned = true
					u.BanRemaining = formatDurationRussian(t.Sub(now))
				}
			}
		}

		if mUntil.Valid && mUntil.String != "" {
			if strings.EqualFold(mUntil.String, "permanent") {
				u.IsMuted = true
				u.MuteRemaining = "навсегда"
			} else if t, err := time.Parse(time.RFC3339Nano, mUntil.String); err == nil {
				if t.After(now) {
					u.IsMuted = true
					u.MuteRemaining = formatDurationRussian(t.Sub(now))
				}
			}
		}

		result = append(result, &u)
	}

	return result, nil
}

func (d *Database) GetDatabaseStats() (map[string]interface{}, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	var totalUsers, totalContacts, totalGroups, pendingMessages, totalMessages int
	_ = d.db.QueryRow("SELECT COUNT(*) FROM users;").Scan(&totalUsers)
	_ = d.db.QueryRow("SELECT COUNT(*) FROM contacts;").Scan(&totalContacts)
	_ = d.db.QueryRow("SELECT COUNT(*) FROM groups;").Scan(&totalGroups)
	_ = d.db.QueryRow("SELECT COUNT(*) FROM offline_messages WHERE delivered = 0;").Scan(&pendingMessages)
	_ = d.db.QueryRow("SELECT COUNT(*) FROM offline_messages;").Scan(&totalMessages)

	var dbSizeBytes int64
	if fi, err := os.Stat(d.dbPath); err == nil {
		dbSizeBytes = fi.Size()
	}

	return map[string]interface{}{
		"total_users":              totalUsers,
		"total_contacts":           totalContacts,
		"total_groups":             totalGroups,
		"pending_offline_messages": pendingMessages,
		"total_offline_messages":   totalMessages,
		"db_size_bytes":            dbSizeBytes,
		"db_path":                  d.dbPath,
	}, nil
}

func (d *Database) DeleteUser(email string) error {
	email = strings.TrimSpace(email)
	d.mu.Lock()
	defer d.mu.Unlock()

	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, _ = tx.Exec("DELETE FROM users WHERE email = ? COLLATE NOCASE;", email)
	_, _ = tx.Exec("DELETE FROM contacts WHERE user_email = ? COLLATE NOCASE OR contact_email = ? COLLATE NOCASE;", email, email)
	_, _ = tx.Exec("DELETE FROM groups WHERE user_email = ? COLLATE NOCASE;", email)
	_, _ = tx.Exec("DELETE FROM offline_messages WHERE sender = ? COLLATE NOCASE OR recipient = ? COLLATE NOCASE;", email, email)

	return tx.Commit()
}

// Contact Management

func (d *Database) GetContacts(userEmail string) ([]*ContactRecord, error) {
	userEmail = strings.TrimSpace(userEmail)
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query(`
		SELECT user_email, contact_email, list_flags, group_id, friendly_name, created_at
		FROM contacts WHERE user_email = ? COLLATE NOCASE ORDER BY contact_email ASC;`, userEmail)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*ContactRecord
	for rows.Next() {
		var c ContactRecord
		if err := rows.Scan(&c.UserEmail, &c.ContactEmail, &c.ListFlags, &c.GroupID, &c.FriendlyName, &c.CreatedAt); err == nil {
			result = append(result, &c)
		}
	}
	return result, nil
}

func (d *Database) GetContact(userEmail, contactEmail string) (*ContactRecord, error) {
	userEmail = strings.TrimSpace(userEmail)
	contactEmail = strings.TrimSpace(contactEmail)
	d.mu.RLock()
	defer d.mu.RUnlock()

	row := d.db.QueryRow(`
		SELECT user_email, contact_email, list_flags, group_id, friendly_name, created_at
		FROM contacts WHERE user_email = ? COLLATE NOCASE AND contact_email = ? COLLATE NOCASE;`,
		userEmail, contactEmail)

	var c ContactRecord
	err := row.Scan(&c.UserEmail, &c.ContactEmail, &c.ListFlags, &c.GroupID, &c.FriendlyName, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (d *Database) AddOrUpdateContact(userEmail, contactEmail string, listFlag, groupID int, friendlyName string) (*ContactRecord, error) {
	userEmail = strings.TrimSpace(userEmail)
	contactEmail = strings.TrimSpace(contactEmail)
	friendlyName = strings.TrimSpace(friendlyName)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	d.mu.Lock()
	defer d.mu.Unlock()

	// 1. Update user's contact record
	existing, err := d.getContactNoLock(userEmail, contactEmail)
	if err != nil {
		return nil, err
	}

	newFlags := listFlag
	finalFname := friendlyName
	finalGroupID := groupID

	if existing != nil {
		newFlags = existing.ListFlags | listFlag
		if finalFname == "" {
			finalFname = existing.FriendlyName
		}
		if finalGroupID == 0 {
			finalGroupID = existing.GroupID
		}
		_, err = d.db.Exec(`
			UPDATE contacts SET list_flags = ?, group_id = ?, friendly_name = ?
			WHERE user_email = ? COLLATE NOCASE AND contact_email = ? COLLATE NOCASE;`,
			newFlags, finalGroupID, finalFname, userEmail, contactEmail)
	} else {
		_, err = d.db.Exec(`
			INSERT INTO contacts (user_email, contact_email, list_flags, group_id, friendly_name, created_at)
			VALUES (?, ?, ?, ?, ?, ?);`,
			userEmail, contactEmail, newFlags, finalGroupID, finalFname, now)
	}
	if err != nil {
		return nil, err
	}

	// 2. If adding to FL, add user to contact's RL (Reverse List)
	if listFlag&1 != 0 { // ListFL
		revContact, _ := d.getContactNoLock(contactEmail, userEmail)
		userRecord, _ := d.getUserNoLock(userEmail)
		uFname := ""
		if userRecord != nil {
			uFname = userRecord.FriendlyName
		}
		if revContact != nil {
			_, _ = d.db.Exec(`
				UPDATE contacts SET list_flags = list_flags | 8
				WHERE user_email = ? COLLATE NOCASE AND contact_email = ? COLLATE NOCASE;`,
				contactEmail, userEmail)
		} else {
			_, _ = d.db.Exec(`
				INSERT INTO contacts (user_email, contact_email, list_flags, group_id, friendly_name, created_at)
				VALUES (?, ?, 8, 0, ?, ?);`,
				contactEmail, userEmail, uFname, now)
		}
	}

	return &ContactRecord{
		UserEmail:    userEmail,
		ContactEmail: contactEmail,
		ListFlags:    newFlags,
		GroupID:      finalGroupID,
		FriendlyName: finalFname,
		CreatedAt:    now,
	}, nil
}

func (d *Database) getContactNoLock(userEmail, contactEmail string) (*ContactRecord, error) {
	row := d.db.QueryRow(`
		SELECT user_email, contact_email, list_flags, group_id, friendly_name, created_at
		FROM contacts WHERE user_email = ? COLLATE NOCASE AND contact_email = ? COLLATE NOCASE;`,
		userEmail, contactEmail)

	var c ContactRecord
	err := row.Scan(&c.UserEmail, &c.ContactEmail, &c.ListFlags, &c.GroupID, &c.FriendlyName, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &c, nil
}

func (d *Database) getUserNoLock(email string) (*UserRecord, error) {
	row := d.db.QueryRow("SELECT email, friendly_name FROM users WHERE email = ? COLLATE NOCASE;", email)
	var u UserRecord
	err := row.Scan(&u.Email, &u.FriendlyName)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &u, err
}

func (d *Database) RemoveContact(userEmail, contactEmail string, listFlag int) error {
	userEmail = strings.TrimSpace(userEmail)
	contactEmail = strings.TrimSpace(contactEmail)

	d.mu.Lock()
	defer d.mu.Unlock()

	c, err := d.getContactNoLock(userEmail, contactEmail)
	if err != nil || c == nil {
		return nil
	}

	newFlags := c.ListFlags & ^listFlag
	if newFlags <= 0 {
		_, err = d.db.Exec("DELETE FROM contacts WHERE user_email = ? COLLATE NOCASE AND contact_email = ? COLLATE NOCASE;", userEmail, contactEmail)
	} else {
		_, err = d.db.Exec("UPDATE contacts SET list_flags = ? WHERE user_email = ? COLLATE NOCASE AND contact_email = ? COLLATE NOCASE;", newFlags, userEmail, contactEmail)
	}

	// If removed from FL, remove from contact's RL
	if listFlag&1 != 0 {
		rev, _ := d.getContactNoLock(contactEmail, userEmail)
		if rev != nil {
			revFlags := rev.ListFlags & ^8
			if revFlags <= 0 {
				_, _ = d.db.Exec("DELETE FROM contacts WHERE user_email = ? COLLATE NOCASE AND contact_email = ? COLLATE NOCASE;", contactEmail, userEmail)
			} else {
				_, _ = d.db.Exec("UPDATE contacts SET list_flags = ? WHERE user_email = ? COLLATE NOCASE AND contact_email = ? COLLATE NOCASE;", revFlags, contactEmail, userEmail)
			}
		}
	}

	return err
}

func (d *Database) UpdateContactFriendlyName(userEmail, contactEmail, friendlyName string) error {
	userEmail = strings.TrimSpace(userEmail)
	contactEmail = strings.TrimSpace(contactEmail)

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec("UPDATE contacts SET friendly_name = ? WHERE user_email = ? COLLATE NOCASE AND contact_email = ? COLLATE NOCASE;", friendlyName, userEmail, contactEmail)
	return err
}

// Group Management

func (d *Database) GetGroups(userEmail string) ([]*GroupRecord, error) {
	userEmail = strings.TrimSpace(userEmail)
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query("SELECT id, user_email, name, created_at FROM groups WHERE user_email = ? COLLATE NOCASE ORDER BY id ASC;", userEmail)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*GroupRecord
	for rows.Next() {
		var g GroupRecord
		if err := rows.Scan(&g.ID, &g.UserEmail, &g.Name, &g.CreatedAt); err == nil {
			result = append(result, &g)
		}
	}
	return result, nil
}

func (d *Database) AddGroup(userEmail, name string) (*GroupRecord, error) {
	userEmail = strings.TrimSpace(userEmail)
	name = strings.TrimSpace(name)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	d.mu.Lock()
	defer d.mu.Unlock()

	res, err := d.db.Exec("INSERT INTO groups (user_email, name, created_at) VALUES (?, ?, ?);", userEmail, name, now)
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &GroupRecord{
		ID:        int(id),
		UserEmail: userEmail,
		Name:      name,
		CreatedAt: now,
	}, nil
}

func (d *Database) RenameGroup(userEmail string, groupID int, newName string) error {
	userEmail = strings.TrimSpace(userEmail)
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec("UPDATE groups SET name = ? WHERE id = ? AND user_email = ? COLLATE NOCASE;", newName, groupID, userEmail)
	return err
}

func (d *Database) RemoveGroup(userEmail string, groupID int) error {
	userEmail = strings.TrimSpace(userEmail)
	d.mu.Lock()
	defer d.mu.Unlock()

	_, err := d.db.Exec("DELETE FROM groups WHERE id = ? AND user_email = ? COLLATE NOCASE;", groupID, userEmail)
	if err == nil {
		_, _ = d.db.Exec("UPDATE contacts SET group_id = 0 WHERE group_id = ? AND user_email = ? COLLATE NOCASE;", groupID, userEmail)
	}
	return err
}

// Offline Messages

func (d *Database) SaveOfflineMessage(sender, recipient, message string) error {
	sender = strings.TrimSpace(sender)
	recipient = strings.TrimSpace(recipient)
	now := time.Now().UTC().Format(time.RFC3339Nano)

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec("INSERT INTO offline_messages (sender, recipient, message, timestamp, delivered) VALUES (?, ?, ?, ?, 0);",
		sender, recipient, message, now)
	return err
}

func (d *Database) GetPendingOfflineMessages(recipient string) ([]*OfflineMessageRecord, error) {
	recipient = strings.TrimSpace(recipient)
	d.mu.RLock()
	defer d.mu.RUnlock()

	rows, err := d.db.Query("SELECT id, sender, recipient, message, timestamp, delivered FROM offline_messages WHERE recipient = ? COLLATE NOCASE AND delivered = 0 ORDER BY id ASC;", recipient)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []*OfflineMessageRecord
	for rows.Next() {
		var m OfflineMessageRecord
		if err := rows.Scan(&m.ID, &m.Sender, &m.Recipient, &m.Message, &m.Timestamp, &m.Delivered); err == nil {
			result = append(result, &m)
		}
	}
	return result, nil
}

func (d *Database) MarkOfflineMessagesDelivered(recipient string) error {
	recipient = strings.TrimSpace(recipient)
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec("UPDATE offline_messages SET delivered = 1 WHERE recipient = ? COLLATE NOCASE;", recipient)
	return err
}

// Penalty Management (Ban & Mute)

func (d *Database) BanUser(email string, durationMinutes int, reason string) error {
	email = strings.TrimSpace(email)
	var bannedUntilStr string
	if durationMinutes > 0 {
		bannedUntilStr = time.Now().UTC().Add(time.Duration(durationMinutes) * time.Minute).Format(time.RFC3339Nano)
	} else {
		bannedUntilStr = "permanent"
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec("UPDATE users SET banned_until = ?, ban_reason = ? WHERE email = ? COLLATE NOCASE;", bannedUntilStr, reason, email)
	return err
}

func (d *Database) UnbanUser(email string) error {
	email = strings.TrimSpace(email)
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec("UPDATE users SET banned_until = '', ban_reason = '' WHERE email = ? COLLATE NOCASE;", email)
	return err
}

func (d *Database) MuteUser(email string, durationMinutes int, reason string) error {
	email = strings.TrimSpace(email)
	var mutedUntilStr string
	if durationMinutes > 0 {
		mutedUntilStr = time.Now().UTC().Add(time.Duration(durationMinutes) * time.Minute).Format(time.RFC3339Nano)
	} else {
		mutedUntilStr = "permanent"
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec("UPDATE users SET muted_until = ?, mute_reason = ? WHERE email = ? COLLATE NOCASE;", mutedUntilStr, reason, email)
	return err
}

func (d *Database) UnmuteUser(email string) error {
	email = strings.TrimSpace(email)
	d.mu.Lock()
	defer d.mu.Unlock()
	_, err := d.db.Exec("UPDATE users SET muted_until = '', mute_reason = '' WHERE email = ? COLLATE NOCASE;", email)
	return err
}

func (d *Database) GetUserPenaltyStatus(email string) (*PenaltyStatus, error) {
	u, err := d.GetUser(email)
	if err != nil || u == nil {
		return &PenaltyStatus{}, nil
	}

	res := &PenaltyStatus{
		BanReason:  u.BanReason,
		MuteReason: u.MuteReason,
	}

	now := time.Now().UTC()

	// Check ban
	if u.BannedUntil != "" {
		if strings.EqualFold(u.BannedUntil, "permanent") {
			res.IsBanned = true
			res.BanRemaining = "навсегда"
		} else if t, err := time.Parse(time.RFC3339Nano, u.BannedUntil); err == nil {
			if t.After(now) {
				res.IsBanned = true
				diff := t.Sub(now)
				res.BanRemaining = formatDurationRussian(diff)
			} else {
				// Expired, clear
				_ = d.UnbanUser(email)
			}
		}
	}

	// Check mute
	if u.MutedUntil != "" {
		if strings.EqualFold(u.MutedUntil, "permanent") {
			res.IsMuted = true
			res.MuteRemaining = "навсегда"
		} else if t, err := time.Parse(time.RFC3339Nano, u.MutedUntil); err == nil {
			if t.After(now) {
				res.IsMuted = true
				diff := t.Sub(now)
				res.MuteRemaining = formatDurationRussian(diff)
			} else {
				// Expired, clear
				_ = d.UnmuteUser(email)
			}
		}
	}

	return res, nil
}

func formatDurationRussian(d time.Duration) string {
	mins := int(d.Minutes())
	if mins <= 0 {
		return "меньше минуты"
	}
	hours := mins / 60
	remMins := mins % 60
	if hours > 0 {
		return fmt.Sprintf("%d ч %d мин", hours, remMins)
	}
	return fmt.Sprintf("%d мин", remMins)
}
