"""
SQLite database manager for MSNP Server.
Manages database.db schemas, queries, and transactions.
"""
import contextlib
import datetime
import os
import sqlite3
import threading
from typing import Optional, List, Dict, Any

from .models import UserRecord, ContactRecord, GroupRecord, OfflineMessageRecord


class Database:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._lock = threading.Lock()
        self.init_db()

    @contextlib.contextmanager
    def _connection(self):
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        try:
            yield conn
        finally:
            conn.close()

    def init_db(self) -> None:
        """Initialize all tables in database.db"""
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                
                # Users table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
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
                );
                """)

                for col in ["banned_until", "ban_reason", "muted_until", "mute_reason"]:
                    try:
                        cursor.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT '';")
                    except sqlite3.OperationalError:
                        pass

                # Contacts table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS contacts (
                    user_email TEXT NOT NULL COLLATE NOCASE,
                    contact_email TEXT NOT NULL COLLATE NOCASE,
                    list_flags INTEGER DEFAULT 1,
                    group_id INTEGER DEFAULT 0,
                    friendly_name TEXT DEFAULT '',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (user_email, contact_email)
                );
                """)

                # Groups table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS groups (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_email TEXT NOT NULL COLLATE NOCASE,
                    name TEXT NOT NULL
                );
                """)

                # Offline messages table
                cursor.execute("""
                CREATE TABLE IF NOT EXISTS offline_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender TEXT NOT NULL COLLATE NOCASE,
                    recipient TEXT NOT NULL COLLATE NOCASE,
                    message TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    delivered INTEGER DEFAULT 0
                );
                """)
                
                conn.commit()

    # User Management
    def get_user(self, email: str) -> Optional[UserRecord]:
        email = email.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE email = ?;", (email,))
                row = cursor.fetchone()
                if not row:
                    return None
                return UserRecord(
                    email=row["email"],
                    password=row["password"],
                    friendly_name=row["friendly_name"],
                    status=row["status"],
                    client_id=row["client_id"],
                    custom_message=row["custom_message"],
                    msn_obj=row["msn_obj"],
                    phone_home=row["phone_home"],
                    phone_work=row["phone_work"],
                    phone_mobile=row["phone_mobile"],
                    created_at=str(row["created_at"]),
                    last_seen=str(row["last_seen"]),
                )

    def create_user(self, email: str, password: str, friendly_name: Optional[str] = None) -> UserRecord:
        email = email.strip()
        friendly_name = friendly_name.strip() if friendly_name else email.split("@")[0]
        now = datetime.datetime.utcnow().isoformat()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT OR REPLACE INTO users (
                    email, password, friendly_name, status, client_id,
                    custom_message, msn_obj, created_at, last_seen
                ) VALUES (?, ?, ?, 'FLN', '0', '', '', ?, ?);
                """, (email, password, friendly_name, now, now))

                # If this is a regular user, automatically add the service bot to user's contacts
                try:
                    import config
                    service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
                    service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")
                    auto_add = getattr(config, "AUTO_ADD_SERVICE_CONTACT", True)
                except Exception:
                    service_email = "system@msn.local"
                    service_name = "Служба сообщений MSN"
                    auto_add = True

                if auto_add and email.lower() != service_email.lower():
                    cursor.execute("""
                    INSERT OR REPLACE INTO contacts (user_email, contact_email, list_flags, group_id, friendly_name, created_at)
                    VALUES (?, ?, 11, 0, ?, ?);
                    """, (email, service_email, service_name, now))
                    cursor.execute("""
                    INSERT OR REPLACE INTO contacts (user_email, contact_email, list_flags, group_id, friendly_name, created_at)
                    VALUES (?, ?, 8, 0, ?, ?);
                    """, (service_email, email, friendly_name, now))

                conn.commit()
        return self.get_user(email)  # type: ignore

    def update_user_status(self, email: str, status: str, client_id: Optional[str] = None,
                           custom_message: Optional[str] = None, msn_obj: Optional[str] = None) -> None:
        email = email.strip()
        now = datetime.datetime.utcnow().isoformat()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                updates = ["status = ?", "last_seen = ?"]
                params: List[Any] = [status, now]

                if client_id is not None:
                    updates.append("client_id = ?")
                    params.append(client_id)
                if custom_message is not None:
                    updates.append("custom_message = ?")
                    params.append(custom_message)
                if msn_obj is not None:
                    updates.append("msn_obj = ?")
                    params.append(msn_obj)

                params.append(email)
                query = f"UPDATE users SET {', '.join(updates)} WHERE email = ?;"
                cursor.execute(query, params)
                conn.commit()

    def update_friendly_name(self, email: str, friendly_name: str) -> None:
        email = email.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET friendly_name = ? WHERE email = ?;", (friendly_name, email))
                conn.commit()

    def update_phone(self, email: str, phone_type: str, number: str) -> None:
        email = email.strip()
        col_map = {
            "PHH": "phone_home",
            "PHW": "phone_work",
            "PHM": "phone_mobile",
            "MOB": "phone_mobile",
        }
        col = col_map.get(phone_type.upper())
        if not col:
            return
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute(f"UPDATE users SET {col} = ? WHERE email = ?;", (number, email))
                conn.commit()

    def update_password(self, email: str, new_password: str) -> bool:
        email = email.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET password = ? WHERE email = ?;", (new_password, email))
                conn.commit()
                return cursor.rowcount > 0

    def delete_user(self, email: str) -> bool:
        email = email.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM users WHERE email = ?;", (email,))
                user_deleted = cursor.rowcount > 0
                cursor.execute("DELETE FROM contacts WHERE user_email = ? OR contact_email = ?;", (email, email))
                cursor.execute("DELETE FROM groups WHERE user_email = ?;", (email,))
                cursor.execute("DELETE FROM offline_messages WHERE sender = ? OR recipient = ?;", (email, email))
                conn.commit()
                return user_deleted

    def ensure_service_account(self, email: str, name: str) -> UserRecord:
        email = email.strip()
        user = self.get_user(email)
        if not user:
            user = self.create_user(email, "system_service_internal_password", name)
        else:
            if user.friendly_name != name:
                self.update_friendly_name(email, name)

        # Automatically ensure the service account is in the contact list of all registered users
        try:
            import config
            auto_add = getattr(config, "AUTO_ADD_SERVICE_CONTACT", True)
        except Exception:
            auto_add = True

        if auto_add:
            with self._lock:
                with self._connection() as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT email FROM users WHERE LOWER(email) != LOWER(?);", (email,))
                    other_users = [r["email"] for r in cursor.fetchall()]
                    now = datetime.datetime.utcnow().isoformat()
                    for u_email in other_users:
                        cursor.execute("SELECT list_flags FROM contacts WHERE user_email = ? AND contact_email = ?;", (u_email, email))
                        c_row = cursor.fetchone()
                        if c_row:
                            new_flags = c_row["list_flags"] | 11  # FL (1) | AL (2) | RL (8)
                            cursor.execute("UPDATE contacts SET list_flags = ?, friendly_name = ? WHERE user_email = ? AND contact_email = ?;",
                                           (new_flags, name, u_email, email))
                        else:
                            cursor.execute("INSERT INTO contacts (user_email, contact_email, list_flags, group_id, friendly_name, created_at) VALUES (?, ?, 11, 0, ?, ?);",
                                           (u_email, email, name, now))

                        # Also reverse list for service account
                        cursor.execute("SELECT list_flags FROM contacts WHERE user_email = ? AND contact_email = ?;", (email, u_email))
                        rev_row = cursor.fetchone()
                        if rev_row:
                            rev_flags = rev_row["list_flags"] | 8
                            cursor.execute("UPDATE contacts SET list_flags = ? WHERE user_email = ? AND contact_email = ?;",
                                           (rev_flags, email, u_email))
                        else:
                            cursor.execute("INSERT INTO contacts (user_email, contact_email, list_flags, group_id, friendly_name, created_at) VALUES (?, ?, 8, 0, ?, ?);",
                                           (email, u_email, u_email.split("@")[0], now))
                    conn.commit()

        return user

    @staticmethod
    def _format_remaining_time(until_str: str) -> Optional[str]:
        if not until_str:
            return None
        if until_str.startswith("9999"):
            return "Бессрочно (Навсегда)"
        try:
            until_dt = datetime.datetime.fromisoformat(until_str)
            now = datetime.datetime.utcnow()
            diff = until_dt - now
            total_seconds = int(round(diff.total_seconds()))
            if total_seconds <= 0:
                return None  # Expired
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            minutes = (total_seconds % 3600) // 60
            parts = []
            if days > 0:
                parts.append(f"{days} дн.")
            if hours > 0:
                parts.append(f"{hours} ч.")
            if minutes > 0 or not parts:
                parts.append(f"{max(1, minutes)} мин.")
            return " ".join(parts)
        except Exception:
            return None

    def ban_user(self, email: str, duration_minutes: Optional[int], reason: str = "") -> None:
        email = email.strip()
        now = datetime.datetime.utcnow()
        if duration_minutes is None:
            banned_until = "9999-12-31T23:59:59"
        else:
            banned_until = (now + datetime.timedelta(minutes=duration_minutes)).isoformat()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET banned_until = ?, ban_reason = ? WHERE email = ?;",
                               (banned_until, reason, email))
                conn.commit()

    def unban_user(self, email: str) -> bool:
        email = email.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET banned_until = '', ban_reason = '' WHERE email = ?;", (email,))
                conn.commit()
                return cursor.rowcount > 0

    def mute_user(self, email: str, duration_minutes: Optional[int], reason: str = "") -> None:
        email = email.strip()
        now = datetime.datetime.utcnow()
        if duration_minutes is None:
            muted_until = "9999-12-31T23:59:59"
        else:
            muted_until = (now + datetime.timedelta(minutes=duration_minutes)).isoformat()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET muted_until = ?, mute_reason = ? WHERE email = ?;",
                               (muted_until, reason, email))
                conn.commit()

    def unmute_user(self, email: str) -> bool:
        email = email.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE users SET muted_until = '', mute_reason = '' WHERE email = ?;", (email,))
                conn.commit()
                return cursor.rowcount > 0

    def get_user_penalty_status(self, email: str) -> Dict[str, Any]:
        email = email.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT banned_until, ban_reason, muted_until, mute_reason FROM users WHERE email = ?;", (email,))
                row = cursor.fetchone()
                if not row:
                    return {
                        "is_banned": False, "ban_remaining": "", "ban_reason": "",
                        "is_muted": False, "mute_remaining": "", "mute_reason": ""
                    }
                banned_until = row["banned_until"] or ""
                ban_reason = row["ban_reason"] or ""
                muted_until = row["muted_until"] or ""
                mute_reason = row["mute_reason"] or ""

                ban_rem = self._format_remaining_time(banned_until)
                if banned_until and not ban_rem:
                    cursor.execute("UPDATE users SET banned_until = '', ban_reason = '' WHERE email = ?;", (email,))
                    conn.commit()
                    banned_until = ""
                    ban_reason = ""

                mute_rem = self._format_remaining_time(muted_until)
                if muted_until and not mute_rem:
                    cursor.execute("UPDATE users SET muted_until = '', mute_reason = '' WHERE email = ?;", (email,))
                    conn.commit()
                    muted_until = ""
                    mute_reason = ""

                return {
                    "is_banned": bool(ban_rem),
                    "ban_remaining": ban_rem or "",
                    "ban_reason": ban_reason,
                    "is_muted": bool(mute_rem),
                    "mute_remaining": mute_rem or "",
                    "mute_reason": mute_reason,
                }

    def get_all_users_with_meta(self) -> List[Dict[str, Any]]:
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                SELECT u.*, 
                       (SELECT COUNT(*) FROM contacts c 
                        WHERE c.user_email = u.email AND (c.list_flags & 1) 
                          AND LOWER(c.contact_email) != LOWER('system@msn.local')) AS contact_count
                FROM users u 
                ORDER BY u.email ASC;
                """)
                rows = cursor.fetchall()
                results = []
                for r in rows:
                    b_until = r["banned_until"] or ""
                    b_reason = r["ban_reason"] or ""
                    m_until = r["muted_until"] or ""
                    m_reason = r["mute_reason"] or ""

                    ban_rem = self._format_remaining_time(b_until)
                    if b_until and not ban_rem:
                        cursor.execute("UPDATE users SET banned_until = '', ban_reason = '' WHERE email = ?;", (r["email"],))
                        b_reason = ""

                    mute_rem = self._format_remaining_time(m_until)
                    if m_until and not mute_rem:
                        cursor.execute("UPDATE users SET muted_until = '', mute_reason = '' WHERE email = ?;", (r["email"],))
                        m_reason = ""

                    results.append({
                        "email": r["email"],
                        "friendly_name": r["friendly_name"] or "",
                        "status": r["status"] or "FLN",
                        "client_id": r["client_id"] or "0",
                        "custom_message": r["custom_message"] or "",
                        "created_at": str(r["created_at"]) if r["created_at"] else "",
                        "last_seen": str(r["last_seen"]) if r["last_seen"] else "",
                        "contact_count": int(r["contact_count"] or 0),
                        "is_banned": bool(ban_rem),
                        "ban_remaining": ban_rem or "",
                        "ban_reason": b_reason,
                        "is_muted": bool(mute_rem),
                        "mute_remaining": mute_rem or "",
                        "mute_reason": m_reason,
                    })
                conn.commit()
                return results

    def get_database_stats(self) -> Dict[str, Any]:
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM users;")
                total_users = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM contacts;")
                total_contacts = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM groups;")
                total_groups = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM offline_messages WHERE delivered = 0;")
                pending_messages = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM offline_messages;")
                total_messages = cursor.fetchone()[0]

                db_size_bytes = 0
                try:
                    if os.path.exists(self.db_path):
                        db_size_bytes = os.path.getsize(self.db_path)
                except Exception:
                    pass

                return {
                    "total_users": total_users,
                    "total_contacts": total_contacts,
                    "total_groups": total_groups,
                    "pending_offline_messages": pending_messages,
                    "total_offline_messages": total_messages,
                    "db_size_bytes": db_size_bytes,
                    "db_path": self.db_path,
                }

    def get_all_users(self) -> List[UserRecord]:
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users ORDER BY email ASC;")
                rows = cursor.fetchall()
                return [
                    UserRecord(
                        email=r["email"],
                        password=r["password"],
                        friendly_name=r["friendly_name"],
                        status=r["status"],
                        client_id=r["client_id"],
                        custom_message=r["custom_message"],
                        msn_obj=r["msn_obj"],
                        phone_home=r["phone_home"],
                        phone_work=r["phone_work"],
                        phone_mobile=r["phone_mobile"],
                        created_at=str(r["created_at"]),
                        last_seen=str(r["last_seen"]),
                    )
                    for r in rows
                ]

    # Contact Management
    def get_contacts(self, user_email: str) -> List[ContactRecord]:
        user_email = user_email.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM contacts WHERE user_email = ?;", (user_email,))
                rows = cursor.fetchall()
                return [
                    ContactRecord(
                        user_email=r["user_email"],
                        contact_email=r["contact_email"],
                        list_flags=r["list_flags"],
                        group_id=r["group_id"],
                        friendly_name=r["friendly_name"],
                        created_at=str(r["created_at"]),
                    )
                    for r in rows
                ]

    def get_contact(self, user_email: str, contact_email: str) -> Optional[ContactRecord]:
        user_email = user_email.strip()
        contact_email = contact_email.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM contacts WHERE user_email = ? AND contact_email = ?;", (user_email, contact_email))
                r = cursor.fetchone()
                if not r:
                    return None
                return ContactRecord(
                    user_email=r["user_email"],
                    contact_email=r["contact_email"],
                    list_flags=r["list_flags"],
                    group_id=r["group_id"],
                    friendly_name=r["friendly_name"],
                    created_at=str(r["created_at"]),
                )

    def add_or_update_contact(self, user_email: str, contact_email: str, add_flag: int,
                              group_id: int = 0, friendly_name: Optional[str] = None) -> ContactRecord:
        """
        Adds or updates contact in user's list.
        Flags: 1=FL, 2=AL, 4=BL, 8=RL, 16=PL
        """
        user_email = user_email.strip()
        contact_email = contact_email.strip()
        now = datetime.datetime.utcnow().isoformat()

        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT list_flags, friendly_name, group_id FROM contacts WHERE user_email = ? AND contact_email = ?;",
                               (user_email, contact_email))
                r = cursor.fetchone()
                if r:
                    current_flags = r["list_flags"]
                    new_flags = current_flags | add_flag
                    # If adding to FL, also ensure AL (Allow) is set and BL (Block) is cleared
                    if add_flag & 1:
                        new_flags |= 2
                        new_flags &= ~4
                    elif add_flag == 2:  # AL
                        new_flags &= ~4
                    elif add_flag == 4:  # BL
                        new_flags &= ~2
                    
                    fname = friendly_name if (friendly_name is not None and friendly_name != "") else r["friendly_name"]
                    gid = group_id if (add_flag & 1 or group_id != 0) else r["group_id"]
                    cursor.execute("""
                    UPDATE contacts SET list_flags = ?, friendly_name = ?, group_id = ?
                    WHERE user_email = ? AND contact_email = ?;
                    """, (new_flags, fname, gid, user_email, contact_email))
                else:
                    flags = add_flag
                    # By default, adding to FL also allows the contact (AL)
                    if add_flag & 1:
                        flags |= 2
                    fname = friendly_name or contact_email.split("@")[0]
                    cursor.execute("""
                    INSERT INTO contacts (user_email, contact_email, list_flags, group_id, friendly_name, created_at)
                    VALUES (?, ?, ?, ?, ?, ?);
                    """, (user_email, contact_email, flags, group_id, fname, now))

                # Bidirectional relationship: If user adds contact to FL (flag 1),
                # the contact must have the user on their RL (flag 8)
                if add_flag & 1:
                    cursor.execute("SELECT list_flags, friendly_name, group_id FROM contacts WHERE user_email = ? AND contact_email = ?;",
                                   (contact_email, user_email))
                    rev = cursor.fetchone()
                    user_record = self._get_user_unlocked(conn, user_email)
                    user_display = user_record.friendly_name if user_record else user_email.split("@")[0]

                    if rev:
                        rev_flags = rev["list_flags"] | 8  # Add RL
                        cursor.execute("""
                        UPDATE contacts SET list_flags = ? WHERE user_email = ? AND contact_email = ?;
                        """, (rev_flags, contact_email, user_email))
                    else:
                        cursor.execute("""
                        INSERT INTO contacts (user_email, contact_email, list_flags, group_id, friendly_name, created_at)
                        VALUES (?, ?, 8, 0, ?, ?);
                        """, (contact_email, user_email, user_display, now))

                conn.commit()

        return self.get_contact(user_email, contact_email)  # type: ignore

    def _get_user_unlocked(self, conn: sqlite3.Connection, email: str) -> Optional[UserRecord]:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?;", (email,))
        row = cursor.fetchone()
        if not row:
            return None
        return UserRecord(
            email=row["email"],
            password=row["password"],
            friendly_name=row["friendly_name"],
            status=row["status"],
            client_id=row["client_id"],
            custom_message=row["custom_message"],
            msn_obj=row["msn_obj"],
            phone_home=row["phone_home"],
            phone_work=row["phone_work"],
            phone_mobile=row["phone_mobile"],
            created_at=str(row["created_at"]),
            last_seen=str(row["last_seen"]),
        )

    def remove_contact_flag(self, user_email: str, contact_email: str, rem_flag: int) -> Optional[ContactRecord]:
        user_email = user_email.strip()
        contact_email = contact_email.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT list_flags FROM contacts WHERE user_email = ? AND contact_email = ?;",
                               (user_email, contact_email))
                r = cursor.fetchone()
                if not r:
                    return None
                new_flags = r["list_flags"] & ~rem_flag
                if new_flags == 0:
                    cursor.execute("DELETE FROM contacts WHERE user_email = ? AND contact_email = ?;",
                                   (user_email, contact_email))
                else:
                    cursor.execute("UPDATE contacts SET list_flags = ? WHERE user_email = ? AND contact_email = ?;",
                                   (new_flags, user_email, contact_email))
                
                # If removed from FL, also remove from contact's RL
                if rem_flag == 1:
                    cursor.execute("SELECT list_flags FROM contacts WHERE user_email = ? AND contact_email = ?;",
                                   (contact_email, user_email))
                    rev = cursor.fetchone()
                    if rev:
                        rev_flags = rev["list_flags"] & ~8
                        if rev_flags == 0:
                            cursor.execute("DELETE FROM contacts WHERE user_email = ? AND contact_email = ?;",
                                           (contact_email, user_email))
                        else:
                            cursor.execute("UPDATE contacts SET list_flags = ? WHERE user_email = ? AND contact_email = ?;",
                                           (rev_flags, contact_email, user_email))

                conn.commit()
        return self.get_contact(user_email, contact_email)

    def update_contact_friendly_name(self, user_email: str, contact_email: str, friendly_name: str) -> None:
        user_email = user_email.strip()
        contact_email = contact_email.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE contacts SET friendly_name = ? WHERE user_email = ? AND contact_email = ?;",
                               (friendly_name, user_email, contact_email))
                conn.commit()

    # Group Management
    def get_groups(self, user_email: str) -> List[GroupRecord]:
        user_email = user_email.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM groups WHERE user_email = ? ORDER BY id ASC;", (user_email,))
                rows = cursor.fetchall()
                return [GroupRecord(id=r["id"], user_email=r["user_email"], name=r["name"]) for r in rows]

    def add_group(self, user_email: str, name: str) -> GroupRecord:
        user_email = user_email.strip()
        name = name.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("INSERT INTO groups (user_email, name) VALUES (?, ?);", (user_email, name))
                gid = cursor.lastrowid
                conn.commit()
                return GroupRecord(id=gid, user_email=user_email, name=name)

    def remove_group(self, user_email: str, group_id: int) -> bool:
        user_email = user_email.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM groups WHERE id = ? AND user_email = ?;", (group_id, user_email))
                # Reset group_id for contacts in this group
                cursor.execute("UPDATE contacts SET group_id = 0 WHERE user_email = ? AND group_id = ?;",
                               (user_email, group_id))
                conn.commit()
                return cursor.rowcount > 0

    def rename_group(self, user_email: str, group_id: int, new_name: str) -> bool:
        user_email = user_email.strip()
        new_name = new_name.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE groups SET name = ? WHERE id = ? AND user_email = ?;",
                               (new_name, group_id, user_email))
                conn.commit()
                return cursor.rowcount > 0

    # Offline Messages
    def save_offline_message(self, sender: str, recipient: str, message: str) -> int:
        sender = sender.strip()
        recipient = recipient.strip()
        now = datetime.datetime.utcnow().isoformat()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                INSERT INTO offline_messages (sender, recipient, message, timestamp, delivered)
                VALUES (?, ?, ?, ?, 0);
                """, (sender, recipient, message, now))
                msg_id = cursor.lastrowid
                conn.commit()
                return msg_id

    def get_pending_offline_messages(self, recipient: str) -> List[OfflineMessageRecord]:
        recipient = recipient.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM offline_messages WHERE recipient = ? AND delivered = 0 ORDER BY timestamp ASC;",
                               (recipient,))
                rows = cursor.fetchall()
                return [
                    OfflineMessageRecord(
                        id=r["id"],
                        sender=r["sender"],
                        recipient=r["recipient"],
                        message=r["message"],
                        timestamp=str(r["timestamp"]),
                        delivered=r["delivered"],
                    )
                    for r in rows
                ]

    def mark_offline_messages_delivered(self, recipient: str) -> None:
        recipient = recipient.strip()
        with self._lock:
            with self._connection() as conn:
                cursor = conn.cursor()
                cursor.execute("UPDATE offline_messages SET delivered = 1 WHERE recipient = ?;", (recipient,))
                conn.commit()
