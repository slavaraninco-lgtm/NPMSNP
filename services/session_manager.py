"""
Session Manager for MSNP Notification Server (NS).
Manages connected users, presence tracking, and cross-session routing (RNG, NLN, FLN).
"""
import logging
from typing import Dict, Optional, List, Set, Any, TYPE_CHECKING

from db.database import Database
from protocol.constants import ListMask, UserStatus

if TYPE_CHECKING:
    from protocol.ns_handler import NSClientHandler

logger = logging.getLogger("MSNP.SessionManager")


class SessionManager:
    def __init__(self, db: Database):
        self.db = db
        # Active sessions: email (lowercase) -> NSClientHandler
        self._active_sessions: Dict[str, "NSClientHandler"] = {}

    def register_session(self, email: str, handler: "NSClientHandler") -> None:
        """Registers an authenticated active NS session."""
        email_key = email.lower()
        if email_key in self._active_sessions:
            old_handler = self._active_sessions[email_key]
            if old_handler is not handler:
                logger.info(f"Duplicate login for {email}; disconnecting older session.")
                try:
                    old_handler.send_error(207)  # Other session logged in
                    old_handler.close()
                except Exception:
                    pass

        self._active_sessions[email_key] = handler
        logger.info(f"User {email} registered in SessionManager. Active count: {len(self._active_sessions)}")

    def unregister_session(self, email: str, handler: "NSClientHandler") -> None:
        """Removes a session upon disconnect."""
        email_key = email.lower()
        if email_key in self._active_sessions and self._active_sessions[email_key] is handler:
            del self._active_sessions[email_key]
            logger.info(f"User {email} unregistered from SessionManager. Active count: {len(self._active_sessions)}")
            # Broadcast offline presence (FLN) to contacts
            self.broadcast_offline(email)

    def get_session(self, email: str) -> Optional["NSClientHandler"]:
        """Gets active session handler for user."""
        return self._active_sessions.get(email.lower())

    def is_online(self, email: str) -> bool:
        """Checks if a user is currently online (and not hidden)."""
        try:
            import config
            service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
        except Exception:
            service_email = "system@msn.local"

        if email.lower() == service_email.lower():
            return True

        session = self.get_session(email)
        if not session:
            return False
        return session.status != UserStatus.OFFLINE and session.status != UserStatus.HIDDEN

    def disconnect_user(self, email: str) -> bool:
        """Forces disconnect of an active user session."""
        session = self.get_session(email)
        if session:
            try:
                session.send_error(207)  # Other session logged in / forced disconnect
                session.close()
            except Exception:
                pass
            return True
        return False

    def send_system_notification(self, email: str, message: str, sender_email: str = "system@msn.local", sender_name: str = "Служба сообщений MSN") -> bool:
        """Sends an instant notification over NS if user is connected."""
        session = self.get_session(email)
        if session:
            prefix = f"[{sender_name}]:\r\n"
            body_text = message if message.startswith(f"[{sender_name}]:") else f"{prefix}{message}\r\n"
            payload = (
                "MIME-Version: 1.0\r\n"
                "Content-Type: text/plain; charset=UTF-8\r\n"
                "X-MMS-IM-Format: FN=Tahoma; EF=; CO=0; CS=0; PF=0\r\n\r\n"
                f"{body_text}"
            ).encode("utf-8")
            try:
                session.send_cmd("MSG", sender_email, sender_name, payload=payload)
                return True
            except Exception as ex:
                logger.warning(f"Failed to send NS notification to {email}: {ex}")
        return False

    def broadcast_system_notification(self, message: str, sender_email: str = "system@msn.local", sender_name: str = "Служба сообщений MSN") -> int:
        """Sends notification to all active NS sessions."""
        count = 0
        for email in list(self._active_sessions.keys()):
            if self.send_system_notification(email, message, sender_email, sender_name):
                count += 1
        return count

    def get_active_users_count(self) -> int:
        return len(self._active_sessions)

    def get_active_users_list(self) -> List[Dict[str, Any]]:
        result = []
        for email, sess in self._active_sessions.items():
            result.append({
                "email": sess.email,
                "friendly_name": sess.friendly_name,
                "status": sess.status,
                "client_id": sess.client_id,
                "custom_message": sess.custom_message,
                "peer": sess.peername,
            })
        return result

    # Presence Distribution
    def send_initial_presence(self, handler: "NSClientHandler", trid: str = "1") -> None:
        """
        Sends initial presence (ILN) of all online contacts in user's FL.
        Called after user sends CHG.
        """
        user_email = handler.email
        contacts = self.db.get_contacts(user_email)

        try:
            import config
            service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
            service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")
        except Exception:
            service_email = "system@msn.local"
            service_name = "Служба сообщений MSN"

        bot_sent = False
        for c in contacts:
            # Check if contact is on user's Forward List (FL)
            if c.list_flags & ListMask.FL:
                if c.contact_email.lower() == service_email.lower():
                    handler.send_iln(
                        trid,
                        UserStatus.ONLINE,
                        service_email,
                        c.friendly_name or service_name,
                        "0",
                        ""
                    )
                    bot_sent = True
                    continue

                contact_session = self.get_session(c.contact_email)
                if contact_session and contact_session.status != UserStatus.OFFLINE and contact_session.status != UserStatus.HIDDEN:
                    # Check that contact hasn't blocked the user
                    contact_record = self.db.get_contact(c.contact_email, user_email)
                    if not (contact_record and (contact_record.list_flags & ListMask.BL)):
                        handler.send_iln(
                            trid,
                            contact_session.status,
                            contact_session.email,
                            contact_session.friendly_name,
                            contact_session.client_id,
                            contact_session.msn_obj
                        )

    def broadcast_status_change(self, handler: "NSClientHandler") -> None:
        """
        Broadcasts status change (NLN or FLN if hidden) to all online contacts who have
        this user on their Reverse List (RL).
        """
        user_email = handler.email
        status = handler.status
        friendly_name = handler.friendly_name
        client_id = handler.client_id
        msn_obj = handler.msn_obj

        # If user is changing to HIDDEN, to other contacts they look OFFLINE (FLN)
        effective_status = UserStatus.OFFLINE if status == UserStatus.HIDDEN else status

        # Get all users who have this user on their contacts list
        # We query contacts where contact_email == user_email and list_flags & RL
        for contact_email, sess in self._active_sessions.items():
            if contact_email == user_email.lower():
                continue

            # Check if contact_email has user_email in their FL
            c = self.db.get_contact(sess.email, user_email)
            if c and (c.list_flags & ListMask.FL):
                # Check that user hasn't blocked this contact
                user_contact = self.db.get_contact(user_email, sess.email)
                if user_contact and (user_contact.list_flags & ListMask.BL):
                    # Blocked: send FLN
                    sess.send_fln(user_email)
                elif effective_status == UserStatus.OFFLINE:
                    sess.send_fln(user_email)
                else:
                    sess.send_nln(effective_status, user_email, friendly_name, client_id, msn_obj)

    def broadcast_friendly_name_change(self, user_email: str, new_friendly_name: str) -> None:
        """Broadcasts updated friendly name to all online contacts."""
        sess = self.get_session(user_email)
        if not sess:
            return
        self.broadcast_status_change(sess)

    def broadcast_offline(self, user_email: str) -> None:
        """Broadcasts FLN to all contacts when user disconnects."""
        for contact_email, sess in self._active_sessions.items():
            if contact_email == user_email.lower():
                continue
            c = self.db.get_contact(sess.email, user_email)
            if c and (c.list_flags & ListMask.FL):
                sess.send_fln(user_email)

    # Switchboard Invitation Dispatch
    def send_switchboard_ring(self, callee_email: str, session_id: int, sb_host: str, sb_port: int,
                               cookie: str, caller_email: str, caller_friendly_name: str) -> bool:
        """
        Sends RNG command to callee over their Notification Server connection.
        Format: RNG session_id sb_host:sb_port CKI cookie caller_email caller_friendly_name
        """
        callee_sess = self.get_session(callee_email)
        if not callee_sess:
            return False

        callee_sess.send_rng(session_id, sb_host, sb_port, cookie, caller_email, caller_friendly_name)
        return True
