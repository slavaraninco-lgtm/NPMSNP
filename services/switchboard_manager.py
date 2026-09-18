"""
Switchboard Manager for MSNP.
Coordinates multi-party chat rooms, caller/callee invitations, and message broadcasting.
"""
import logging
import threading
from typing import Dict, Optional, List, Set, Tuple, Any, TYPE_CHECKING

from protocol.auth import AuthManager

if TYPE_CHECKING:
    from protocol.sb_handler import SBClientHandler

logger = logging.getLogger("MSNP.SwitchboardManager")


class SwitchboardRoom:
    """Represents an active multi-user Switchboard chat conversation."""
    def __init__(self, session_id: int, creator_email: str):
        self.session_id = session_id
        self.creator_email = creator_email.lower()
        # Participants: email (lowercase) -> SBClientHandler
        self.participants: Dict[str, "SBClientHandler"] = {}
        # Expected invitees: email (lowercase) -> cookie
        self.pending_invites: Dict[str, str] = {}
        self.has_service_bot: bool = False
        self.lock = threading.Lock()

    def add_participant(self, email: str, handler: "SBClientHandler") -> None:
        with self.lock:
            self.participants[email.lower()] = handler
            if email.lower() in self.pending_invites:
                del self.pending_invites[email.lower()]

    def remove_participant(self, email: str) -> None:
        with self.lock:
            self.participants.pop(email.lower(), None)

    def is_empty(self) -> bool:
        with self.lock:
            return len(self.participants) == 0

    def get_participants(self) -> List["SBClientHandler"]:
        with self.lock:
            return list(self.participants.values())

    def broadcast(self, data: bytes, exclude_email: Optional[str] = None) -> None:
        """Broadcasts raw bytes to all participants in this room."""
        exclude = exclude_email.lower() if exclude_email else None
        with self.lock:
            handlers = list(self.participants.values())

        for h in handlers:
            if exclude and h.email.lower() == exclude:
                continue
            try:
                h.send_raw(data)
            except Exception as ex:
                logger.warning(f"Error broadcasting to {h.email}: {ex}")


class SwitchboardManager:
    def __init__(self, auth_manager: AuthManager):
        self.auth_manager = auth_manager
        self._next_session_id = 1000
        self._lock = threading.Lock()
        # Active rooms: session_id -> SwitchboardRoom
        self._rooms: Dict[int, SwitchboardRoom] = {}
        # Queued messages for offline / not-yet-joined users: email -> List[str]
        self._pending_service_messages: Dict[str, List[str]] = {}

    def queue_service_message(self, user_email: str, message: str) -> None:
        """Queues a service message to be delivered when user opens or connects to a Switchboard room."""
        with self._lock:
            key = user_email.lower()
            if key not in self._pending_service_messages:
                self._pending_service_messages[key] = []
            self._pending_service_messages[key].append(message)

    def pop_pending_service_messages(self, user_email: str) -> List[str]:
        """Pops and returns all queued service messages for the given user."""
        with self._lock:
            return self._pending_service_messages.pop(user_email.lower(), [])

    def has_pending_service_messages(self, user_email: str) -> bool:
        """Returns True if there are pending service messages queued for this user."""
        with self._lock:
            return bool(self._pending_service_messages.get(user_email.lower()))

    def allocate_session(self, creator_email: str) -> Tuple[int, str]:
        """
        Creates a new Switchboard room and caller cookie for XFR.
        Returns (session_id, caller_cookie).
        """
        with self._lock:
            self._next_session_id += 1
            session_id = self._next_session_id
            room = SwitchboardRoom(session_id, creator_email)
            self._rooms[session_id] = room

        caller_cookie = self.auth_manager.create_sb_cookie(creator_email, session_id, role="caller")
        logger.info(f"Allocated Switchboard room {session_id} for {creator_email}")
        return session_id, caller_cookie

    def get_room(self, session_id: int) -> Optional[SwitchboardRoom]:
        with self._lock:
            return self._rooms.get(session_id)

    def prepare_invite(self, session_id: int, callee_email: str) -> Optional[str]:
        """
        Prepares an invite for callee in an existing room.
        Generates callee cookie.
        """
        room = self.get_room(session_id)
        if not room:
            return None

        callee_cookie = self.auth_manager.create_sb_cookie(callee_email, session_id, role="callee")
        with room.lock:
            room.pending_invites[callee_email.lower()] = callee_cookie
        return callee_cookie

    def join_room(self, session_id: int, email: str, handler: "SBClientHandler", is_callee: bool = False, trid: str = "1") -> Optional[SwitchboardRoom]:
        """
        Registers participant in room.
        Notifies existing participants with JOI.
        Sends IRO to joining participant for existing participants.
        """
        room = self.get_room(session_id)
        if not room:
            return None

        with room.lock:
            existing_participants = list(room.participants.values())
            room.participants[email.lower()] = handler
            if email.lower() in room.pending_invites:
                del room.pending_invites[email.lower()]

        # If joining user is callee (via ANS), send IRO for each existing participant
        if is_callee:
            total_count = len(existing_participants)
            for idx, p in enumerate(existing_participants, start=1):
                handler.send_iro(trid, idx, total_count, p.email, p.friendly_name)

        # Send JOI to all existing participants notifying that this user joined
        for p in existing_participants:
            if p.email.lower() != email.lower():
                p.send_joi(email, handler.friendly_name)

        logger.info(f"User {email} joined room {session_id}. Total in room: {len(room.participants)}")
        return room

    def leave_room(self, session_id: int, email: str) -> None:
        """
        Removes participant from room and notifies remaining participants with BYE.
        """
        room = self.get_room(session_id)
        if not room:
            return

        room.remove_participant(email)
        # Notify others with BYE
        for p in room.get_participants():
            p.send_bye(email)

        # Cleanup room if empty
        if room.is_empty():
            with self._lock:
                self._rooms.pop(session_id, None)
            logger.info(f"Room {session_id} destroyed (empty).")

    def broadcast_message(self, session_id: int, sender_email: str, sender_friendly_name: str,
                          payload: bytes, db: Optional[Any] = None) -> List[str]:
        """Relays a chat MSG to other participants in the room. Skips banned users and returns their emails."""
        room = self.get_room(session_id)
        if not room:
            return []

        blocked = []
        for p in room.get_participants():
            if p.email.lower() != sender_email.lower():
                if db:
                    p_penalty = db.get_user_penalty_status(p.email)
                    if p_penalty.get("is_banned"):
                        blocked.append(p.email)
                        continue
                p.send_msg_relay(sender_email, sender_friendly_name, payload)
        return blocked

    def broadcast_typing(self, session_id: int, sender_email: str, payload: bytes) -> bool:
        """Relays a typing notification NOT to other participants in the room."""
        room = self.get_room(session_id)
        if not room:
            return False

        for p in room.get_participants():
            if p.email.lower() != sender_email.lower():
                p.send_not_relay(sender_email, payload)
        return True

    def _format_mime_message(self, message: str) -> bytes:
        return (
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "X-MMS-IM-Format: FN=Tahoma; EF=; CO=0; CS=0; PF=0\r\n\r\n"
            f"{message}\r\n"
        ).encode("utf-8")

    def send_system_message_to_user_rooms(self, user_email: str, sender_email: str, sender_name: str, message: str) -> bool:
        """
        Sends a message into an active 1-on-1 switchboard room between user_email and the service bot.
        Returns True if delivered into an existing 1-on-1 bot room.
        MUST NEVER inject into or modify rooms between human users.
        """
        prefix = f"[{sender_name}]:\r\n"
        body_msg = message if message.startswith(f"[{sender_name}]:") else f"{prefix}{message}"
        payload = self._format_mime_message(body_msg)
        with self._lock:
            rooms = list(self._rooms.values())
        for room in rooms:
            with room.lock:
                # Must be a dedicated service bot room
                if not getattr(room, "has_service_bot", False):
                    continue
                # Must have exactly 1 human participant (the user)
                if len(room.participants) != 1:
                    continue
                target_p = room.participants.get(user_email.lower())
                if target_p and not target_p.closed:
                    try:
                        target_p.send_msg_relay(sender_email, sender_name, payload)
                        return True
                    except Exception as ex:
                        logger.warning(f"Error relaying system message to {user_email}: {ex}")
        return False

    def deliver_service_pm(self, target_email: str, message: str,
                           session_manager: Any,
                           external_host: str = "",
                           sb_port: int = 0) -> bool:
        """
        Delivers a private message (личка) from the service account to target_email:
        1. If user already has an active 1-on-1 room open with the service bot, delivers immediately.
        2. Otherwise, if user is online on NS, queues the message and sends RNG invitation
           so client connects via ANS into a dedicated 1-on-1 room.
        Returns True if delivered or ring invitation was sent.
        """
        import config
        service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
        service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")
        host = external_host or getattr(config, "EXTERNAL_HOST", "127.0.0.1")
        if (not host or host in ("127.0.0.1", "0.0.0.0", "localhost")) and session_manager:
            target_sess = session_manager.get_session(target_email)
            if target_sess and hasattr(target_sess, "get_effective_host"):
                host = target_sess.get_effective_host()
        port = sb_port or getattr(config, "SB_PORT", 1864)

        # 1. Check if user already has an active 1-on-1 bot room
        if self.send_system_message_to_user_rooms(target_email, service_email, service_name, message):
            return True

        # 2. Check if user is online on NS
        if not session_manager or not session_manager.is_online(target_email):
            return False

        # 3. Queue message for delivery upon ANS
        self.queue_service_message(target_email, message)

        # 4. Allocate dedicated 1-on-1 bot room and invite via RNG
        try:
            session_id, _ = self.allocate_session(service_email)
            room = self.get_room(session_id)
            if room:
                room.has_service_bot = True
            cookie = self.prepare_invite(session_id, target_email)
            if cookie:
                return session_manager.send_switchboard_ring(
                    target_email, session_id, host, port,
                    cookie, service_email, service_name
                )
        except Exception as ex:
            logger.warning(f"Error ringing {target_email} for service message: {ex}")
        return False

    def broadcast_system_message_to_all_rooms(self, sender_email: str, sender_name: str, message: str) -> int:
        """Broadcasts a system message only to active 1-on-1 bot rooms."""
        count = 0
        prefix = f"[{sender_name}]:\r\n"
        body_msg = message if message.startswith(f"[{sender_name}]:") else f"{prefix}{message}"
        payload = self._format_mime_message(body_msg)
        with self._lock:
            rooms = list(self._rooms.values())
        seen_emails = set()
        for room in rooms:
            with room.lock:
                if not getattr(room, "has_service_bot", False) or len(room.participants) != 1:
                    continue
                for p in room.get_participants():
                    if p.email.lower() not in seen_emails and not p.closed:
                        try:
                            p.send_msg_relay(sender_email, sender_name, payload)
                            seen_emails.add(p.email.lower())
                            count += 1
                        except Exception as ex:
                            logger.warning(f"Error broadcasting system message to {p.email}: {ex}")
        return count

