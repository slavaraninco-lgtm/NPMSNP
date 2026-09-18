"""
Switchboard Server (SB) Client Handler.
Handles chat conversations, caller-callee rendezvous, messaging, and typing notifications:
- Caller authentication (USR)
- Callee invitation (CAL)
- Callee answer (ANS)
- Roster sync (IRO, JOI)
- Chat messaging (MSG) with ACK support
- Typing indicators (NOT)
- Leaving chat (BYE, OUT)
"""
import asyncio
import logging
from typing import Optional, List, Dict, Any

import config
from db.database import Database
from protocol.constants import MSNPError, SUPPORTED_DIALECTS
from protocol.packet import MSNPReader, MSNPWriter, encode_arg
from protocol.auth import AuthManager
from services.session_manager import SessionManager
from services.switchboard_manager import SwitchboardManager, SwitchboardRoom

logger = logging.getLogger("MSNP.SBHandler")


class SBClientHandler:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 db: Database, auth_manager: AuthManager,
                 session_manager: SessionManager, switchboard_manager: SwitchboardManager,
                 external_host: str = config.EXTERNAL_HOST,
                 sb_port: int = config.SB_PORT):
        self.reader = reader
        self.writer = writer
        self.db = db
        self.auth_manager = auth_manager
        self.session_manager = session_manager
        self.switchboard_manager = switchboard_manager
        self.external_host = external_host
        self.sb_port = sb_port

        self.msnp_reader = MSNPReader()
        self.peername = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        self.closed = False

        # Session State
        self.authenticated = False
        self.email: str = ""
        self.friendly_name: str = ""
        self.session_id: Optional[int] = None
        self.room: Optional[SwitchboardRoom] = None

    @property
    def is_ansi(self) -> bool:
        if self.email:
            ns_sess = self.session_manager.get_session(self.email)
            if ns_sess and hasattr(ns_sess, "is_ansi"):
                return bool(ns_sess.is_ansi)
        return False

    def get_effective_host(self) -> str:
        """
        Determines the most accurate IP or hostname to report to this client.
        1. If external_host was explicitly configured to a real domain or IP (not localhost/0.0.0.0), use it.
        2. If the client connected to a specific non-loopback network interface (sockname[0]), use that IP.
        3. If client is remote (peername[0] is not 127.0.0.1) and external_host is loopback, try to detect outward IP.
        4. Fallback to external_host or '127.0.0.1'.
        """
        if self.external_host and self.external_host not in ("127.0.0.1", "0.0.0.0", "localhost"):
            return self.external_host

        sockname = self.writer.get_extra_info("sockname") if self.writer else None
        if sockname and isinstance(sockname, tuple) and sockname[0]:
            local_ip = str(sockname[0])
            if local_ip not in ("0.0.0.0", "127.0.0.1", "::1"):
                return local_ip

        peername = self.writer.get_extra_info("peername") if self.writer else None
        if peername and isinstance(peername, tuple) and peername[0]:
            peer_ip = str(peername[0])
            if peer_ip not in ("127.0.0.1", "::1", "localhost"):
                try:
                    import socket
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.settimeout(0.5)
                    s.connect(("8.8.8.8", 80))
                    ip = s.getsockname()[0]
                    s.close()
                    if ip and not ip.startswith("127."):
                        return ip
                except Exception:
                    pass

        return self.external_host or "127.0.0.1"

    async def run(self) -> None:
        """Main receive loop for the Switchboard connection."""
        logger.info(f"SB Client connected from {self.peername}")
        try:
            while not self.closed:
                data = await self.reader.read(4096)
                if not data:
                    break

                commands = self.msnp_reader.feed_data(data)
                for cmd, args, payload in commands:
                    await self._handle_command(cmd, args, payload)
        except asyncio.CancelledError:
            pass
        except ConnectionResetError:
            logger.debug(f"SB Client {self.peername} connection reset")
        except Exception as ex:
            logger.warning(f"Error handling SB client {self.peername}: {ex}", exc_info=True)
        finally:
            self.close()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True

        if self.session_id and self.email:
            self.switchboard_manager.leave_room(self.session_id, self.email)

        try:
            self.writer.close()
        except Exception:
            pass
        logger.info(f"SB Client {self.email or self.peername} disconnected.")

    def send_raw(self, data: bytes) -> None:
        if self.closed:
            return
        try:
            self.writer.write(data)
        except Exception as ex:
            logger.warning(f"Error sending data to SB client {self.email}: {ex}")
            self.close()

    def send_cmd(self, cmd: str, *args: Any, payload: Optional[bytes] = None) -> None:
        arg_str = " ".join(str(a) for a in args if a is not None)
        logger.debug(f"<<< SB {cmd} {arg_str}{' [payload ' + str(len(payload)) + 'b]' if payload else ''}")
        if cmd.upper() == "MSG":
            encoding = "utf-8"
        else:
            encoding = "cp1251" if self.is_ansi else "utf-8"
        data = MSNPWriter.format_command(cmd, *args, payload=payload, encoding=encoding)
        self.send_raw(data)

    def send_error(self, code: int, trid: str = "0") -> None:
        self.send_cmd(str(code), trid)

    # Command Dispatcher
    async def _handle_command(self, cmd: str, args: List[str], payload: Optional[bytes]) -> None:
        logger.debug(f">>> SB {cmd} {' '.join(args)}{' [payload ' + str(len(payload)) + 'b]' if payload else ''}")
        method_name = f"_cmd_{cmd.lower()}"
        method = getattr(self, method_name, None)
        if method:
            try:
                await method(args, payload)
            except Exception as ex:
                logger.error(f"Exception in SB handler {cmd} for {self.email}: {ex}", exc_info=True)
                trid = args[0] if args else "0"
                self.send_error(MSNPError.INTERNAL_SERVER_ERROR, trid)
        else:
            logger.warning(f"Unhandled SB command: {cmd} args={args}")
            trid = args[0] if args else "0"
            if cmd in ("CHL", "PNG", "QNG", "NOT", "UUN", "UUM"):
                return
            self.send_error(MSNPError.SYNTAX_ERROR, trid)

    # Handlers

    async def _cmd_ver(self, args: List[str], payload: Optional[bytes]) -> None:
        # VER trid MSNP9 MSNP8 CVR0
        if not args:
            return
        trid = args[0]
        offered = [a.upper() for a in args[1:]]
        chosen = "MSNP9"
        for d in SUPPORTED_DIALECTS:
            if d in offered:
                chosen = d
                break
        resp_args = [chosen]
        for a in offered:
            if a.startswith("CVR"):
                resp_args.append(a)
                break
        self.send_cmd("VER", trid, *resp_args)

    async def _cmd_cvr(self, args: List[str], payload: Optional[bytes]) -> None:
        trid = args[0] if args else "1"
        ver = "6.0.0602"
        host = self.get_effective_host()
        url = f"http://{host}:{self.http_port}/"
        self.send_cmd("CVR", trid, ver, ver, ver, url, url)

    async def _cmd_png(self, args: List[str], payload: Optional[bytes]) -> None:
        self.send_cmd("QNG", 60)

    async def _cmd_out(self, args: List[str], payload: Optional[bytes]) -> None:
        self.close()

    async def _cmd_usr(self, args: List[str], payload: Optional[bytes]) -> None:
        # Caller connects: USR trid caller_email cookie
        if len(args) < 3:
            self.close()
            return

        trid = args[0]
        email = args[1].strip()
        cookie = args[2].strip()

        cookie_data = self.auth_manager.verify_and_consume_sb_cookie(cookie, email)
        if not cookie_data:
            self.send_error(MSNPError.AUTH_FAILED, trid)
            self.close()
            return

        session_id, role = cookie_data
        self.email = email
        self.session_id = session_id

        user = self.db.get_user(self.email)
        self.friendly_name = user.friendly_name if user else self.email.split("@")[0]

        self.room = self.switchboard_manager.join_room(session_id, self.email, self, is_callee=False)
        if not self.room:
            self.send_error(MSNPError.SWITCHBOARD_FAILED, trid)
            self.close()
            return

        self.authenticated = True
        # Respond: USR trid OK email friendly_name
        self.send_cmd("USR", trid, "OK", self.email, self.friendly_name)

    async def _cmd_ans(self, args: List[str], payload: Optional[bytes]) -> None:
        # Callee connects: ANS trid callee_email cookie session_id
        if len(args) < 4:
            self.close()
            return

        trid = args[0]
        email = args[1].strip()
        cookie = args[2].strip()
        try:
            session_id = int(args[3].strip())
        except ValueError:
            self.close()
            return

        cookie_data = self.auth_manager.verify_and_consume_sb_cookie(cookie, email)
        if not cookie_data or cookie_data[0] != session_id:
            self.send_error(MSNPError.AUTH_FAILED, trid)
            self.close()
            return

        self.email = email
        self.session_id = session_id

        user = self.db.get_user(self.email)
        self.friendly_name = user.friendly_name if user else self.email.split("@")[0]

        # Respond: ANS trid OK
        self.send_cmd("ANS", trid, "OK")

        # Join room as callee (sends IRO of existing participants, and JOI to others)
        self.room = self.switchboard_manager.join_room(session_id, self.email, self, is_callee=True, trid=trid)
        if not self.room:
            self.close()
            return

        self.authenticated = True

        # Check if room has service bot or bot was creator
        service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
        service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")
        if (getattr(self.room, "has_service_bot", False) or (self.room and self.room.creator_email == service_email.lower())) and len(self.room.participants) == 1:
            self.room.has_service_bot = True
            self.send_iro(trid, 1, 1, service_email, service_name)
            pending = self.switchboard_manager.pop_pending_service_messages(self.email)
            for pmsg in pending:
                self.send_service_notice(pmsg)

    def send_service_notice(self, text: str) -> None:
        """Sends a notification directly to this client from the service account."""
        service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
        service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")
        prefix = f"[{service_name}]:\r\n"
        body_text = text if text.startswith(f"[{service_name}]:") else f"{prefix}{text}\r\n"
        payload = (
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "X-MMS-IM-Format: FN=Tahoma; EF=; CO=0; CS=0; PF=0\r\n\r\n"
            f"{body_text}"
        ).encode("utf-8")
        self.send_msg_relay(service_email, service_name, payload)

    async def _cmd_cal(self, args: List[str], payload: Optional[bytes]) -> None:
        # CAL trid callee_email
        if len(args) < 2 or not self.session_id:
            return

        if not self.room and self.session_id:
            self.room = self.switchboard_manager.get_room(self.session_id)

        trid = args[0]
        callee_email = args[1].strip()

        if "@" not in callee_email:
            self.send_error(MSNPError.INVALID_USER, trid)
            return

        # Check caller ban
        caller_penalty = self.db.get_user_penalty_status(self.email)
        if caller_penalty.get("is_banned"):
            rem = caller_penalty["ban_remaining"]
            reason = f" Причина: {caller_penalty['ban_reason']}." if caller_penalty["ban_reason"] else ""
            msg = f"Вы не можете совершать вызовы, так как ваша учетная запись заблокирована (бан).{reason} До окончания блокировки осталось: {rem}."
            self.switchboard_manager.deliver_service_pm(self.email, msg, self.session_manager, self.get_effective_host(), self.sb_port)
            self.send_error(MSNPError.NOT_ALLOWED, trid)
            return

        # Check callee ban
        callee_penalty = self.db.get_user_penalty_status(callee_email)
        if callee_penalty.get("is_banned"):
            msg = f"Пользователь {callee_email} заблокирован администрацией и не может принимать вызовы."
            self.switchboard_manager.deliver_service_pm(self.email, msg, self.session_manager, self.get_effective_host(), self.sb_port)
            self.send_error(MSNPError.PRINCIPAL_NOT_ONLINE, trid)
            return

        service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
        service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")

        # If calling the service bot account, automatically accept and join
        if callee_email.lower() == service_email.lower():
            if self.room and len(self.room.participants) > 1:
                # Disallow inviting service bot into conferences / group chats
                self.send_error(MSNPError.NOT_ALLOWED, trid)
                return
            self.send_cmd("CAL", trid, "RINGING", self.session_id)
            if self.room:
                self.room.has_service_bot = True
            self.send_joi(service_email, service_name)
            pending = self.switchboard_manager.pop_pending_service_messages(self.email)
            for pmsg in pending:
                self.send_service_notice(pmsg)
            return

        # Prepare callee cookie
        callee_cookie = self.switchboard_manager.prepare_invite(self.session_id, callee_email)
        if not callee_cookie:
            self.send_error(MSNPError.SWITCHBOARD_FAILED, trid)
            return

        # Check if callee is online
        if not self.session_manager.is_online(callee_email):
            # Callee is not online
            self.send_error(MSNPError.PRINCIPAL_NOT_ONLINE, trid)
            return

        # Send RINGING to caller
        self.send_cmd("CAL", trid, "RINGING", self.session_id)

        # Dispatch RNG to callee over their NS connection
        ring_sent = self.session_manager.send_switchboard_ring(
            callee_email, self.session_id, self.get_effective_host(), self.sb_port,
            callee_cookie, self.email, self.friendly_name
        )
        if not ring_sent:
            self.send_error(MSNPError.PRINCIPAL_NOT_ONLINE, trid)

    async def _cmd_msg(self, args: List[str], payload: Optional[bytes]) -> None:
        # MSG trid ack_type len\r\n<payload>
        if len(args) < 2 or not payload or not self.session_id:
            return

        trid = args[0]
        ack_type = args[1].upper()

        # Send ACK if requested
        if ack_type in ("A", "D"):
            self.send_cmd("ACK", trid)

        # Check if sender is banned
        penalty = self.db.get_user_penalty_status(self.email)
        if penalty.get("is_banned"):
            rem = penalty["ban_remaining"]
            reason = f" Причина: {penalty['ban_reason']}." if penalty["ban_reason"] else ""
            msg = f"Ваша учетная запись заблокирована (бан).{reason} До окончания блокировки осталось: {rem}. Вы не можете отправлять и принимать сообщения."
            self.switchboard_manager.deliver_service_pm(self.email, msg, self.session_manager, self.get_effective_host(), self.sb_port)
            return

        # Check if sender is muted
        if penalty.get("is_muted"):
            rem = penalty["mute_remaining"]
            reason = f" Причина: {penalty['mute_reason']}." if penalty["mute_reason"] else ""
            msg = f"Вам временно ограничен доступ к отправке сообщений (мут).{reason} До окончания мута осталось: {rem}."
            self.switchboard_manager.deliver_service_pm(self.email, msg, self.session_manager, self.get_effective_host(), self.sb_port)
            return

        # Check if caller is in a room with the service bot alone
        if self.room and getattr(self.room, "has_service_bot", False) and len(self.room.participants) == 1:
            bot_text = (
                "Здравствуйте! Это автоматическая служба сообщений MSN. "
                "Данная учетная запись используется сервером для системных оповещений и уведомлений администрации."
            )
            self.send_service_notice(bot_text)
            return

        # If only this user is in the room and there is a pending invite or recipient,
        # save as offline message
        if self.room and len(self.room.participants) == 1:
            recipients = list(self.room.pending_invites.keys())
            if recipients:
                target = recipients[0]
                target_penalty = self.db.get_user_penalty_status(target)
                if target_penalty.get("is_banned"):
                    self.switchboard_manager.deliver_service_pm(
                        self.email,
                        f"Сообщение не доставлено: пользователь {target} заблокирован администрацией.",
                        self.session_manager, self.get_effective_host(), self.sb_port
                    )
                    return

                text_content = payload.decode("utf-8", errors="replace")
                body_text = text_content
                if "\r\n\r\n" in text_content:
                    body_text = text_content.split("\r\n\r\n", 1)[1]
                self.db.save_offline_message(self.email, target, body_text.strip())

        # Relay message to everyone else in this chat room (skipping banned users)
        blocked = self.switchboard_manager.broadcast_message(
            self.session_id, self.email, self.friendly_name, payload, db=self.db
        )
        if blocked:
            for b_user in blocked:
                self.switchboard_manager.deliver_service_pm(
                    self.email,
                    f"Сообщение не доставлено: пользователь {b_user} заблокирован администрацией.",
                    self.session_manager, self.get_effective_host(), self.sb_port
                )

    async def _cmd_not(self, args: List[str], payload: Optional[bytes]) -> None:
        # NOT len\r\n<payload> (Typing notification)
        if not payload or not self.session_id:
            return

        penalty = self.db.get_user_penalty_status(self.email)
        if penalty.get("is_banned") or penalty.get("is_muted"):
            return

        self.switchboard_manager.broadcast_typing(self.session_id, self.email, payload)

    async def _cmd_out(self, args: List[str], payload: Optional[bytes]) -> None:
        # Participant leaves chat
        self.close()

    # Outgoing Switchboard Event Helpers

    def send_iro(self, trid: str, index: int, total: int, email: str, friendly_name: str) -> None:
        """Sends IRO (Initial Roster) to callee upon joining."""
        self.send_cmd("IRO", trid, index, total, email, friendly_name or email)

    def send_joi(self, email: str, friendly_name: str) -> None:
        """Sends JOI (Join) notification to existing participants."""
        self.send_cmd("JOI", email, friendly_name or email)

    def send_bye(self, email: str) -> None:
        """Sends BYE when someone leaves."""
        self.send_cmd("BYE", email)

    def send_msg_relay(self, sender_email: str, sender_friendly_name: str, payload: bytes) -> None:
        """Relays a message from another participant."""
        self.send_cmd("MSG", sender_email, sender_friendly_name or sender_email, payload=payload)

    def send_not_relay(self, sender_email: str, payload: bytes) -> None:
        """Relays typing indicator from another participant."""
        self.send_cmd("NOT", sender_email, payload=payload)
