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
import os
import re
import time
import urllib.parse
import uuid
from typing import Optional, List, Dict, Any

import config
from db.database import Database
from protocol.constants import MSNPError
from protocol.packet import MSNPReader, MSNPWriter, encode_arg
from protocol.auth import AuthManager
from services.session_manager import SessionManager
from services.switchboard_manager import SwitchboardManager, SwitchboardRoom

logger = logging.getLogger("MSNP.SBHandler")

# Global tracking for active MSNFTP invitations across switchboard sessions
_active_ft_invitations: Dict[str, dict] = {}


class SBClientHandler:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 db: Database, auth_manager: AuthManager,
                 session_manager: SessionManager, switchboard_manager: SwitchboardManager,
                 external_host: str = config.EXTERNAL_HOST,
                 sb_port: int = config.SB_PORT,
                 msnftp_relay: Optional[Any] = None,
                 http_port: int = getattr(config, "HTTP_PORT", 1865)):
        self.reader = reader
        self.writer = writer
        self.db = db
        self.auth_manager = auth_manager
        self.session_manager = session_manager
        self.switchboard_manager = switchboard_manager
        self.external_host = external_host
        self.sb_port = sb_port
        self.msnftp_relay = msnftp_relay
        self.http_port = http_port

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
        if payload and logger.isEnabledFor(logging.DEBUG):
            try:
                preview = payload.decode("utf-8", errors="replace")[:250].strip()
                logger.debug(f">>> SB payload preview: {preview}")
            except Exception:
                pass
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
            self.send_error(MSNPError.SYNTAX_ERROR, trid)

    # Handlers

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
            self.switchboard_manager.deliver_service_pm(self.email, msg, self.session_manager, self.external_host, self.sb_port)
            self.send_error(MSNPError.NOT_ALLOWED, trid)
            return

        # Check callee ban
        callee_penalty = self.db.get_user_penalty_status(callee_email)
        if callee_penalty.get("is_banned"):
            msg = f"Пользователь {callee_email} заблокирован администрацией и не может принимать вызовы."
            self.switchboard_manager.deliver_service_pm(self.email, msg, self.session_manager, self.external_host, self.sb_port)
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
            callee_email, self.session_id, self.external_host, self.sb_port,
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
            self.switchboard_manager.deliver_service_pm(self.email, msg, self.session_manager, self.external_host, self.sb_port)
            return

        # Check if sender is muted
        if penalty.get("is_muted"):
            rem = penalty["mute_remaining"]
            reason = f" Причина: {penalty['mute_reason']}." if penalty["mute_reason"] else ""
            msg = f"Вам временно ограничен доступ к отправке сообщений (мут).{reason} До окончания мута осталось: {rem}."
            self.switchboard_manager.deliver_service_pm(self.email, msg, self.session_manager, self.external_host, self.sb_port)
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
                        self.session_manager, self.external_host, self.sb_port
                    )
                    return

                text_content = payload.decode("utf-8", errors="replace")
                body_text = text_content
                if "\r\n\r\n" in text_content:
                    body_text = text_content.split("\r\n\r\n", 1)[1]
                self.db.save_offline_message(self.email, target, body_text.strip())

        # Inspect and process MSNFTP file transfer invitations
        if payload and b"text/x-msmsgsinvite" in payload:
            processed = await self._process_file_transfer_payload(payload)
            if processed is None:
                # The invitation was auto-accepted or handled internally by the server
                return
            payload = processed

        # Handle Gaim MSNSLP P2P file transfers if recipient is Trillian
        if payload and b"application/x-msnmsgrp2p" in payload:
            if b"{5D3E02AB-6190-11D3-BBBB-00C04F795683}" in payload or b"INVITE MSNMSGR:" in payload:
                if self.room:
                    for p in self.room.get_participants():
                        if p.email.lower() != self.email.lower():
                            ns = self.session_manager.get_session(p.email)
                            capp = getattr(ns, "client_app", "").lower() if ns else ""
                            if "trillian" in capp:
                                notice = (
                                    f"Пользователь {p.friendly_name} использует Trillian, который не поддерживает "
                                    f"прямую передачу файлов P2P. Для отправки файлов воспользуйтесь веб-интерфейсом: "
                                    f"http://{self.external_host}:{self.http_port}/"
                                )
                                self.send_service_notice(notice)
                                break

        # Relay message to everyone else in this chat room (skipping banned users)
        blocked = self.switchboard_manager.broadcast_message(
            self.session_id, self.email, self.friendly_name, payload, db=self.db
        )
        if blocked:
            for b_user in blocked:
                self.switchboard_manager.deliver_service_pm(
                    self.email,
                    f"Сообщение не доставлено: пользователь {b_user} заблокирован администрацией.",
                    self.session_manager, self.external_host, self.sb_port
                )

    async def _process_file_transfer_payload(self, payload: bytes) -> Optional[bytes]:
        """Inspects and rewrites MSNFTP file transfer invitation parameters for NAT traversal and cross-client bridging."""
        try:
            text = payload.decode("utf-8", errors="replace")

            # 1. Primary Invitation from Sender (e.g. Trillian)
            if "Invitation-Command: INVITE" in text:
                cookie_match = re.search(r"Invitation-Cookie:\s*(\d+)", text)
                file_match = re.search(r"Application-File:\s*([^\r\n]+)", text)
                size_match = re.search(r"Application-FileSize:\s*(\d+)", text)

                cookie = cookie_match.group(1).strip() if cookie_match else ""
                filename = file_match.group(1).strip() if file_match else "file.bin"
                filesize = int(size_match.group(1).strip()) if size_match else 0

                ft_info = {
                    "cookie": cookie,
                    "sender_email": self.email,
                    "sender_name": self.friendly_name,
                    "sender_host": self.peername[0],
                    "filename": filename,
                    "filesize": filesize,
                    "created_at": time.time(),
                    "auto_accepted": False,
                    "receiver_email": "",
                    "receiver_name": "",
                }
                _active_ft_invitations[cookie] = ft_info

                # Check if recipient in the room is Gaim (or cannot handle MSNFTP)
                if self.room:
                    other_participants = [p for p in self.room.get_participants() if p.email.lower() != self.email.lower()]
                    if other_participants:
                        target = other_participants[0]
                        ns = self.session_manager.get_session(target.email)
                        client_app = getattr(ns, "client_app", "").lower() if ns else ""
                        is_gaim = any(x in client_app for x in ("gaim", "pidgin", "libpurple")) or ("trillian" not in client_app and "msmsgs" not in client_app)

                        if is_gaim:
                            # Recipient Gaim cannot process text/x-msmsgsinvite!
                            # Auto-accept on behalf of Gaim so sender proceeds with MSNFTP transfer
                            ft_info["auto_accepted"] = True
                            ft_info["receiver_email"] = target.email
                            ft_info["receiver_name"] = target.friendly_name

                            accept_payload = (
                                "MIME-Version: 1.0\r\n"
                                "Content-Type: text/x-msmsgsinvite; charset=UTF-8\r\n\r\n"
                                "Invitation-Command: ACCEPT\r\n"
                                f"Invitation-Cookie: {cookie}\r\n"
                                "Launch-Application: FALSE\r\n"
                                "Request-Data: IP-Address:\r\n"
                            ).encode("utf-8")
                            self.send_cmd("MSG", target.email, target.friendly_name or target.email, payload=accept_payload)
                            logger.info(f"Auto-accepted MSNFTP invite for '{filename}' ({filesize}b) on behalf of Gaim user {target.email}")
                            return None

            # 2. Sender supplying connection parameters (IP-Address, Port, AuthCookie)
            elif "Invitation-Command: ACCEPT" in text and "IP-Address:" in text:
                cookie_match = re.search(r"Invitation-Cookie:\s*(\d+)", text)
                ip_match = re.search(r"IP-Address:\s*([^\r\n]+)", text)
                port_match = re.search(r"Port:\s*(\d+)", text)
                auth_match = re.search(r"AuthCookie:\s*(\w+)", text)

                cookie = cookie_match.group(1).strip() if cookie_match else ""
                orig_ip = ip_match.group(1).strip() if ip_match else ""
                orig_port = int(port_match.group(1).strip()) if port_match else 0
                auth_cookie = auth_match.group(1).strip() if auth_match else ""

                ft_info = _active_ft_invitations.get(cookie, {})
                sender_ip = self.peername[0]

                # If this transfer was auto-accepted by the server (for Gaim/web delivery)
                if ft_info.get("auto_accepted"):
                    logger.info(f"Connecting to sender {sender_ip}:{orig_port} to download file for Gaim recipient...")
                    asyncio.create_task(self._download_and_share_file(
                        sender_host=sender_ip,
                        sender_port=orig_port,
                        auth_cookie=auth_cookie,
                        ft_info=ft_info
                    ))
                    return None

                # Otherwise, standard client-to-client transfer (e.g. Trillian to Trillian)
                if self.msnftp_relay:
                    self.msnftp_relay.register_session(
                        sender_email=self.email,
                        receiver_email=ft_info.get("receiver_email", ""),
                        auth_cookie=auth_cookie,
                        file_name=ft_info.get("filename", ""),
                        file_size=ft_info.get("filesize", 0),
                        sender_host=sender_ip,
                        sender_port=orig_port,
                    )

                # NAT Traversal rewrite
                if getattr(config, "ENABLE_MSNFTP_NAT_REWRITE", True):
                    new_ip = self.external_host
                    new_port = getattr(config, "MSNFTP_PORT", 1866)
                    text = re.sub(r"IP-Address:\s*[^\r\n]+", f"IP-Address: {new_ip}", text)
                    text = re.sub(r"Port:\s*\d+", f"Port: {new_port}", text)
                    return text.encode("utf-8")

            # 3. Handle Cancel / Reject
            elif "Invitation-Command: CANCEL" in text:
                cookie_match = re.search(r"Invitation-Cookie:\s*(\d+)", text)
                if cookie_match:
                    _active_ft_invitations.pop(cookie_match.group(1).strip(), None)

        except Exception as ex:
            logger.warning(f"Error processing MSNFTP invitation: {ex}", exc_info=True)
        return payload

    async def _download_and_share_file(self, sender_host: str, sender_port: int,
                                       auth_cookie: str, ft_info: dict) -> None:
        """
        Downloads a file from an MSNFTP sender and delivers it to the room chat with a public download link.
        """
        filename = ft_info.get("filename", "file.bin")
        filesize = ft_info.get("filesize", 0)
        sender_email = ft_info.get("sender_email", self.email)
        sender_name = ft_info.get("sender_name", self.friendly_name)
        receiver_email = ft_info.get("receiver_email", "")

        if not self.msnftp_relay:
            logger.warning("No MSNFTP relay available to download file.")
            return

        file_bytes = await self.msnftp_relay.receive_file_from_sender(
            sender_host=sender_host,
            sender_port=sender_port,
            auth_cookie=auth_cookie,
            receiver_email=receiver_email or "user@msn.local",
            file_name=filename,
            file_size=filesize
        )

        if not file_bytes:
            logger.warning(f"Failed to receive file '{filename}' from sender {sender_host}:{sender_port}")
            return

        # Save to disk
        file_id = uuid.uuid4().hex[:12]
        storage_dir = getattr(config, "FILES_STORAGE_DIR", os.path.join(config.BASE_DIR, "storage", "files"))
        os.makedirs(storage_dir, exist_ok=True)
        safe_name = os.path.basename(filename)
        stored_name = f"{file_id}_{safe_name}"
        file_path = os.path.join(storage_dir, stored_name)
        with open(file_path, "wb") as f:
            f.write(file_bytes)

        # Save to database
        self.db.save_uploaded_file(
            file_id=file_id,
            original_name=safe_name,
            stored_name=stored_name,
            file_size=len(file_bytes),
            uploaded_by=sender_email
        )
        logger.info(f"Saved received file {safe_name} ({len(file_bytes)}b) with file_id={file_id}")

        # Human-readable size
        size_bytes = len(file_bytes)
        if size_bytes < 1024:
            size_str = f"{size_bytes} B"
        elif size_bytes < 1024 * 1024:
            size_str = f"{size_bytes / 1024:.1f} KB"
        else:
            size_str = f"{size_bytes / (1024 * 1024):.1f} MB"

        http_port = getattr(self, "http_port", getattr(config, "HTTP_PORT", 1865))
        download_url = f"http://{self.external_host}:{http_port}/files/{file_id}/{urllib.parse.quote(safe_name)}"

        chat_msg = (
            f"📎 [Файл от {sender_name}]: {safe_name} ({size_str})\r\n"
            f"Скачать: {download_url}"
        )

        # Broadcast download message into room
        service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
        service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")
        payload = (
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n"
            "X-MMS-IM-Format: FN=Tahoma; EF=; CO=0; CS=0; PF=0\r\n\r\n"
            f"{chat_msg}\r\n"
        ).encode("utf-8")

        if self.session_id:
            self.switchboard_manager.broadcast_message(
                self.session_id, service_email, service_name, payload, db=self.db
            )
            # Also send confirmation into sender's chat window
            self.send_msg_relay(service_email, service_name, payload)

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
