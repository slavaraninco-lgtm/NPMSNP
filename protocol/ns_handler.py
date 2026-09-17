"""
Notification Server (NS) Client Handler.
Handles the complete MSN Messenger NS protocol:
- Version negotiation (VER)
- Client identification (CVR)
- Authentication (MD5 Challenge/Response, TWN)
- Contact synchronization (SYN, GTC, BLP, LSG, LST, BPR)
- Presence and status changes (CHG, ILN, NLN, FLN)
- Contact and group management (ADD, REM, REA, ADG, RMG, REG, PRP)
- Switchboard transfer initiation (XFR SB)
- Keep-alive pings (PNG/QNG)
"""
import asyncio
import logging
import time
from typing import Optional, List, Dict, Any, Tuple
from urllib.parse import quote, unquote

import config
from db.database import Database
from protocol.constants import (
    SUPPORTED_DIALECTS, ListMask, UserStatus, MSNPError
)
from protocol.packet import MSNPReader, MSNPWriter, encode_arg
from protocol.auth import AuthManager
from services.session_manager import SessionManager
from services.switchboard_manager import SwitchboardManager

logger = logging.getLogger("MSNP.NSHandler")


class NSClientHandler:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                 db: Database, auth_manager: AuthManager,
                 session_manager: SessionManager, switchboard_manager: SwitchboardManager,
                 external_host: str = config.EXTERNAL_HOST,
                 ns_port: int = config.NS_PORT,
                 sb_port: int = config.SB_PORT,
                 http_port: int = config.HTTP_PORT):
        self.reader = reader
        self.writer = writer
        self.db = db
        self.auth_manager = auth_manager
        self.session_manager = session_manager
        self.switchboard_manager = switchboard_manager
        self.external_host = external_host
        self.ns_port = ns_port
        self.sb_port = sb_port
        self.http_port = http_port

        self.msnp_reader = MSNPReader()
        self.peername = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        self.closed = False

        # Session State
        self.dialect = 9  # Default MSNP9
        self.authenticated = False
        self.email: str = ""
        self.friendly_name: str = ""
        self.status: str = UserStatus.OFFLINE
        self.client_id: str = "0"
        self.custom_message: str = ""
        self.msn_obj: str = ""
        self.sync_serial: int = 1
        self.initial_presence_sent = False
        self.client_app: str = ""
        self.auth_type: str = ""

    @property
    def is_ansi(self) -> bool:
        app = getattr(self, "client_app", "").lower()
        if "trillian" in app or "miranda" in app or "msnmsgr 5." in app or "msnmsgr 4." in app:
            return True
        if self.dialect < 8:
            return True
        if getattr(self, "auth_type", "") == "MD5" and "gaim" not in app and "pidgin" not in app:
            return True
        return False

    async def run(self) -> None:
        """Main receive loop for the NS connection."""
        logger.info(f"NS Client connected from {self.peername}")
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
            logger.debug(f"NS Client {self.peername} connection reset")
        except Exception as ex:
            logger.warning(f"Error handling NS client {self.peername}: {ex}", exc_info=True)
        finally:
            self.close()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True

        if self.authenticated and self.email:
            try:
                self.session_manager.unregister_session(self.email, self)
                self.db.update_user_status(self.email, UserStatus.OFFLINE)
            except Exception as ex:
                logger.debug(f"Error during close cleanup for {self.email}: {ex}")

        try:
            self.writer.close()
        except Exception:
            pass
        logger.info(f"NS Client {self.email or self.peername} disconnected.")

    def send_raw(self, data: bytes) -> None:
        if self.closed:
            return
        try:
            self.writer.write(data)
        except Exception as ex:
            logger.warning(f"Error sending data to NS client {self.email}: {ex}")
            self.close()

    def send_cmd(self, cmd: str, *args: Any, payload: Optional[bytes] = None) -> None:
        arg_str = " ".join(str(a) for a in args if a is not None)
        logger.debug(f"<<< {cmd} {arg_str}{' [payload ' + str(len(payload)) + 'b]' if payload else ''}")
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
        logger.debug(f">>> {cmd} {' '.join(args)}{' [payload ' + str(len(payload)) + 'b]' if payload else ''}")
        method_name = f"_cmd_{cmd.lower()}"
        method = getattr(self, method_name, None)
        if method:
            try:
                await method(args, payload)
            except Exception as ex:
                logger.error(f"Exception in NS handler {cmd} for {self.email}: {ex}", exc_info=True)
                trid = args[0] if args else "0"
                self.send_error(MSNPError.INTERNAL_SERVER_ERROR, trid)
        else:
            logger.warning(f"Unhandled NS command: {cmd} args={args}")
            trid = args[0] if args else "0"
            self.send_error(MSNPError.SYNTAX_ERROR, trid)

    # Handlers

    async def _cmd_ver(self, args: List[str], payload: Optional[bytes]) -> None:
        # Client sends: VER trid MSNP9 MSNP8 CVR0
        if not args:
            self.close()
            return
        trid = args[0]
        offered = [a.upper() for a in args[1:]]

        chosen = None
        for d in SUPPORTED_DIALECTS:
            if d in offered:
                chosen = d
                break

        # If PREFER_MD5_AUTH is explicitly set to True, negotiate MSNP7
        if chosen in ("MSNP9", "MSNP8") and getattr(config, "PREFER_MD5_AUTH", False):
            chosen = "MSNP7"

        if not chosen:
            # None matched, send 0 and close
            self.send_cmd("VER", trid, "0")
            self.close()
            return

        self.dialect = int(chosen[4:]) if chosen.startswith("MSNP") and chosen[4:].isdigit() else 7
        self.send_cmd("VER", trid, chosen)

    async def _cmd_cvr(self, args: List[str], payload: Optional[bytes]) -> None:
        # CVR trid 0x0409 winnt 5.1 i386 MSNMSGR 6.0.0602 MSMSGS user@email.com
        self.client_app = " ".join(args).lower()
        trid = args[0] if args else "1"
        client_ver = "6.0.0602"
        for a in args[5:]:
            if any(c.isdigit() for c in a):
                client_ver = a
                break
        download_url = f"http://{self.external_host}:{self.http_port}/"
        info_url = download_url
        self.send_cmd("CVR", trid, client_ver, client_ver, client_ver, download_url, info_url)

    async def _cmd_inf(self, args: List[str], payload: Optional[bytes]) -> None:
        # INF trid (used in MSNP < 8)
        trid = args[0] if args else "1"
        self.send_cmd("INF", trid, "MD5")

    async def _cmd_usr(self, args: List[str], payload: Optional[bytes]) -> None:
        # USR trid auth_type stage [args...]
        if len(args) < 3:
            self.close()
            return

        trid = args[0]
        auth_type = args[1].upper()
        self.auth_type = auth_type
        stage = args[2].upper()

        if auth_type == "MD5":
            if stage == "I":
                # USR trid MD5 I email@domain.com
                email = args[3].strip() if len(args) > 3 else ""
                if "@" not in email:
                    self.send_error(MSNPError.INVALID_USER, trid)
                    self.close()
                    return

                self.email = email
                user = self.db.get_user(email)
                if not user and config.AUTO_REGISTER_UNKNOWN_USERS:
                    user = self.db.create_user(email, "123456")

                challenge = self.auth_manager.create_md5_challenge(email)
                self.send_cmd("USR", trid, "MD5", "S", challenge)

            elif stage == "S":
                # USR trid MD5 S <md5_hash>
                response_hash = args[3].strip() if len(args) > 3 else ""
                user = self.db.get_user(self.email)
                if not user:
                    self.send_error(MSNPError.AUTH_FAILED, trid)
                    self.close()
                    return

                if self.auth_manager.verify_md5_response(self.email, response_hash, user.password):
                    await self._login_successful(trid, user)
                else:
                    self.send_error(MSNPError.AUTH_FAILED, trid)
                    self.close()

        elif auth_type == "TWN":
            if stage == "I":
                # USR trid TWN I email@domain.com
                self.email = args[3].strip() if len(args) > 3 else ""
                if "@" not in self.email:
                    self.send_error(MSNPError.INVALID_USER, trid)
                    self.close()
                    return

                user = self.db.get_user(self.email)
                if not user and config.AUTO_REGISTER_UNKNOWN_USERS:
                    user = self.db.create_user(self.email, "123456")

                # If BYPASS_PASSPORT_FOR_TWN is True (default), authenticate user directly!
                # Third-party clients like Gaim/Pidgin and MSN Messenger immediately accept
                # "USR trid OK ..." and proceed to buddy list retrieval without hanging on dead nexus.passport.com:443.
                if getattr(config, "BYPASS_PASSPORT_FOR_TWN", True) and user:
                    logger.info(f"Direct TWN authentication granted for {self.email}")
                    await self._login_successful(trid, user)
                    return

                # Send Tweener passport challenge string
                self.send_cmd("USR", trid, "TWN", "S", "ct=1,rver=1,wp=FS_40SEC_0_COMPACT,lc=1,id=1")

            elif stage == "S":
                # USR trid TWN S <ticket>
                ticket = args[3].strip() if len(args) > 3 else ""
                user = self.db.get_user(self.email)
                if not user and config.AUTO_REGISTER_UNKNOWN_USERS:
                    user = self.db.create_user(self.email, "123456")

                # Verify TWN ticket
                valid = self.auth_manager.verify_twn_ticket(ticket, self.email)
                if not valid and config.AUTO_REGISTER_UNKNOWN_USERS:
                    # In local/testing mode, accept any non-empty ticket for existing user
                    valid = bool(user and ticket)

                if valid and user:
                    await self._login_successful(trid, user)
                else:
                    self.send_error(MSNPError.AUTH_FAILED, trid)
                    self.close()
        else:
            self.send_error(MSNPError.AUTH_FAILED, trid)
            self.close()

    async def _login_successful(self, trid: str, user: Any) -> None:
        self.authenticated = True
        self.email = user.email
        self.friendly_name = user.friendly_name or user.email.split("@")[0]
        self.session_manager.register_session(self.email, self)

        # USR trid OK email friendly_name verified [policy]
        args: List[Any] = ["OK", self.email, self.friendly_name]
        if self.dialect in (6, 7):
            args.append(1)  # Email verified
        elif self.dialect >= 8:
            args.extend([1, 0])  # Email verified (1), Account restriction bit (0)

        self.send_cmd("USR", trid, *args)

    async def _cmd_syn(self, args: List[str], payload: Optional[bytes]) -> None:
        # SYN trid <cached_serial>
        trid = args[0] if args else "1"
        contacts = self.db.get_contacts(self.email)

        service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
        service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")
        # Ensure service account is in the contacts list returned to client
        auto_add = getattr(config, "AUTO_ADD_SERVICE_CONTACT", True)
        if auto_add and self.email.lower() != service_email.lower():
            if not any(c.contact_email.lower() == service_email.lower() for c in contacts):
                c_rec = self.db.add_or_update_contact(self.email, service_email, 11, 0, service_name)
                contacts.append(c_rec)

        groups = self.db.get_groups(self.email)
        total_groups = len(groups) + 1  # 0 = Other Contacts

        user = self.db.get_user(self.email)

        if self.dialect < 6:
            # MSNP2 - MSNP5: SYN trid sync_serial
            self.send_cmd("SYN", trid, self.sync_serial)
            self.send_cmd("GTC", trid, self.sync_serial, "A")
            self.send_cmd("BLP", trid, self.sync_serial, "AL")

            # In MSNP2-5, LST is sent separately for each of the 4 lists (FL, AL, BL, RL)
            list_specs = [("FL", ListMask.FL), ("AL", ListMask.AL), ("BL", ListMask.BL), ("RL", ListMask.RL)]
            for lname, mask in list_specs:
                cs = [c for c in contacts if (c.list_flags & mask)]
                if cs:
                    for i, c in enumerate(cs):
                        # LST trid list_name ser item_index total_in_list email friendly_name
                        self.send_cmd("LST", trid, lname, self.sync_serial, i + 1, len(cs), c.contact_email, c.friendly_name or c.contact_email)
                else:
                    # When list is empty: LST trid list_name ser 0 0
                    self.send_cmd("LST", trid, lname, self.sync_serial, 0, 0)

        elif self.dialect < 8:
            # MSNP6 - MSNP7: SYN trid sync_serial
            self.send_cmd("SYN", trid, self.sync_serial)
            self.send_cmd("GTC", trid, self.sync_serial, "A")
            self.send_cmd("BLP", trid, self.sync_serial, "AL")

            # Groups list
            self.send_cmd("LSG", trid, self.sync_serial, 1, total_groups, 0, "Other Contacts", 0)
            for i, g in enumerate(groups):
                self.send_cmd("LSG", trid, self.sync_serial, i + 2, total_groups, g.id, g.name, 0)

            # Contacts per list
            list_specs = [("FL", ListMask.FL), ("AL", ListMask.AL), ("BL", ListMask.BL), ("RL", ListMask.RL)]
            for lname, mask in list_specs:
                cs = [c for c in contacts if (c.list_flags & mask)]
                if cs:
                    for i, c in enumerate(cs):
                        gid = c.group_id if lname == "FL" else 0
                        self.send_cmd("LST", trid, lname, self.sync_serial, i + 1, len(cs), c.contact_email, c.friendly_name or c.contact_email, gid)
                else:
                    self.send_cmd("LST", trid, lname, self.sync_serial, 0, 0)

        else:
            # MSNP8 - MSNP9+: SYN trid sync_serial total_contacts total_groups
            self.send_cmd("SYN", trid, self.sync_serial, len(contacts), total_groups)
            self.send_cmd("GTC", "A")
            self.send_cmd("BLP", "AL")

            # Phone properties
            if user:
                if user.phone_home:
                    self.send_cmd("PRP", "PHH", user.phone_home)
                if user.phone_work:
                    self.send_cmd("PRP", "PHW", user.phone_work)
                if user.phone_mobile:
                    self.send_cmd("PRP", "PHM", user.phone_mobile)

            # Groups list (LSG)
            self.send_cmd("LSG", 0, "Other Contacts", 0)
            for g in groups:
                self.send_cmd("LSG", g.id, g.name, 0)

            # Contacts list (LST)
            for c in contacts:
                # LST email friendly_name list_mask group_id
                self.send_cmd("LST", c.contact_email, c.friendly_name or c.contact_email, c.list_flags, c.group_id)

    async def _cmd_chg(self, args: List[str], payload: Optional[bytes]) -> None:
        # CHG trid status [client_id] [msnobj]
        if len(args) < 2:
            self.close()
            return

        trid = args[0]
        new_status = args[1].upper()
        client_id = args[2] if len(args) > 2 else "0"
        msn_obj = args[3] if len(args) > 3 else ""

        self.status = new_status
        self.client_id = client_id
        self.msn_obj = msn_obj

        # Update status in DB
        self.db.update_user_status(self.email, self.status, client_id=self.client_id, msn_obj=self.msn_obj)

        # Send confirmation
        if self.dialect >= 9 and msn_obj:
            self.send_cmd("CHG", trid, self.status, self.client_id, msn_obj)
        elif self.dialect >= 8:
            self.send_cmd("CHG", trid, self.status, self.client_id)
        else:
            self.send_cmd("CHG", trid, self.status)

        # First status change after login triggers initial presence and offline messages
        if not self.initial_presence_sent:
            self.initial_presence_sent = True
            # Send ILN of online contacts
            self.session_manager.send_initial_presence(self, trid=trid)

            # Check active penalties and inform user via Service Account
            penalty = self.db.get_user_penalty_status(self.email)
            service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
            service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")
            if penalty.get("is_banned"):
                rem = penalty["ban_remaining"]
                reason = f" Причина: {penalty['ban_reason']}." if penalty["ban_reason"] else ""
                warn_payload = (
                    "MIME-Version: 1.0\r\n"
                    "Content-Type: text/plain; charset=UTF-8\r\n"
                    "X-MMS-IM-Format: FN=Tahoma; EF=; CO=0; CS=0; PF=0\r\n\r\n"
                    f"[{service_name}]:\r\n"
                    f"Внимание: Ваша учетная запись заблокирована (бан).{reason} До окончания блокировки осталось: {rem}. Вы не можете отправлять и принимать сообщения.\r\n"
                ).encode("utf-8")
                self.send_cmd("MSG", service_email, service_name, payload=warn_payload)
            elif penalty.get("is_muted"):
                rem = penalty["mute_remaining"]
                reason = f" Причина: {penalty['mute_reason']}." if penalty["mute_reason"] else ""
                warn_payload = (
                    "MIME-Version: 1.0\r\n"
                    "Content-Type: text/plain; charset=UTF-8\r\n"
                    "X-MMS-IM-Format: FN=Tahoma; EF=; CO=0; CS=0; PF=0\r\n\r\n"
                    f"[{service_name}]:\r\n"
                    f"Внимание: Вам ограничен доступ к отправке сообщений (мут).{reason} До окончания мута осталось: {rem}.\r\n"
                ).encode("utf-8")
                self.send_cmd("MSG", service_email, service_name, payload=warn_payload)

            # Deliver offline messages (if not banned)
            if not penalty.get("is_banned"):
                self._deliver_offline_messages()

        # Broadcast status change to contacts
        self.session_manager.broadcast_status_change(self)

    def _deliver_offline_messages(self) -> None:
        penalty = self.db.get_user_penalty_status(self.email)
        if penalty.get("is_banned"):
            return

        messages = self.db.get_pending_offline_messages(self.email)
        if not messages:
            return

        for m in messages:
            sender_user = self.db.get_user(m.sender)
            s_name = sender_user.friendly_name if (sender_user and sender_user.friendly_name) else m.sender
            mail_payload = (
                "MIME-Version: 1.0\r\n"
                "Content-Type: text/plain; charset=UTF-8\r\n"
                f"X-MMS-IM-Format: FN=Segoe%20UI; EF=; CO=0; CS=0; PF=0\r\n\r\n"
                f"[Offline Message from {s_name} at {m.timestamp}]:\r\n"
                f"{m.message}\r\n"
            ).encode("utf-8")
            self.send_cmd("MSG", m.sender, s_name, payload=mail_payload)

        self.db.mark_offline_messages_delivered(self.email)

    async def _cmd_rea(self, args: List[str], payload: Optional[bytes]) -> None:
        # REA trid email new_friendly_name
        trid = args[0]
        new_name = args[2] if len(args) > 2 else (args[1] if len(args) > 1 else "")
        self.friendly_name = new_name
        self.db.update_friendly_name(self.email, new_name)
        self.sync_serial += 1

        self.send_cmd("REA", trid, self.sync_serial, self.email, self.friendly_name)
        # Broadcast updated friendly name to all online contacts
        self.session_manager.broadcast_friendly_name_change(self.email, self.friendly_name)

    async def _cmd_add(self, args: List[str], payload: Optional[bytes]) -> None:
        # ADD trid list_type contact_email friendly_name [group_id]
        if len(args) < 3:
            return
        trid = args[0]
        list_type = args[1].upper()
        contact_email = args[2].strip()

        # Parse friendly_name and group_id flexibly depending on client format
        if len(args) > 4:
            fname = args[3]
            group_id = int(args[4]) if args[4].isdigit() else 0
        elif len(args) == 4:
            if list_type == "FL" and args[3].isdigit():
                fname = contact_email.split("@")[0]
                group_id = int(args[3])
            else:
                fname = args[3]
                group_id = 0
        else:
            fname = contact_email.split("@")[0]
            group_id = 0

        flag_map = {
            "FL": ListMask.FL,
            "AL": ListMask.AL,
            "BL": ListMask.BL,
            "RL": ListMask.RL,
        }
        flag = flag_map.get(list_type, ListMask.FL)
        c = self.db.add_or_update_contact(self.email, contact_email, int(flag), group_id, fname)
        self.sync_serial += 1

        friendly_disp = c.friendly_name or fname or contact_email

        # Response: ADD trid list_type sync_serial contact_email friendly_name [group_id]
        if list_type == "FL":
            if self.dialect >= 8:
                self.send_cmd("ADD", trid, list_type, self.sync_serial, contact_email, friendly_disp, c.group_id)
            else:
                self.send_cmd("ADD", trid, list_type, self.sync_serial, contact_email, friendly_disp)
            # If contact is online and user is on contact's AL/FL, send presence immediately
            service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
            service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")
            if contact_email.lower() == service_email.lower():
                self.send_iln(trid, UserStatus.ONLINE, service_email, friendly_disp or service_name, "0", "")
            else:
                contact_sess = self.session_manager.get_session(contact_email)
                if contact_sess and contact_sess.status != UserStatus.OFFLINE and contact_sess.status != UserStatus.HIDDEN:
                    self.send_iln(
                        trid, contact_sess.status, contact_sess.email,
                        contact_sess.friendly_name, contact_sess.client_id, contact_sess.msn_obj
                    )
                # Notify online contact that they have been added (so their client shows reverse list / notification)
                if contact_sess:
                    contact_sess.send_cmd("ADD", "0", "RL", contact_sess.sync_serial, self.email, self.friendly_name or self.email)
        else:
            self.send_cmd("ADD", trid, list_type, self.sync_serial, contact_email, friendly_disp)

    async def _cmd_rem(self, args: List[str], payload: Optional[bytes]) -> None:
        # REM trid list_type contact_email [group_id]
        if len(args) < 3:
            return
        trid = args[0]
        list_type = args[1].upper()
        contact_email = args[2].strip()

        flag_map = {"FL": ListMask.FL, "AL": ListMask.AL, "BL": ListMask.BL}
        flag = flag_map.get(list_type, ListMask.FL)
        self.db.remove_contact_flag(self.email, contact_email, int(flag))
        self.sync_serial += 1

        self.send_cmd("REM", trid, list_type, self.sync_serial, contact_email)

        # If removed from FL, notify online contact that they were removed from RL
        if list_type == "FL":
            contact_sess = self.session_manager.get_session(contact_email)
            if contact_sess:
                contact_sess.send_cmd("REM", "0", "RL", contact_sess.sync_serial, self.email)

    async def _cmd_adg(self, args: List[str], payload: Optional[bytes]) -> None:
        # ADG trid group_name 0
        trid = args[0]
        group_name = args[1] if len(args) > 1 else "New Group"
        group = self.db.add_group(self.email, group_name)
        self.sync_serial += 1
        self.send_cmd("ADG", trid, self.sync_serial, group.name, group.id)

    async def _cmd_rmg(self, args: List[str], payload: Optional[bytes]) -> None:
        # RMG trid group_id
        trid = args[0]
        group_id = int(args[1]) if len(args) > 1 and args[1].isdigit() else 0
        self.db.remove_group(self.email, group_id)
        self.sync_serial += 1
        self.send_cmd("RMG", trid, self.sync_serial, group_id)

    async def _cmd_reg(self, args: List[str], payload: Optional[bytes]) -> None:
        # REG trid group_id new_name 0
        trid = args[0]
        group_id = int(args[1]) if len(args) > 1 and args[1].isdigit() else 0
        new_name = args[2] if len(args) > 2 else "Group"
        self.db.rename_group(self.email, group_id, new_name)
        self.sync_serial += 1
        self.send_cmd("REG", trid, self.sync_serial, group_id, new_name)

    async def _cmd_prp(self, args: List[str], payload: Optional[bytes]) -> None:
        # PRP trid property_name value
        trid = args[0]
        prop_name = args[1].upper() if len(args) > 1 else ""
        prop_val = args[2] if len(args) > 2 else ""
        self.db.update_phone(self.email, prop_name, prop_val)
        self.send_cmd("PRP", trid, prop_name, prop_val)

    async def _cmd_png(self, args: List[str], payload: Optional[bytes]) -> None:
        # Client sends keepalive PNG -> responds with QNG 60
        self.send_cmd("QNG", 60)

    async def _cmd_qng(self, args: List[str], payload: Optional[bytes]) -> None:
        pass

    async def _cmd_xfr(self, args: List[str], payload: Optional[bytes]) -> None:
        # XFR trid SB (or NS)
        if len(args) < 2:
            return
        trid = args[0]
        dest = args[1].upper()

        if dest == "SB":
            # Allocate chat room and cookie
            session_id, cookie = self.switchboard_manager.allocate_session(self.email)
            sb_addr = f"{self.external_host}:{self.sb_port}"
            self.send_cmd("XFR", trid, "SB", sb_addr, "CKI", cookie)
        elif dest == "NS":
            ns_addr = f"{self.external_host}:{self.ns_port}"
            self.send_cmd("XFR", trid, "NS", ns_addr, "0", ns_addr)
        else:
            self.send_error(MSNPError.INVALID_PARAMETER, trid)

    async def _cmd_uux(self, args: List[str], payload: Optional[bytes]) -> None:
        # UUX trid len\r\n<payload>
        trid = args[0] if args else "1"
        if payload:
            text = payload.decode("utf-8", errors="replace")
            # Extract Personal Status Message (PSM)
            if "<PSM>" in text and "</PSM>" in text:
                psm = text.split("<PSM>")[1].split("</PSM>")[0]
                self.custom_message = psm
                self.db.update_user_status(self.email, self.status, custom_message=psm)

        self.send_cmd("UUX", trid, 0)
        # Broadcast UBX
        self._broadcast_ubx()

    def _broadcast_ubx(self) -> None:
        ubx_payload = f"<Data><PSM>{self.custom_message}</PSM><CurrentMedia></CurrentMedia></Data>".encode("utf-8")
        for contact in self.db.get_contacts(self.email):
            if contact.list_flags & ListMask.FL:
                sess = self.session_manager.get_session(contact.contact_email)
                if sess:
                    sess.send_cmd("UBX", self.email, payload=ubx_payload)

    async def _cmd_gtc(self, args: List[str], payload: Optional[bytes]) -> None:
        # GTC trid value (A or N)
        trid = args[0] if args else "1"
        val = args[1].upper() if len(args) > 1 else "A"
        self.sync_serial += 1
        self.send_cmd("GTC", trid, self.sync_serial, val)

    async def _cmd_blp(self, args: List[str], payload: Optional[bytes]) -> None:
        # BLP trid value (AL or BL)
        trid = args[0] if args else "1"
        val = args[1].upper() if len(args) > 1 else "AL"
        self.sync_serial += 1
        self.send_cmd("BLP", trid, self.sync_serial, val)

    async def _cmd_url(self, args: List[str], payload: Optional[bytes]) -> None:
        # URL trid [type]
        trid = args[0] if args else "1"
        self.send_cmd("URL", trid, "/unused1", "/unused2", 1)

    async def _cmd_qry(self, args: List[str], payload: Optional[bytes]) -> None:
        # QRY trid [response]
        trid = args[0] if args else "1"
        self.send_cmd("QRY", trid)

    async def _cmd_out(self, args: List[str], payload: Optional[bytes]) -> None:
        # Client requests clean logout
        self.close()

    # Presence Sender Helpers

    def send_iln(self, trid: str, status: str, email: str, friendly_name: str, client_id: str, msn_obj: str) -> None:
        """Sends Initial Online Presence (ILN) for an online contact."""
        if self.dialect >= 9 and msn_obj:
            self.send_cmd("ILN", trid, status, email, friendly_name or email, client_id, msn_obj)
        elif self.dialect >= 8:
            self.send_cmd("ILN", trid, status, email, friendly_name or email, client_id)
        else:
            self.send_cmd("ILN", trid, status, email, friendly_name or email)

    def send_nln(self, status: str, email: str, friendly_name: str, client_id: str, msn_obj: str) -> None:
        """Broadcasts Online Status Change (NLN) to this client."""
        if self.dialect >= 9 and msn_obj:
            self.send_cmd("NLN", status, email, friendly_name or email, client_id, msn_obj)
        elif self.dialect >= 8:
            self.send_cmd("NLN", status, email, friendly_name or email, client_id)
        else:
            self.send_cmd("NLN", status, email, friendly_name or email)

    def send_fln(self, email: str) -> None:
        """Broadcasts Offline Status (FLN) to this client."""
        self.send_cmd("FLN", email)

    def send_rng(self, session_id: int, sb_host: str, sb_port: int, cookie: str,
                 caller_email: str, caller_friendly_name: str) -> None:
        """Sends Switchboard Ringing invitation (RNG) to this callee."""
        sb_addr = f"{sb_host}:{sb_port}"
        self.send_cmd("RNG", session_id, sb_addr, "CKI", cookie, caller_email, caller_friendly_name or caller_email)
