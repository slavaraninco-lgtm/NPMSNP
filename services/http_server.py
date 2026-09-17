"""
HTTP Passport / Nexus Server and Web Dashboard for MSNP Server.
Provides:
- Legacy Passport Nexus redirection (/rdr/pprdr.asp)
- Tweener login ticket issuance (/login.srf)
- Web interface with 4 classic retro tabs:
    1. Регистрация (Registration & Setup Instructions)
    2. Управление учетными записями (User Management: list, filter, ban, mute, direct message, password/name, disconnect, delete)
    3. Оповещения (Broadcast & Custom Alerts: maintenance presets, custom notifications, service bot)
    4. Состояние сервера (Server Status: services, metrics, real-time active connections monitoring)
- RESTful JSON API endpoints for dashboard operations
"""
import asyncio
import html
import hmac
import json
import logging
import os
import secrets
import time
import urllib.parse
from http import HTTPStatus
from typing import Dict, Any, Optional, List

import config
from db.database import Database
from db.security import decrypt_password
from protocol.auth import AuthManager
from services.session_manager import SessionManager
from services.switchboard_manager import SwitchboardManager

logger = logging.getLogger("MSNP.HTTPServer")


class HTTPServer:
    def __init__(self, host: str, port: int, external_host: str, db: Database,
                 auth_manager: AuthManager, session_manager: SessionManager,
                 switchboard_manager: Optional[SwitchboardManager] = None,
                 auto_register: bool = True):
        self.host = host
        self.port = port
        self.external_host = external_host
        self.db = db
        self.auth_manager = auth_manager
        self.session_manager = session_manager
        self.switchboard_manager = switchboard_manager
        self.auto_register = auto_register
        self.start_time = time.time()
        self._server = None
        self._admin_sessions: Dict[str, float] = {}

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.host, self.port)
        logger.info(f"HTTP Nexus / Web Admin Server listening on http://{self.host}:{self.port} (Public: {self.external_host}:{self.port})")

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            line = await reader.readline()
            if not line:
                writer.close()
                await writer.wait_closed()
                return

            req_line = line.decode("utf-8", errors="replace").strip()
            parts = req_line.split(" ")
            if len(parts) < 2:
                writer.close()
                return

            method = parts[0].upper()
            full_path = parts[1]
            url_parsed = urllib.parse.urlparse(full_path)
            path = url_parsed.path

            headers: Dict[str, str] = {}
            while True:
                header_line = await reader.readline()
                if not header_line or header_line == b"\r\n":
                    break
                h_str = header_line.decode("utf-8", errors="replace").strip()
                if ":" in h_str:
                    k, v = h_str.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            body = b""
            if "content-length" in headers:
                try:
                    content_len = int(headers["content-length"])
                    if content_len > 0:
                        body = await reader.readexactly(content_len)
                except Exception:
                    pass

            await self._dispatch(writer, method, path, headers, body)

        except Exception as ex:
            logger.warning(f"HTTP handler error: {ex}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    def _parse_body(self, headers: Dict[str, str], body: bytes) -> Dict[str, Any]:
        """Parses JSON or form-urlencoded body into a dictionary."""
        content_type = headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                return json.loads(body.decode("utf-8", errors="replace"))
            except Exception:
                return {}
        else:
            try:
                parsed = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"))
                return {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
            except Exception:
                return {}

    def _dispatch_service_notice(self, target_email: str, service_email: str, service_name: str, message: str) -> bool:
        """
        Delivers a service notice to an online user strictly as a 1-on-1 private message (личка).
        """
        if not self.switchboard_manager:
            return False
        sb_port = getattr(config, "SB_PORT", 1864)
        return self.switchboard_manager.deliver_service_pm(
            target_email, message, self.session_manager, self.external_host, sb_port
        )

    def get_admin_password(self) -> str:
        """Retrieves and decrypts the configured administrator password."""
        raw_pwd = getattr(config, "ADMIN_PASSWORD", "")
        secret_key = getattr(config, "DB_SECRET_KEY", "msnp_server_default_master_salt_key_2026")
        if not raw_pwd:
            return ""
        return decrypt_password(raw_pwd, secret_key)

    def _parse_cookies(self, headers: Dict[str, str]) -> Dict[str, str]:
        """Parses standard Cookie header into key-value dictionary."""
        cookie_str = headers.get("cookie", "")
        cookies: Dict[str, str] = {}
        if cookie_str:
            for part in cookie_str.split(";"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    cookies[k.strip()] = v.strip()
        return cookies

    def _is_valid_admin_token(self, token: str) -> bool:
        """Validates that session token exists and has not expired."""
        if not token or token not in self._admin_sessions:
            return False
        expires_at = self._admin_sessions[token]
        if time.time() > expires_at:
            del self._admin_sessions[token]
            return False
        return True

    def _is_admin_authenticated(self, headers: Dict[str, str]) -> bool:
        """
        Verifies if request has valid administrator credentials.
        Supports:
        - Header X-Admin-Password: <plain_password>
        - Header X-Admin-Token: <token>
        - Header Authorization: Bearer <token>
        - Cookie admin_session=<token>
        """
        admin_pwd = self.get_admin_password()
        if not admin_pwd:
            return False

        # 1. Direct password header
        hdr_pwd = headers.get("x-admin-password")
        if hdr_pwd and hmac.compare_digest(hdr_pwd, admin_pwd):
            return True

        # 2. Token header
        token = headers.get("x-admin-token")
        if token and self._is_valid_admin_token(token):
            return True

        # 3. Authorization Bearer header
        auth_hdr = headers.get("authorization", "")
        if auth_hdr.lower().startswith("bearer "):
            b_token = auth_hdr[7:].strip()
            if self._is_valid_admin_token(b_token):
                return True

        # 4. Cookie session
        cookies = self._parse_cookies(headers)
        c_token = cookies.get("admin_session")
        if c_token and self._is_valid_admin_token(c_token):
            return True

        return False

    async def _dispatch(self, writer: asyncio.StreamWriter, method: str, path: str,
                         headers: Dict[str, str], body: bytes) -> None:
        path_lower = path.lower()

        # 1. Nexus Redirection (/rdr/pprdr.asp)
        if "/rdr/pprdr.asp" in path_lower:
            login_url = f"http://{self.external_host}:{self.port}/login.srf"
            reg_url = f"http://{self.external_host}:{self.port}/"
            resp_headers = {
                "PassportURLs": f"DARes={login_url},DALogin={login_url},DAReg={reg_url}",
                "Content-Type": "text/plain",
            }
            self._send_response(writer, HTTPStatus.OK, resp_headers, b"Passport Nexus Ready\r\n")
            return

        # 2. Tweener / Passport Login (/login.srf)
        if "/login.srf" in path_lower:
            auth_header = headers.get("authorization", "")
            email = None
            password = None

            if "passport1.4" in auth_header.lower():
                pairs = auth_header.replace("Passport1.4 ", "").split(",")
                for pair in pairs:
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        k = k.strip().lower()
                        v = urllib.parse.unquote(v.strip())
                        if k == "sign-in":
                            email = v
                        elif k in ("pwd", "password"):
                            password = v

            if not email:
                params = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"))
                if "email" in params:
                    email = params["email"][0]
                    password = params.get("password", [""])[0]

            if email and password:
                user = self.db.get_user(email)
                if not user and self.auto_register:
                    user = self.db.create_user(email, password)

                if user and user.password == password:
                    ticket = self.auth_manager.create_twn_ticket(email)
                    resp_headers = {
                        "Authentication-Info": f"Passport1.4 da-status=success,tkt={ticket}",
                        "Content-Type": "text/plain",
                    }
                    self._send_response(writer, HTTPStatus.OK, resp_headers, b"OK\r\n")
                    logger.info(f"Tweener login success for {email}")
                    return

            resp_headers = {
                "WWW-Authenticate": "Passport1.4 da-status=failed",
                "Content-Type": "text/plain",
            }
            self._send_response(writer, HTTPStatus.UNAUTHORIZED, resp_headers, b"Authentication Failed\r\n")
            return

        # 3. Admin Authentication Endpoints
        # POST /api/admin/login
        if path_lower == "/api/admin/login" and method == "POST":
            data = self._parse_body(headers, body)
            pwd = data.get("password") or ""
            admin_pwd = self.get_admin_password()
            if admin_pwd and hmac.compare_digest(pwd, admin_pwd):
                token = secrets.token_hex(32)
                self._admin_sessions[token] = time.time() + 86400 * 7  # 7 days
                resp_hdrs = {
                    "Set-Cookie": f"admin_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={86400 * 7}"
                }
                self._send_json(writer, {"success": True, "token": token}, resp_headers=resp_hdrs)
                return
            else:
                self._send_json(writer, {"error": "Неверный пароль администратора"}, status=HTTPStatus.UNAUTHORIZED)
                return

        # POST /api/admin/logout
        if path_lower == "/api/admin/logout" and method == "POST":
            cookies = self._parse_cookies(headers)
            token = headers.get("x-admin-token") or cookies.get("admin_session")
            if token and token in self._admin_sessions:
                del self._admin_sessions[token]
            resp_hdrs = {
                "Set-Cookie": "admin_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
            }
            self._send_json(writer, {"success": True}, resp_headers=resp_hdrs)
            return

        # GET /api/admin/check
        if path_lower == "/api/admin/check" and method == "GET":
            is_auth = self._is_admin_authenticated(headers)
            self._send_json(writer, {"authenticated": is_auth})
            return

        # 4. API: User Registration (POST /api/register) - PUBLIC, NO ADMIN AUTH REQUIRED
        if path_lower == "/api/register" and method == "POST":
            data = self._parse_body(headers, body)
            email = (data.get("email") or "").strip()
            password = data.get("password") or ""
            confirm_password = data.get("confirm_password")
            friendly_name = (data.get("friendly_name") or "").strip() or None

            if not email or not password or "@" not in email:
                self._send_json(writer, {"error": "Некорректный адрес email или пустой пароль"}, status=HTTPStatus.BAD_REQUEST)
                return

            if confirm_password is not None and confirm_password != password:
                self._send_json(writer, {"error": "Пароли не совпадают"}, status=HTTPStatus.BAD_REQUEST)
                return

            if self.db.get_user(email):
                self._send_json(writer, {"error": "Пользователь с таким email уже зарегистрирован"}, status=HTTPStatus.CONFLICT)
                return

            user = self.db.create_user(email, password, friendly_name)
            self._send_json(writer, {
                "success": True,
                "email": user.email,
                "friendly_name": user.friendly_name
            })
            return

        # 5. ALL OTHER /api/ ENDPOINTS REQUIRE ADMIN AUTHENTICATION
        if path_lower.startswith("/api/"):
            if not self._is_admin_authenticated(headers):
                self._send_json(writer, {
                    "error": "Доступ запрещен: требуется авторизация администратора",
                    "auth_required": True
                }, status=HTTPStatus.UNAUTHORIZED)
                return

        # 6. API: Get Users List (GET /api/users)
        if path_lower == "/api/users" and method == "GET":
            users = self.db.get_all_users_with_meta()
            for u in users:
                email = u["email"]
                is_on = self.session_manager.is_online(email)
                sess = self.session_manager.get_session(email)
                u["is_online"] = is_on
                u["live_status"] = sess.status if (sess and is_on) else "FLN"
                u["peer"] = sess.peername if sess else ""
            self._send_json(writer, {"users": users})
            return

        # 5. API: Update User Password (POST /api/users/update_password)
        if path_lower == "/api/users/update_password" and method == "POST":
            data = self._parse_body(headers, body)
            email = (data.get("email") or "").strip()
            new_password = data.get("password") or ""
            if not email or not new_password:
                self._send_json(writer, {"error": "Email и новый пароль обязательны"}, status=HTTPStatus.BAD_REQUEST)
                return
            if not self.db.get_user(email):
                self._send_json(writer, {"error": "Пользователь не найден"}, status=HTTPStatus.NOT_FOUND)
                return
            ok = self.db.update_password(email, new_password)
            self._send_json(writer, {"success": ok})
            return

        # 6. API: Update User Friendly Name (POST /api/users/update_name)
        if path_lower == "/api/users/update_name" and method == "POST":
            data = self._parse_body(headers, body)
            email = (data.get("email") or "").strip()
            friendly_name = (data.get("friendly_name") or "").strip()
            if not email:
                self._send_json(writer, {"error": "Email обязателен"}, status=HTTPStatus.BAD_REQUEST)
                return
            if not self.db.get_user(email):
                self._send_json(writer, {"error": "Пользователь не найден"}, status=HTTPStatus.NOT_FOUND)
                return
            self.db.update_friendly_name(email, friendly_name)
            sess = self.session_manager.get_session(email)
            if sess:
                sess.friendly_name = friendly_name
                try:
                    self.session_manager.broadcast_presence(email, sess.status, sess.client_id, sess.msn_obj)
                except Exception:
                    pass
            self._send_json(writer, {"success": True, "friendly_name": friendly_name})
            return

        # 7. API: Disconnect User (POST /api/users/disconnect)
        if path_lower == "/api/users/disconnect" and method == "POST":
            data = self._parse_body(headers, body)
            email = (data.get("email") or "").strip()
            if not email:
                self._send_json(writer, {"error": "Email обязателен"}, status=HTTPStatus.BAD_REQUEST)
                return
            disconnected = self.session_manager.disconnect_user(email)
            self._send_json(writer, {"success": True, "disconnected": disconnected})
            return

        # 8. API: Delete User (POST /api/users/delete)
        if path_lower == "/api/users/delete" and method == "POST":
            data = self._parse_body(headers, body)
            email = (data.get("email") or "").strip()
            if not email:
                self._send_json(writer, {"error": "Email обязателен"}, status=HTTPStatus.BAD_REQUEST)
                return
            self.session_manager.disconnect_user(email)
            ok = self.db.delete_user(email)
            self._send_json(writer, {"success": ok})
            return

        # 9. API: Ban User (POST /api/users/ban)
        if path_lower == "/api/users/ban" and method == "POST":
            data = self._parse_body(headers, body)
            email = (data.get("email") or "").strip()
            duration = data.get("duration_minutes")
            duration_minutes = int(duration) if (duration is not None and str(duration).isdigit() and int(duration) > 0) else None
            reason = (data.get("reason") or "Нарушение правил сервера").strip()

            if not email or not self.db.get_user(email):
                self._send_json(writer, {"error": "Пользователь не найден"}, status=HTTPStatus.NOT_FOUND)
                return

            self.db.ban_user(email, duration_minutes, reason)
            penalty = self.db.get_user_penalty_status(email)

            service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
            service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")
            rem = penalty["ban_remaining"]
            notice = f"Ваша учетная запись заблокирована (бан). Причина: {reason}. Срок: {rem}. Вы не можете отправлять и принимать сообщения."

            if not self._dispatch_service_notice(email, service_email, service_name, notice):
                self.db.save_offline_message(service_email, email, notice)

            self._send_json(writer, {"success": True, "penalty": penalty})
            return

        # 10. API: Unban User (POST /api/users/unban)
        if path_lower == "/api/users/unban" and method == "POST":
            data = self._parse_body(headers, body)
            email = (data.get("email") or "").strip()
            if not email or not self.db.get_user(email):
                self._send_json(writer, {"error": "Пользователь не найден"}, status=HTTPStatus.NOT_FOUND)
                return

            ok = self.db.unban_user(email)
            service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
            service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")
            notice = "Блокировка вашей учетной записи (бан) снята администратором. Вы снова можете отправлять и принимать сообщения."

            if not self._dispatch_service_notice(email, service_email, service_name, notice):
                self.db.save_offline_message(service_email, email, notice)

            self._send_json(writer, {"success": ok})
            return

        # 11. API: Mute User (POST /api/users/mute)
        if path_lower == "/api/users/mute" and method == "POST":
            data = self._parse_body(headers, body)
            email = (data.get("email") or "").strip()
            duration = data.get("duration_minutes")
            duration_minutes = int(duration) if (duration is not None and str(duration).isdigit() and int(duration) > 0) else None
            reason = (data.get("reason") or "Нарушение правил общения").strip()

            if not email or not self.db.get_user(email):
                self._send_json(writer, {"error": "Пользователь не найден"}, status=HTTPStatus.NOT_FOUND)
                return

            self.db.mute_user(email, duration_minutes, reason)
            penalty = self.db.get_user_penalty_status(email)

            service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
            service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")
            rem = penalty["mute_remaining"]
            notice = f"Вам временно ограничен доступ к отправке сообщений (мут). Причина: {reason}. Срок: {rem}. Вы можете принимать сообщения."

            if not self._dispatch_service_notice(email, service_email, service_name, notice):
                self.db.save_offline_message(service_email, email, notice)

            self._send_json(writer, {"success": True, "penalty": penalty})
            return

        # 12. API: Unmute User (POST /api/users/unmute)
        if path_lower == "/api/users/unmute" and method == "POST":
            data = self._parse_body(headers, body)
            email = (data.get("email") or "").strip()
            if not email or not self.db.get_user(email):
                self._send_json(writer, {"error": "Пользователь не найден"}, status=HTTPStatus.NOT_FOUND)
                return

            ok = self.db.unmute_user(email)
            service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
            service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")
            notice = "Ограничение на отправку сообщений (мут) снято администратором. Вы снова можете отправлять сообщения."

            if not self._dispatch_service_notice(email, service_email, service_name, notice):
                self.db.save_offline_message(service_email, email, notice)

            self._send_json(writer, {"success": ok})
            return

        # 13. API: Send Notifications / Alerts (POST /api/notify)
        if path_lower == "/api/notify" and method == "POST":
            data = self._parse_body(headers, body)
            target = (data.get("target") or "online").strip().lower()
            message = (data.get("message") or "").strip()

            if not message:
                self._send_json(writer, {"error": "Текст оповещения не может быть пустым"}, status=HTTPStatus.BAD_REQUEST)
                return

            service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
            service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")

            delivered_online = 0
            saved_offline = 0

            def deliver_to_user(u_email: str) -> bool:
                """Delivers system alert to an online user via Switchboard and NS."""
                return self._dispatch_service_notice(u_email, service_email, service_name, message)

            if target == "online":
                active_users = list(self.session_manager._active_sessions.keys())
                for u_email in active_users:
                    if u_email.lower() == service_email.lower():
                        continue
                    if deliver_to_user(u_email):
                        delivered_online += 1

                self._send_json(writer, {
                    "success": True,
                    "target": "online",
                    "delivered_online": delivered_online,
                    "saved_offline": 0
                })
                return

            elif target == "all":
                active_users = list(self.session_manager._active_sessions.keys())
                for u_email in active_users:
                    if u_email.lower() == service_email.lower():
                        continue
                    if deliver_to_user(u_email):
                        delivered_online += 1

                all_users = self.db.get_all_users()
                for u in all_users:
                    if u.email.lower() == service_email.lower():
                        continue
                    if not self.session_manager.is_online(u.email):
                        self.db.save_offline_message(service_email, u.email, message)
                        saved_offline += 1

                self._send_json(writer, {
                    "success": True,
                    "target": "all",
                    "delivered_online": delivered_online,
                    "saved_offline": saved_offline
                })
                return

            else:
                target_email = target
                user = self.db.get_user(target_email)
                if not user:
                    self._send_json(writer, {"error": f"Пользователь {target_email} не найден в базе данных"}, status=HTTPStatus.NOT_FOUND)
                    return

                is_online = self.session_manager.is_online(target_email)
                if is_online:
                    if deliver_to_user(target_email):
                        delivered_online = 1
                else:
                    self.db.save_offline_message(service_email, target_email, message)
                    saved_offline = 1

                self._send_json(writer, {
                    "success": True,
                    "target": target_email,
                    "delivered_online": delivered_online,
                    "saved_offline": saved_offline
                })
                return

        # 14. API: Server Status (GET /api/status)
        if path_lower == "/api/status" and method == "GET":
            uptime_seconds = int(time.time() - self.start_time)
            stats = self.db.get_database_stats()
            active_users = self.session_manager.get_active_users_list()
            self._send_json(writer, {
                "project": getattr(config, "PROJECT_NAME", "NPMSNP"),
                "server_name": getattr(config, "SERVER_NAME", "NPMSNP Server"),
                "version": getattr(config, "SERVER_VERSION", "1.0.0"),
                "status": "online",
                "uptime_seconds": uptime_seconds,
                "total_users": stats.get("total_users", 0),
                "external_host": self.external_host,
                "ports": {
                    "ns": 1863,
                    "sb": 1864,
                    "http": self.port
                },
                "stats": stats,
                "active_users_count": len(active_users),
                "active_users": active_users,
            })
            return

        # 16. Web UI Dashboard (/)
        if path_lower in ("/", "/index.html", "/admin"):
            html_content = self._render_dashboard(headers=headers)
            resp_headers = {"Content-Type": "text/html; charset=utf-8"}
            self._send_response(writer, HTTPStatus.OK, resp_headers, html_content.encode("utf-8"))
            return

        # 404
        self._send_response(writer, HTTPStatus.NOT_FOUND, {"Content-Type": "text/plain"}, b"Not Found\r\n")

    def _send_response(self, writer: asyncio.StreamWriter, status: HTTPStatus,
                       headers: Dict[str, str], body: bytes) -> None:
        header_lines = [f"HTTP/1.1 {status.value} {status.phrase}"]
        headers["Content-Length"] = str(len(body))
        headers["Connection"] = "close"
        for k, v in headers.items():
            header_lines.append(f"{k}: {v}")
        head = "\r\n".join(header_lines) + "\r\n\r\n"
        writer.write(head.encode("latin-1") + body)

    def _send_json(self, writer: asyncio.StreamWriter, obj: Any, status: HTTPStatus = HTTPStatus.OK,
                   resp_headers: Optional[Dict[str, str]] = None) -> None:
        body = json.dumps(obj, indent=2).encode("utf-8")
        headers = {"Content-Type": "application/json; charset=utf-8"}
        if resp_headers:
            headers.update(resp_headers)
        self._send_response(writer, status, headers, body)

    def _render_dashboard(self, headers: Optional[Dict[str, str]] = None) -> str:
        headers = headers or {}
        is_admin = self._is_admin_authenticated(headers)

        db_stats = self.db.get_database_stats() if is_admin else {}
        users = self.db.get_all_users_with_meta() if is_admin else []
        active_users = self.session_manager.get_active_users_list() if is_admin else []
        uptime_total_sec = int(time.time() - self.start_time)
        uptime_hours = uptime_total_sec // 3600
        uptime_mins = (uptime_total_sec % 3600) // 60
        uptime_secs = uptime_total_sec % 60
        uptime_str = f"{uptime_hours} ч. {uptime_mins} мин. {uptime_secs} сек."

        db_size_kb = round(db_stats.get("db_size_bytes", 0) / 1024, 1)

        if is_admin:
            auth_badge_html = '''<span id="authStatusText" style="color: #008000; font-weight: bold;">&#128274; Администратор: Авторизован</span> <button type="button" id="authBtn" class="btn-classic btn-sm" onclick="submitAdminLogout()" style="margin-left: 6px;">Выйти</button>'''
        else:
            auth_badge_html = '''<span id="authStatusText" style="color: #666;">&#128274; Гостевой режим (регистрация)</span> <button type="button" id="authBtn" class="btn-classic btn-sm" onclick="openLoginModal()" style="margin-left: 6px;">Вход администратора</button>'''

        # Pre-render initial rows for accounts table
        user_rows = []
        for idx, u in enumerate(users):
            is_on = self.session_manager.is_online(u["email"])
            sess = self.session_manager.get_session(u["email"])
            status_badge = f'<span style="color: #008000; font-weight: bold;">[В СЕТИ: {html.escape(sess.status if sess else "NLN")}]</span>' if is_on else '<span style="color: #666666;">[ОФЛАЙН]</span>'

            # Penalty Badges
            penalties_html = []
            if u.get("is_banned"):
                rem_b = html.escape(u.get("ban_remaining", ""))
                penalties_html.append(f'<span style="color: #cc0000; font-weight: bold; margin-left: 3px;" title="Бан: {html.escape(u.get("ban_reason", ""))}">[БАН: {rem_b}]</span>')
            if u.get("is_muted"):
                rem_m = html.escape(u.get("mute_remaining", ""))
                penalties_html.append(f'<span style="color: #b05a00; font-weight: bold; margin-left: 3px;" title="Мут: {html.escape(u.get("mute_reason", ""))}">[МУТ: {rem_m}]</span>')

            penalty_str = " ".join(penalties_html)

            row_class = ' class="row-alt"' if idx % 2 == 1 else ""
            email_escaped = html.escape(u["email"])
            name_escaped = html.escape(u["friendly_name"] or "")
            email_js = u["email"].replace("'", "\\'")
            name_js = (u["friendly_name"] or "").replace("'", "\\'")
            created_str = html.escape(u["created_at"][:19] if u["created_at"] else "")
            last_seen_str = html.escape(u["last_seen"][:19] if u["last_seen"] else "")

            action_disconnect = f'<button type="button" class="btn-classic btn-sm btn-warn" onclick="disconnectUser(\'{email_js}\')" title="Разорвать текущую сессию">Сброс</button> ' if is_on else ''

            btn_ban_text = "Разбан" if u.get("is_banned") else "Бан"
            btn_ban_cls = "btn-classic btn-sm" if not u.get("is_banned") else "btn-classic btn-sm btn-danger"

            btn_mute_text = "Размут" if u.get("is_muted") else "Мут"
            btn_mute_cls = "btn-classic btn-sm" if not u.get("is_muted") else "btn-classic btn-sm btn-warn"

            user_rows.append(f"""
            <tr{row_class} id="row-{email_escaped}" data-email="{email_escaped.lower()}" data-name="{name_escaped.lower()}">
                <td><strong>{email_escaped}</strong></td>
                <td id="name-cell-{email_escaped}">{name_escaped}</td>
                <td>{status_badge} {penalty_str}</td>
                <td align="center"><strong>{u['contact_count']}</strong></td>
                <td style="color: #555555;">{created_str}</td>
                <td style="color: #555555;">{last_seen_str}</td>
                <td align="center">
                    <button type="button" class="{btn_ban_cls}" onclick="openBanModal('{email_js}', {1 if u.get('is_banned') else 0})" title="Управление блокировкой">{btn_ban_text}</button>
                    <button type="button" class="{btn_mute_cls}" onclick="openMuteModal('{email_js}', {1 if u.get('is_muted') else 0})" title="Управление мутом">{btn_mute_text}</button>
                    <button type="button" class="btn-classic btn-sm" onclick="openDirectMsgModal('{email_js}')" title="Отправить сообщение от служебного аккаунта">ЛС</button>
                    <button type="button" class="btn-classic btn-sm" onclick="openPasswordModal('{email_js}')" title="Сменить пароль">Пароль</button>
                    <button type="button" class="btn-classic btn-sm" onclick="openNameModal('{email_js}', '{name_js}')" title="Изменить имя">Имя</button>
                    {action_disconnect}
                    <button type="button" class="btn-classic btn-sm btn-danger" onclick="deleteUser('{email_js}')" title="Удалить аккаунт">Удалить</button>
                </td>
            </tr>
            """)

        # Pre-render initial rows for active connections table
        conn_rows = []
        for idx, sess in enumerate(active_users):
            row_class = ' class="row-alt"' if idx % 2 == 1 else ""
            c_email = html.escape(sess.get("email", ""))
            c_name = html.escape(sess.get("friendly_name", "") or "")
            c_peer = html.escape(str(sess.get("peer", "")))
            c_status = html.escape(str(sess.get("status", "NLN")))
            c_client_id = html.escape(str(sess.get("client_id", "0")))
            c_email_js = sess.get("email", "").replace("'", "\\'")

            conn_rows.append(f"""
            <tr{row_class}>
                <td><strong>{c_email}</strong></td>
                <td>{c_name}</td>
                <td><span class="code-font">{c_peer}</span></td>
                <td><span style="color: #008000; font-weight: bold;">{c_status}</span></td>
                <td><span class="code-font">{c_client_id}</span></td>
                <td align="center">
                    <button type="button" class="btn-classic btn-sm btn-warn" onclick="disconnectUser('{c_email_js}')">Отключить</button>
                </td>
            </tr>
            """)

        if is_admin:
            user_rows_html = "\n".join(user_rows) if user_rows else "<tr><td colspan='7' align='center' style='color: #666; padding: 12px;'>В базе данных пока нет зарегистрированных пользователей</td></tr>"
            conn_rows_html = "\n".join(conn_rows) if conn_rows else "<tr><td colspan='6' align='center' style='color: #666; padding: 12px;'>Нет активных подключений в данный момент</td></tr>"
        else:
            user_rows_html = "<tr><td colspan='7' align='center' style='color: #666; padding: 25px;'><strong>Доступ к списку пользователей защищен паролем администратора.</strong><br><br><button type='button' class='btn-classic' onclick='openLoginModal()'>Ввести пароль администратора</button></td></tr>"
            conn_rows_html = "<tr><td colspan='6' align='center' style='color: #666; padding: 20px;'><strong>Доступ к списку подключений защищен паролем администратора.</strong><br><br><button type='button' class='btn-classic' onclick='openLoginModal()'>Ввести пароль администратора</button></td></tr>"

        service_email = getattr(config, "SERVICE_ACCOUNT_EMAIL", "system@msn.local")
        service_name = getattr(config, "SERVICE_ACCOUNT_NAME", "Служба сообщений MSN")
        project_name = getattr(config, "PROJECT_NAME", "NPMSNP")
        server_name = getattr(config, "SERVER_NAME", "NPMSNP Server")
        server_version = getattr(config, "SERVER_VERSION", "1.0.0")

        return f"""<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title>{project_name} - Панель управления</title>
    <style type="text/css">
        body {{
            background-color: #d4d0c8;
            color: #000000;
            font-family: Tahoma, Verdana, Arial, sans-serif;
            font-size: 11px;
            margin: 0;
            padding: 12px;
        }}
        #container {{
            width: 990px;
            margin: 0 auto;
            background-color: #ece9d8;
            border-top: 2px solid #ffffff;
            border-left: 2px solid #ffffff;
            border-right: 2px solid #404040;
            border-bottom: 2px solid #404040;
            padding: 10px;
        }}
        .header-bar {{
            background: linear-gradient(to right, #000080, #3a6ea5);
            color: #ffffff;
            padding: 5px 8px;
            font-weight: bold;
            font-size: 13px;
            border-top: 1px solid #999999;
            border-left: 1px solid #999999;
            border-right: 1px solid #333333;
            border-bottom: 1px solid #333333;
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .sub-bar {{
            background-color: #dfdfdf;
            border: 1px solid #808080;
            padding: 4px 8px;
            font-size: 11px;
            margin-bottom: 10px;
        }}

        /* SysTabControl32 Classic Windows Tabs */
        .tab-bar {{
            display: flex;
            margin: 0 0 -2px 0;
            padding: 0 0 0 4px;
            position: relative;
            z-index: 2;
        }}
        .tab-btn {{
            background-color: #d4d0c8;
            border-top: 2px solid #ffffff;
            border-left: 2px solid #ffffff;
            border-right: 2px solid #404040;
            border-bottom: 2px solid #808080;
            padding: 6px 14px;
            margin-right: 3px;
            cursor: pointer;
            font-family: Tahoma, Verdana, Arial, sans-serif;
            font-size: 11px;
            font-weight: normal;
            color: #000000;
            position: relative;
            top: 2px;
            outline: none;
        }}
        .tab-btn:hover {{
            background-color: #e2dfd8;
        }}
        .tab-btn.active {{
            background-color: #ece9d8;
            border-top: 2px solid #ffffff;
            border-left: 2px solid #ffffff;
            border-right: 2px solid #404040;
            border-bottom: 2px solid #ece9d8;
            font-weight: bold;
            top: 0px;
            padding-top: 7px;
            padding-bottom: 7px;
            z-index: 4;
        }}
        .tab-content {{
            background-color: #ece9d8;
            border-top: 2px solid #ffffff;
            border-left: 2px solid #ffffff;
            border-right: 2px solid #404040;
            border-bottom: 2px solid #404040;
            padding: 12px;
            min-height: 480px;
            position: relative;
            z-index: 1;
        }}
        .tab-pane {{
            display: none;
        }}
        .tab-pane.active {{
            display: block;
        }}

        fieldset {{
            border: 1px solid #808080;
            padding: 10px;
            margin-bottom: 12px;
            background-color: #f0eee6;
        }}
        legend {{
            font-weight: bold;
            color: #000000;
            padding: 0 4px;
        }}
        table.data-table {{
            width: 100%;
            border-collapse: collapse;
            border: 1px solid #808080;
            background-color: #ffffff;
            font-size: 11px;
        }}
        table.data-table th {{
            background-color: #d4d0c8;
            border: 1px solid #808080;
            padding: 4px 6px;
            text-align: left;
            font-weight: bold;
            color: #000000;
        }}
        table.data-table td {{
            border: 1px solid #d4d0c8;
            padding: 4px 6px;
        }}
        table.data-table tr.row-alt {{
            background-color: #f7f6f0;
        }}
        table.data-table tr:hover {{
            background-color: #ffffdd;
        }}
        input.text-input, select.text-input, textarea.text-input {{
            font-family: Tahoma, Arial, sans-serif;
            font-size: 11px;
            background-color: #ffffff;
            color: #000000;
            border-top: 1px solid #808080;
            border-left: 1px solid #808080;
            border-right: 1px solid #ffffff;
            border-bottom: 1px solid #ffffff;
            padding: 3px 5px;
            box-sizing: border-box;
        }}
        .btn-classic {{
            font-family: Tahoma, Arial, sans-serif;
            font-size: 11px;
            color: #000000;
            background-color: #d4d0c8;
            border-top: 1px solid #ffffff;
            border-left: 1px solid #ffffff;
            border-right: 2px solid #404040;
            border-bottom: 2px solid #404040;
            padding: 4px 14px;
            cursor: pointer;
            font-weight: bold;
            outline: none;
        }}
        .btn-classic:active {{
            border-top: 2px solid #404040;
            border-left: 2px solid #404040;
            border-right: 1px solid #ffffff;
            border-bottom: 1px solid #ffffff;
            padding: 5px 13px 3px 15px;
        }}
        .btn-sm {{
            padding: 2px 6px;
            font-size: 10px;
            font-weight: normal;
        }}
        .btn-sm:active {{
            padding: 3px 5px 1px 7px;
        }}
        .btn-danger {{
            color: #990000;
            font-weight: bold;
        }}
        .btn-warn {{
            color: #b05a00;
            font-weight: bold;
        }}
        .status-msg {{
            margin-top: 8px;
            padding: 6px 8px;
            font-size: 11px;
            display: none;
        }}
        .msg-success {{
            border: 1px solid #008000;
            background-color: #f0fff0;
            color: #006600;
            font-weight: bold;
        }}
        .msg-error {{
            border: 1px solid #cc0000;
            background-color: #fff0f0;
            color: #cc0000;
            font-weight: bold;
        }}
        .footer {{
            border-top: 1px solid #808080;
            margin-top: 12px;
            padding-top: 6px;
            text-align: center;
            color: #555555;
            font-size: 10px;
        }}
        .code-box {{
            font-family: "Courier New", Courier, monospace;
            background-color: #ffffff;
            border: 1px solid #808080;
            padding: 6px;
            font-size: 11px;
            line-height: 1.4;
        }}
        .code-font {{
            font-family: "Courier New", Courier, monospace;
            font-size: 11px;
        }}

        /* Classic Modal Dialog Windows */
        .modal-overlay {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.35);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }}
        .modal-dialog {{
            background-color: #ece9d8;
            border-top: 2px solid #ffffff;
            border-left: 2px solid #ffffff;
            border-right: 2px solid #000000;
            border-bottom: 2px solid #000000;
            box-shadow: 3px 3px 10px rgba(0,0,0,0.5);
            width: 420px;
            padding: 3px;
        }}
        .modal-titlebar {{
            background: linear-gradient(to right, #000080, #1084d0);
            color: #ffffff;
            padding: 3px 6px;
            font-weight: bold;
            font-size: 11px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .modal-close-btn {{
            background-color: #d4d0c8;
            border-top: 1px solid #ffffff;
            border-left: 1px solid #ffffff;
            border-right: 1px solid #000000;
            border-bottom: 1px solid #000000;
            font-family: Arial, sans-serif;
            font-size: 10px;
            font-weight: bold;
            width: 16px;
            height: 14px;
            line-height: 12px;
            text-align: center;
            cursor: pointer;
            color: #000000;
        }}
        .modal-body {{
            padding: 12px 10px;
        }}
        .modal-footer {{
            padding: 8px 10px;
            text-align: right;
            border-top: 1px solid #d4d0c8;
        }}
        .template-btn {{
            text-align: left;
            margin-bottom: 4px;
            width: 100%;
            padding: 5px 8px;
            font-size: 11px;
            background-color: #e4e2d5;
            border: 1px solid #808080;
            cursor: pointer;
            font-family: Tahoma, Arial, sans-serif;
        }}
        .template-btn:hover {{
            background-color: #ffffdd;
            border-color: #000080;
        }}
    </style>
</head>
<body>

<div id="container">
    <div class="header-bar">
        <span>{project_name} &bull; Панель управления сервером [v{server_version}]</span>
        <span style="font-size: 11px; font-weight: normal;">Microsoft Notification Protocol Service &bull; {project_name}</span>
    </div>

    <div class="sub-bar" style="display: flex; justify-content: space-between; align-items: center;">
        <div>
            Проект: <strong style="color: #000080;">{project_name}</strong> &bull;
            Статус: <strong style="color: #008000;">РАБОТАЕТ</strong> &bull;
            Хост: <strong>{self.external_host}</strong> &bull;
            Порты: <strong>NS: 1863 | SB: 1864 | HTTP: {self.port}</strong> &bull;
            Служебный бот: <strong>{service_name} ({service_email})</strong>
        </div>
        <div id="adminAuthBadge">
            {auth_badge_html}
        </div>
    </div>

    <!-- Вкладки (Tabs) -->
    <div class="tab-bar">
        <button type="button" id="tabBtn-reg" class="tab-btn active" onclick="switchTab('reg')">Регистрация</button>
        <button type="button" id="tabBtn-accounts" class="tab-btn" onclick="switchTab('accounts')">Управление учетными записями</button>
        <button type="button" id="tabBtn-alerts" class="tab-btn" onclick="switchTab('alerts')">Оповещения</button>
        <button type="button" id="tabBtn-server" class="tab-btn" onclick="switchTab('server')">Состояние сервера</button>
    </div>

    <div class="tab-content">

        <!-- ВКЛАДКА 1: РЕГИСТРАЦИЯ -->
        <div id="pane-reg" class="tab-pane active">
            <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr valign="top">
                    <!-- Левая колонка: Форма регистрации -->
                    <td width="55%" style="padding-right: 12px;">
                        <fieldset>
                            <legend>Регистрация нового пользователя</legend>
                            <form id="regForm">
                                <table width="100%" border="0" cellspacing="4" cellpadding="2">
                                    <tr>
                                        <td width="35%"><b>Email (Логин):</b></td>
                                        <td width="65%">
                                            <input type="email" id="reg_email" class="text-input" style="width: 100%;" placeholder="user@msn.local" required>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td><b>Пароль:</b></td>
                                        <td>
                                            <input type="password" id="reg_password" class="text-input" style="width: 100%;" placeholder="Введите пароль" required>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td><b>Подтверждение пароля:</b></td>
                                        <td>
                                            <input type="password" id="reg_confirm" class="text-input" style="width: 100%;" placeholder="Повторите пароль" required>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td><b>Отображаемое имя (Ник):</b></td>
                                        <td>
                                            <input type="text" id="reg_friendly_name" class="text-input" style="width: 100%;" placeholder="Никнейм в контакт-листе">
                                        </td>
                                    </tr>
                                    <tr>
                                        <td></td>
                                        <td style="padding-top: 6px;">
                                            <input type="submit" value="Создать учетную запись" class="btn-classic">
                                        </td>
                                    </tr>
                                </table>
                                <div id="regMsg" class="status-msg"></div>
                            </form>
                        </fieldset>

                        <fieldset>
                            <legend>Особенности учетных записей</legend>
                            <div style="line-height: 1.4; color: #333333;">
                                &bull; <strong>Служебный аккаунт:</strong> В системе работает <code>{service_email}</code> ({service_name}), который уведомляет пользователей о тех. работах, банах и мутах.<br>
                                &bull; <strong>Авто-регистрация:</strong> Если в конфигурации включен <code>AUTO_REGISTER_UNKNOWN_USERS</code>, новые клиенты регистрируются автоматически при первом входе.<br>
                                &bull; <strong>Пароли:</strong> Хранятся в локальной базе <code>database.db</code> и поддерживают MD5 Challenge и Tweener (TWN).
                            </div>
                        </fieldset>
                    </td>

                    <!-- Правая колонка: Инструкция по подключению клиентов -->
                    <td width="45%">
                        <fieldset>
                            <legend>Параметры подключения клиентов к серверу</legend>
                            <div class="code-box">
                                Сервер авторизации (Host): <strong>{self.external_host}</strong><br>
                                Порт уведомлений (NS Port): <strong>1863</strong><br>
                                Порт чатов (SB Port): <strong>1864</strong><br>
                                Порт HTTP Nexus & Tweener: <strong>{self.port}</strong><br>
                                Домен по умолчанию: <strong>msn.local</strong>
                            </div>

                            <div style="margin-top: 8px;">
                                <b>Поддерживаемые IM-клиенты:</b>
                                <ul style="margin: 4px 0 0 16px; padding: 0; line-height: 1.4;">
                                    <li><strong>Gaim 0.x / 1.x</strong> (Протокол MSN, Сервер: {self.external_host}:1863)</li>
                                    <li><strong>Pidgin 2.x</strong> (Протокол MSN)</li>
                                    <li><strong>Trillian Pro 1.x - 3.x</strong> (Плагин MSN Messenger)</li>
                                    <li><strong>Miranda IM</strong> (Плагин msn.dll)</li>
                                    <li><strong>MSN Messenger 4.0 - 7.5</strong> (С перенаправлением через hosts)</li>
                                </ul>
                            </div>

                            <div style="margin-top: 8px; border-top: 1px solid #d4d0c8; padding-top: 6px; color: #555;">
                                <strong>Примечание:</strong> На сервере активен режим <code>BYPASS_PASSPORT_FOR_TWN</code>, благодаря чему клиенты авторизуются мгновенно без зависаний на недоступных официальных серверах Microsoft Passport.
                            </div>
                        </fieldset>
                    </td>
                </tr>
            </table>
        </div>

        <!-- ВКЛАДКА 2: УПРАВЛЕНИЕ УЧЕТНЫМИ ЗАПИСЯМИ -->
        <div id="pane-accounts" class="tab-pane">
            <fieldset>
                <legend>Фильтр и управление списком пользователей</legend>
                <table width="100%" border="0" cellspacing="0" cellpadding="2">
                    <tr>
                        <td width="55%">
                            <b>Поиск:</b>
                            <input type="text" id="userSearchInput" class="text-input" style="width: 230px;" placeholder="Поиск по логину или имени..." oninput="filterUsersTable()">
                            <button type="button" class="btn-classic" onclick="refreshAccountsList()">Обновить</button>
                        </td>
                        <td width="45%" align="right">
                            <span id="usersCounter" style="font-weight: bold; color: #333;">Всего аккаунтов: {len(users)} | В сети: {len(active_users)}</span>
                        </td>
                    </tr>
                </table>
            </fieldset>

            <table class="data-table" id="usersTable">
                <thead>
                    <tr>
                        <th width="22%">Email (Логин)</th>
                        <th width="18%">Отображаемое имя</th>
                        <th width="16%">Статус / Наказания</th>
                        <th width="6%" style="text-align: center;">Контактов</th>
                        <th width="11%">Создан</th>
                        <th width="11%">Был в сети</th>
                        <th width="16%" style="text-align: center;">Действия</th>
                    </tr>
                </thead>
                <tbody id="usersTableBody">
                    {user_rows_html}
                </tbody>
            </table>
        </div>

        <!-- ВКЛАДКА 3: ОПОВЕЩЕНИЯ (НОВАЯ ВКЛАДКА) -->
        <div id="pane-alerts" class="tab-pane">
            <table width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr valign="top">
                    <!-- Левая колонка: Быстрые шаблоны тех. работ -->
                    <td width="48%" style="padding-right: 12px;">
                        <fieldset>
                            <legend>Быстрые шаблоны оповещений о тех. работах</legend>
                            <p style="margin-top: 0; color: #444;">Нажмите на шаблон, чтобы автоматически подставить его текст:</p>
                            <button type="button" class="template-btn" onclick="applyTemplate('Сервер будет перезагружен через 15 минут для проведения технических работ. Пожалуйста, завершите важные диалоги.')">
                                &bull; <strong>Перезагрузка через 15 мин</strong> (Технические работы)
                            </button>
                            <button type="button" class="template-btn" onclick="applyTemplate('Сервер уходит на техническое обслуживание через 5 минут. Пожалуйста, сохраните переписку.')">
                                &bull; <strong>Техобслуживание через 5 мин</strong> (Сохранение переписки)
                            </button>
                            <button type="button" class="template-btn" onclick="applyTemplate('Плановые технические работы успешно завершены. Все службы сервера работают в штатном режиме.')">
                                &bull; <strong>Работы завершены</strong> (Все службы работают в штатном режиме)
                            </button>
                            <button type="button" class="template-btn" onclick="applyTemplate('Внимание: на сервере проводятся регламентные технические работы. Возможны кратковременные перебои связи.')">
                                &bull; <strong>Регламентные работы</strong> (Возможны перебои связи)
                            </button>
                            <button type="button" class="template-btn" onclick="applyTemplate('Предупреждение администрации: спам, флуд и нецензурные выражения запрещены правилами сервера.')">
                                &bull; <strong>Соблюдение правил чата</strong> (Предупреждение о спаме/флуде)
                            </button>
                        </fieldset>

                        <fieldset>
                            <legend>Служебная учетная запись</legend>
                            <div style="line-height: 1.4; color: #333333;">
                                &bull; <strong>Отправитель:</strong> <code>{service_email}</code> ({service_name})<br>
                                &bull; <strong>Доставка в реальном времени:</strong> Онлайн-пользователи получают сообщение прямо в окне чата Switchboard и во всплывающем уведомлении клиента.<br>
                                &bull; <strong>Офлайн-сообщения:</strong> При выборе режима «Всем пользователям» офлайн-пользователи увидят оповещение сразу при следующем входе.
                            </div>
                        </fieldset>
                    </td>

                    <!-- Правая колонка: Форма отправки произвольного оповещения -->
                    <td width="52%">
                        <fieldset>
                            <legend>Отправка произвольного оповещения</legend>
                            <form id="notifyForm">
                                <table width="100%" border="0" cellspacing="3" cellpadding="2">
                                    <tr>
                                        <td width="28%"><b>Кому отправить:</b></td>
                                        <td width="72%">
                                            <select id="notifyTarget" class="text-input" style="width: 100%;" onchange="onNotifyTargetChange()">
                                                <option value="online">Всем пользователям онлайн (сейчас в сети)</option>
                                                <option value="all">Всем пользователям в базе (включая офлайн)</option>
                                                <option value="custom">Конкретному пользователю (по логину)...</option>
                                            </select>
                                        </td>
                                    </tr>
                                    <tr id="notifyCustomRow" style="display: none;">
                                        <td><b>Логин пользователя:</b></td>
                                        <td>
                                            <input type="text" id="notifyCustomEmail" class="text-input" style="width: 100%;" placeholder="user@msn.local">
                                        </td>
                                    </tr>
                                    <tr valign="top">
                                        <td style="padding-top: 6px;"><b>Текст оповещения:</b></td>
                                        <td style="padding-top: 6px;">
                                            <textarea id="notifyMessageText" class="text-input" rows="7" style="width: 100%;" placeholder="Введите текст сообщения для пользователей..." required></textarea>
                                        </td>
                                    </tr>
                                    <tr>
                                        <td></td>
                                        <td style="padding-top: 6px;">
                                            <input type="submit" value="Отправить оповещение" class="btn-classic">
                                            <button type="button" class="btn-classic" style="margin-left: 6px;" onclick="clearNotifyForm()">Очистить</button>
                                        </td>
                                    </tr>
                                </table>
                                <div id="notifyStatusMsg" class="status-msg"></div>
                            </form>
                        </fieldset>
                    </td>
                </tr>
            </table>
        </div>

        <!-- ВКЛАДКА 4: СОСТОЯНИЕ СЕРВЕРА -->
        <div id="pane-server" class="tab-pane">
            <fieldset>
                <legend>Статус служб и производительность сервера</legend>
                <table width="100%" border="0" cellspacing="3" cellpadding="2">
                    <tr>
                        <td width="25%"><b>Проект / Сервер:</b></td>
                        <td width="25%"><span style="color: #000080; font-weight: bold;">{project_name} (v{server_version})</span></td>
                        <td width="25%"><b>Время непрерывной работы:</b></td>
                        <td width="25%"><span id="serverUptimeText"><strong>{uptime_str}</strong></span></td>
                    </tr>
                    <tr>
                        <td><b>Notification Server (NS):</b></td>
                        <td><span style="color: #008000; font-weight: bold;">[АКТИВЕН, ПОРТ 1863]</span></td>
                        <td><b>Пользователей онлайн:</b></td>
                        <td><span id="serverActiveCountText" style="color: #008000; font-weight: bold;">{len(active_users)}</span> / <span id="serverTotalUsersText">{len(users)}</span></td>
                    </tr>
                    <tr>
                        <td><b>Switchboard Server (SB):</b></td>
                        <td><span style="color: #008000; font-weight: bold;">[АКТИВЕН, ПОРТ 1864]</span></td>
                        <td><b>Связей в списках контактов:</b></td>
                        <td><span id="serverTotalContactsText"><strong>{db_stats.get('total_contacts', 0)}</strong></span> (Групп: <span id="serverTotalGroupsText">{db_stats.get('total_groups', 0)}</span>)</td>
                    </tr>
                    <tr>
                        <td><b>HTTP Nexus & Tweener:</b></td>
                        <td><span style="color: #008000; font-weight: bold;">[АКТИВЕН, ПОРТ {self.port}]</span></td>
                        <td><b>Офлайн-сообщений в очереди:</b></td>
                        <td><span id="serverPendingMsgsText"><strong>{db_stats.get('pending_offline_messages', 0)}</strong></span></td>
                    </tr>
                    <tr>
                        <td><b>Файл базы данных:</b></td>
                        <td colspan="3"><code>database.db</code> ({db_size_kb} КБ, SQLite WAL)</td>
                    </tr>
                </table>
            </fieldset>

            <fieldset>
                <legend>Мониторинг активных подключений в реальном времени</legend>
                <table width="100%" border="0" cellspacing="0" cellpadding="2" style="margin-bottom: 6px;">
                    <tr>
                        <td>
                            <label style="cursor: pointer;">
                                <input type="checkbox" id="autoRefreshStatusCb" onchange="toggleAutoRefresh(this.checked)">
                                <b>Автообновление каждые 5 сек.</b>
                            </label>
                            <button type="button" class="btn-classic" style="margin-left: 8px;" onclick="refreshServerStatus()">Обновить сейчас</button>
                        </td>
                        <td align="right">
                            <span id="lastUpdatedStatus" style="color: #555;">Обновлено: только что</span>
                        </td>
                    </tr>
                </table>

                <table class="data-table" id="connectionsTable">
                    <thead>
                        <tr>
                            <th width="24%">Email</th>
                            <th width="22%">Отображаемое имя</th>
                            <th width="20%">Адрес клиента (IP:порт)</th>
                            <th width="12%">Статус</th>
                            <th width="12%">Client ID</th>
                            <th width="10%" style="text-align: center;">Действие</th>
                        </tr>
                    </thead>
                    <tbody id="connectionsTableBody">
                        {conn_rows_html}
                    </tbody>
                </table>
            </fieldset>
        </div>

    </div>

    <div class="footer">
        {project_name} Server Administration Console &bull; Microsoft Notification Protocol Emulator &bull; Готово
    </div>
</div>

<!-- Модальное окно: Бан пользователя -->
<div id="banModal" class="modal-overlay">
    <div class="modal-dialog">
        <div class="modal-titlebar">
            <span>Блокировка учетной записи (Бан)</span>
            <div class="modal-close-btn" onclick="closeModal('banModal')">&times;</div>
        </div>
        <div class="modal-body">
            <p style="margin-top: 0;">Пользователь: <strong id="modalBanEmail"></strong></p>
            <p style="color: #555; margin-bottom: 8px; line-height: 1.3;">
                В забаненном состоянии пользователь <strong>не может отправлять и принимать сообщения</strong>. При попытке отправки бот автоматически сообщит причину и оставшееся время бана.
            </p>
            <table width="100%" border="0" cellspacing="2" cellpadding="2">
                <tr>
                    <td width="35%"><b>Срок бана:</b></td>
                    <td width="65%">
                        <select id="modalBanDuration" class="text-input" style="width: 100%;">
                            <option value="15">15 минут</option>
                            <option value="60" selected>1 час</option>
                            <option value="360">6 часов</option>
                            <option value="1440">24 часа (1 день)</option>
                            <option value="10080">7 дней</option>
                            <option value="0">Бессрочно (Навсегда)</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td><b>Причина бана:</b></td>
                    <td>
                        <input type="text" id="modalBanReason" class="text-input" style="width: 100%;" value="Нарушение правил сервера">
                    </td>
                </tr>
            </table>
            <div id="modalBanMsg" class="status-msg"></div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn-classic btn-danger" onclick="submitBan(true)">Применить бан</button>
            <button type="button" class="btn-classic" id="btnLiftBan" onclick="submitBan(false)" style="margin-left: 4px;">Снять бан</button>
            <button type="button" class="btn-classic" onclick="closeModal('banModal')" style="margin-left: 4px;">Отмена</button>
        </div>
    </div>
</div>

<!-- Модальное окно: Мут пользователя -->
<div id="muteModal" class="modal-overlay">
    <div class="modal-dialog">
        <div class="modal-titlebar">
            <span>Ограничение отправки сообщений (Мут)</span>
            <div class="modal-close-btn" onclick="closeModal('muteModal')">&times;</div>
        </div>
        <div class="modal-body">
            <p style="margin-top: 0;">Пользователь: <strong id="modalMuteEmail"></strong></p>
            <p style="color: #555; margin-bottom: 8px; line-height: 1.3;">
                Замьюченный пользователь <strong>может принимать сообщения</strong> от всех, но <strong>не может отправлять</strong> сообщения в чаты.
            </p>
            <table width="100%" border="0" cellspacing="2" cellpadding="2">
                <tr>
                    <td width="35%"><b>Срок мута:</b></td>
                    <td width="65%">
                        <select id="modalMuteDuration" class="text-input" style="width: 100%;">
                            <option value="15">15 минут</option>
                            <option value="60" selected>1 час</option>
                            <option value="360">6 часов</option>
                            <option value="1440">24 часа (1 день)</option>
                            <option value="10080">7 дней</option>
                            <option value="0">Бессрочно (Навсегда)</option>
                        </select>
                    </td>
                </tr>
                <tr>
                    <td><b>Причина мута:</b></td>
                    <td>
                        <input type="text" id="modalMuteReason" class="text-input" style="width: 100%;" value="Флуд / Спам">
                    </td>
                </tr>
            </table>
            <div id="modalMuteMsg" class="status-msg"></div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn-classic btn-warn" onclick="submitMute(true)">Применить мут</button>
            <button type="button" class="btn-classic" id="btnLiftMute" onclick="submitMute(false)" style="margin-left: 4px;">Снять мут</button>
            <button type="button" class="btn-classic" onclick="closeModal('muteModal')" style="margin-left: 4px;">Отмена</button>
        </div>
    </div>
</div>

<!-- Модальное окно: Отправка ЛС от имени бота -->
<div id="directMsgModal" class="modal-overlay">
    <div class="modal-dialog">
        <div class="modal-titlebar">
            <span>Служебное сообщение пользователю</span>
            <div class="modal-close-btn" onclick="closeModal('directMsgModal')">&times;</div>
        </div>
        <div class="modal-body">
            <p style="margin-top: 0;">Получатель: <strong id="modalDirectEmail"></strong></p>
            <p style="color: #555; margin-bottom: 6px;">Отправитель: <strong>{service_name}</strong></p>
            <table width="100%" border="0" cellspacing="2" cellpadding="2">
                <tr valign="top">
                    <td width="25%"><b>Сообщение:</b></td>
                    <td width="75%">
                        <textarea id="modalDirectText" class="text-input" rows="4" style="width: 100%;" placeholder="Введите текст сообщения..."></textarea>
                    </td>
                </tr>
            </table>
            <div id="modalDirectStatus" class="status-msg"></div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn-classic" onclick="submitDirectMsg()">Отправить</button>
            <button type="button" class="btn-classic" onclick="closeModal('directMsgModal')" style="margin-left: 4px;">Отмена</button>
        </div>
    </div>
</div>

<!-- Модальное окно: Смена пароля -->
<div id="passwordModal" class="modal-overlay">
    <div class="modal-dialog">
        <div class="modal-titlebar">
            <span>Смена пароля</span>
            <div class="modal-close-btn" onclick="closeModal('passwordModal')">&times;</div>
        </div>
        <div class="modal-body">
            <p style="margin-top: 0;">Пользователь: <strong id="modalPwdEmail"></strong></p>
            <table width="100%" border="0" cellspacing="2" cellpadding="2">
                <tr>
                    <td width="35%"><b>Новый пароль:</b></td>
                    <td width="65%"><input type="password" id="modalNewPassword" class="text-input" style="width: 100%;"></td>
                </tr>
            </table>
            <div id="modalPwdMsg" class="status-msg"></div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn-classic" onclick="submitPasswordChange()">Сохранить</button>
            <button type="button" class="btn-classic" onclick="closeModal('passwordModal')" style="margin-left: 4px;">Отмена</button>
        </div>
    </div>
</div>

<!-- Модальное окно: Изменение имени -->
<div id="nameModal" class="modal-overlay">
    <div class="modal-dialog">
        <div class="modal-titlebar">
            <span>Изменение отображаемого имени</span>
            <div class="modal-close-btn" onclick="closeModal('nameModal')">&times;</div>
        </div>
        <div class="modal-body">
            <p style="margin-top: 0;">Пользователь: <strong id="modalNameEmail"></strong></p>
            <table width="100%" border="0" cellspacing="2" cellpadding="2">
                <tr>
                    <td width="35%"><b>Новое имя:</b></td>
                    <td width="65%"><input type="text" id="modalNewName" class="text-input" style="width: 100%;"></td>
                </tr>
            </table>
            <div id="modalNameMsg" class="status-msg"></div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn-classic" onclick="submitNameChange()">Сохранить</button>
            <button type="button" class="btn-classic" onclick="closeModal('nameModal')" style="margin-left: 4px;">Отмена</button>
        </div>
    </div>
</div>

<!-- Модальное окно: Вход администратора -->
<div id="loginModal" class="modal-overlay">
    <div class="modal-dialog" style="max-width: 360px;">
        <div class="modal-titlebar">
            <span>{project_name} - Вход администратора</span>
            <div class="modal-close-btn" onclick="closeModal('loginModal')">&times;</div>
        </div>
        <div class="modal-body">
            <p style="margin-top: 0; color: #333; line-height: 1.4;">
                Для доступа к управлению учетными записями, отправке оповещений и серверу введите пароль администратора:
            </p>
            <form id="adminLoginForm" onsubmit="event.preventDefault(); submitAdminLogin();">
                <table width="100%" border="0" cellspacing="2" cellpadding="2">
                    <tr>
                        <td width="30%"><b>Пароль:</b></td>
                        <td width="70%">
                            <input type="password" id="adminPasswordInput" class="text-input" style="width: 100%;" placeholder="Пароль администратора" required autofocus>
                        </td>
                    </tr>
                </table>
                <div id="loginStatusMsg" class="status-msg" style="display: none; margin-top: 8px;"></div>
                <div style="margin-top: 12px; text-align: right;">
                    <button type="submit" class="btn-classic">Войти</button>
                    <button type="button" class="btn-classic" onclick="closeModal('loginModal')" style="margin-left: 4px;">Отмена</button>
                </div>
            </form>
        </div>
    </div>
</div>

<script type="text/javascript">
    var isAdminLoggedIn = {'true' if is_admin else 'false'};
    var currentTargetEmail = '';
    var autoRefreshTimer = null;

    function adminFetch(url, options) {{
        options = options || {{}};
        options.headers = options.headers || {{}};
        var token = localStorage.getItem('msnp_admin_token');
        if (token) {{
            options.headers['X-Admin-Token'] = token;
        }}
        return fetch(url, options).then(function(res) {{
            if (res.status === 401) {{
                updateAdminAuthUI(false);
                openLoginModal();
            }}
            return res;
        }});
    }}

    function openLoginModal() {{
        var msg = document.getElementById('loginStatusMsg');
        if (msg) msg.style.display = 'none';
        var inp = document.getElementById('adminPasswordInput');
        if (inp) inp.value = '';
        var m = document.getElementById('loginModal');
        if (m) {{
            m.style.display = 'flex';
            setTimeout(function() {{ if (inp) inp.focus(); }}, 100);
        }}
    }}

    async function submitAdminLogin() {{
        var inp = document.getElementById('adminPasswordInput');
        var pwd = inp ? inp.value : '';
        var msgBox = document.getElementById('loginStatusMsg');
        if (msgBox) msgBox.style.display = 'none';
        if (!pwd) return;

        try {{
            var res = await fetch('/api/admin/login', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ password: pwd }})
            }});
            var data = await res.json();
            if (res.ok && data.success) {{
                localStorage.setItem('msnp_admin_token', data.token);
                updateAdminAuthUI(true);
                closeModal('loginModal');
                var activePane = document.querySelector('.tab-pane.active');
                if (activePane && activePane.id === 'pane-accounts') {{
                    refreshAccountsList();
                }} else if (activePane && activePane.id === 'pane-server') {{
                    refreshServerStatus();
                }}
            }} else {{
                if (msgBox) {{
                    msgBox.textContent = data.error || 'Неверный пароль администратора';
                    msgBox.className = 'status-msg msg-error';
                    msgBox.style.display = 'block';
                }}
            }}
        }} catch (err) {{
            if (msgBox) {{
                msgBox.textContent = 'Ошибка связи: ' + err.message;
                msgBox.className = 'status-msg msg-error';
                msgBox.style.display = 'block';
            }}
        }}
    }}

    async function submitAdminLogout() {{
        try {{
            await adminFetch('/api/admin/logout', {{ method: 'POST' }});
        }} catch (e) {{}}
        localStorage.removeItem('msnp_admin_token');
        updateAdminAuthUI(false);
        switchTab('reg');
        var tb = document.getElementById('usersTableBody');
        if (tb) tb.innerHTML = '<tr><td colspan="7" align="center" style="color: #666; padding: 25px;"><strong>Доступ к списку пользователей защищен паролем администратора.</strong><br><br><button type="button" class="btn-classic" onclick="openLoginModal()">Ввести пароль администратора</button></td></tr>';
        var cb = document.getElementById('connectionsTableBody');
        if (cb) cb.innerHTML = '<tr><td colspan="6" align="center" style="color: #666; padding: 20px;"><strong>Доступ к списку подключений защищен паролем администратора.</strong><br><br><button type="button" class="btn-classic" onclick="openLoginModal()">Ввести пароль администратора</button></td></tr>';
    }}

    function updateAdminAuthUI(isAuth) {{
        isAdminLoggedIn = isAuth;
        var badge = document.getElementById('adminAuthBadge');
        if (!badge) return;
        if (isAuth) {{
            badge.innerHTML = '<span id="authStatusText" style="color: #008000; font-weight: bold;">&#128274; Администратор: Авторизован</span> <button type="button" id="authBtn" class="btn-classic btn-sm" onclick="submitAdminLogout()" style="margin-left: 6px;">Выйти</button>';
        }} else {{
            badge.innerHTML = '<span id="authStatusText" style="color: #666;">&#128274; Гостевой режим (регистрация)</span> <button type="button" id="authBtn" class="btn-classic btn-sm" onclick="openLoginModal()" style="margin-left: 6px;">Вход администратора</button>';
        }}
    }}

    async function checkAdminStatus() {{
        try {{
            var res = await adminFetch('/api/admin/check');
            if (res.ok) {{
                var data = await res.json();
                updateAdminAuthUI(Boolean(data.authenticated));
                if (data.authenticated) {{
                    var hash = location.hash.replace('#', '');
                    if (hash === 'accounts') refreshAccountsList();
                    else if (hash === 'server') refreshServerStatus();
                }}
            }}
        }} catch (e) {{}}
    }}

    // Tab Switching
    function switchTab(tabId) {{
        if (tabId !== 'reg' && !isAdminLoggedIn) {{
            openLoginModal();
            return;
        }}
        var tabs = ['reg', 'accounts', 'alerts', 'server'];
        for (var i = 0; i < tabs.length; i++) {{
            var t = tabs[i];
            var btn = document.getElementById('tabBtn-' + t);
            var pane = document.getElementById('pane-' + t);
            if (btn && pane) {{
                if (t === tabId) {{
                    btn.className = 'tab-btn active';
                    pane.className = 'tab-pane active';
                }} else {{
                    btn.className = 'tab-btn';
                    pane.className = 'tab-pane';
                }}
            }}
        }}
        location.hash = '#' + tabId;
        if (tabId === 'accounts') {{
            refreshAccountsList();
        }} else if (tabId === 'server') {{
            refreshServerStatus();
        }}
    }}

    // Check hash on page load
    window.addEventListener('DOMContentLoaded', function() {{
        checkAdminStatus();
        var hash = location.hash.replace('#', '');
        if (hash === 'accounts' || hash === 'server' || hash === 'reg' || hash === 'alerts') {{
            switchTab(hash);
        }}
    }});

    // Helper: Escape HTML
    function escapeHtml(str) {{
        if (!str) return '';
        return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
    }}

    // Registration Form Handler (PUBLIC)
    document.getElementById('regForm').addEventListener('submit', async function(e) {{
        e.preventDefault();
        var msgBox = document.getElementById('regMsg');
        msgBox.style.display = 'none';
        msgBox.className = 'status-msg';

        var pwd = document.getElementById('reg_password').value;
        var confirmPwd = document.getElementById('reg_confirm').value;

        if (pwd !== confirmPwd) {{
            msgBox.textContent = 'Ошибка: Введенные пароли не совпадают!';
            msgBox.className = 'status-msg msg-error';
            msgBox.style.display = 'block';
            return;
        }}

        var payload = {{
            email: document.getElementById('reg_email').value.trim(),
            password: pwd,
            confirm_password: confirmPwd,
            friendly_name: document.getElementById('reg_friendly_name').value.trim()
        }};

        try {{
            var res = await fetch('/api/register', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify(payload)
            }});
            var data = await res.json();
            if (res.ok && data.success) {{
                msgBox.textContent = 'Пользователь ' + data.email + ' успешно зарегистрирован!';
                msgBox.className = 'status-msg msg-success';
                msgBox.style.display = 'block';
                document.getElementById('regForm').reset();
            }} else {{
                msgBox.textContent = data.error || 'Ошибка при регистрации аккаунта';
                msgBox.className = 'status-msg msg-error';
                msgBox.style.display = 'block';
            }}
        }} catch (err) {{
            msgBox.textContent = 'Сетевая ошибка: ' + err.message;
            msgBox.className = 'status-msg msg-error';
            msgBox.style.display = 'block';
        }}
    }});

    // Refresh Accounts List
    async function refreshAccountsList() {{
        try {{
            var res = await adminFetch('/api/users');
            if (!res.ok) return;
            var data = await res.json();
            var users = data.users || [];
            var onlineCount = 0;

            var tbody = document.getElementById('usersTableBody');
            var rows = [];

            for (var i = 0; i < users.length; i++) {{
                var u = users[i];
                if (u.is_online) onlineCount++;
                var isAlt = (i % 2 === 1) ? ' class="row-alt"' : '';
                var statusHtml = u.is_online
                    ? '<span style="color: #008000; font-weight: bold;">[В СЕТИ: ' + escapeHtml(u.live_status || 'NLN') + ']</span>'
                    : '<span style="color: #666666;">[ОФЛАЙН]</span>';

                var penalties = [];
                if (u.is_banned) {{
                    penalties.push('<span style="color: #cc0000; font-weight: bold; margin-left: 3px;" title="Бан: ' + escapeHtml(u.ban_reason || '') + '">[БАН: ' + escapeHtml(u.ban_remaining || '') + ']</span>');
                }}
                if (u.is_muted) {{
                    penalties.push('<span style="color: #b05a00; font-weight: bold; margin-left: 3px;" title="Мут: ' + escapeHtml(u.mute_reason || '') + '">[МУТ: ' + escapeHtml(u.mute_remaining || '') + ']</span>');
                }}
                var penaltiesHtml = penalties.join(' ');

                var emailEsc = escapeHtml(u.email);
                var nameEsc = escapeHtml(u.friendly_name || '');
                var emailJs = u.email.replace(/'/g, "\\'");
                var nameJs = (u.friendly_name || '').replace(/'/g, "\\'");
                var createdStr = escapeHtml((u.created_at || '').substring(0, 19));
                var lastSeenStr = escapeHtml((u.last_seen || '').substring(0, 19));

                var disconnectBtn = u.is_online
                    ? '<button type="button" class="btn-classic btn-sm btn-warn" onclick="disconnectUser(\\'' + emailJs + '\\')" title="Разорвать текущую сессию">Сброс</button> '
                    : '';

                var banBtnCls = u.is_banned ? 'btn-classic btn-sm btn-danger' : 'btn-classic btn-sm';
                var banBtnTxt = u.is_banned ? 'Разбан' : 'Бан';
                var muteBtnCls = u.is_muted ? 'btn-classic btn-sm btn-warn' : 'btn-classic btn-sm';
                var muteBtnTxt = u.is_muted ? 'Размут' : 'Мут';

                rows.push(
                    '<tr' + isAlt + ' id="row-' + emailEsc + '" data-email="' + emailEsc.toLowerCase() + '" data-name="' + nameEsc.toLowerCase() + '">' +
                    '<td><strong>' + emailEsc + '</strong></td>' +
                    '<td id="name-cell-' + emailEsc + '">' + nameEsc + '</td>' +
                    '<td>' + statusHtml + ' ' + penaltiesHtml + '</td>' +
                    '<td align="center"><strong>' + (u.contact_count || 0) + '</strong></td>' +
                    '<td style="color: #555555;">' + createdStr + '</td>' +
                    '<td style="color: #555555;">' + lastSeenStr + '</td>' +
                    '<td align="center">' +
                        '<button type="button" class="' + banBtnCls + '" onclick="openBanModal(\\'' + emailJs + '\\', ' + (u.is_banned ? 1 : 0) + ')" title="Управление баном">' + banBtnTxt + '</button> ' +
                        '<button type="button" class="' + muteBtnCls + '" onclick="openMuteModal(\\'' + emailJs + '\\', ' + (u.is_muted ? 1 : 0) + ')" title="Управление мутом">' + muteBtnTxt + '</button> ' +
                        '<button type="button" class="btn-classic btn-sm" onclick="openDirectMsgModal(\\'' + emailJs + '\\')" title="Отправить ЛС">ЛС</button> ' +
                        '<button type="button" class="btn-classic btn-sm" onclick="openPasswordModal(\\'' + emailJs + '\\')" title="Сменить пароль">Пароль</button> ' +
                        '<button type="button" class="btn-classic btn-sm" onclick="openNameModal(\\'' + emailJs + '\\', \\'' + nameJs + '\\')" title="Изменить имя">Имя</button> ' +
                        disconnectBtn +
                        '<button type="button" class="btn-classic btn-sm btn-danger" onclick="deleteUser(\\'' + emailJs + '\\')" title="Удалить аккаунт">Удалить</button>' +
                    '</td>' +
                    '</tr>'
                );
            }}

            if (rows.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="7" align="center" style="color: #666; padding: 12px;">В базе данных пока нет пользователей</td></tr>';
            }} else {{
                tbody.innerHTML = rows.join('');
            }}

            document.getElementById('usersCounter').textContent = 'Всего аккаунтов: ' + users.length + ' | В сети: ' + onlineCount;
            filterUsersTable();
        }} catch (e) {{
            console.error('Error loading accounts:', e);
        }}
    }}

    // Filter Users Table
    function filterUsersTable() {{
        var q = (document.getElementById('userSearchInput').value || '').trim().toLowerCase();
        var rows = document.querySelectorAll('#usersTableBody tr[data-email]');
        for (var i = 0; i < rows.length; i++) {{
            var r = rows[i];
            var email = r.getAttribute('data-email') || '';
            var name = r.getAttribute('data-name') || '';
            if (!q || email.indexOf(q) !== -1 || name.indexOf(q) !== -1) {{
                r.style.display = '';
            }} else {{
                r.style.display = 'none';
            }}
        }}
    }}

    // Apply Quick Alert Template
    function applyTemplate(text) {{
        document.getElementById('notifyMessageText').value = text;
        document.getElementById('notifyMessageText').focus();
    }}

    function onNotifyTargetChange() {{
        var val = document.getElementById('notifyTarget').value;
        document.getElementById('notifyCustomRow').style.display = (val === 'custom') ? '' : 'none';
    }}

    function clearNotifyForm() {{
        document.getElementById('notifyMessageText').value = '';
        document.getElementById('notifyCustomEmail').value = '';
        var msg = document.getElementById('notifyStatusMsg');
        if (msg) msg.style.display = 'none';
    }}

    // Submit Notification / Broadcast
    document.getElementById('notifyForm').addEventListener('submit', async function(e) {{
        e.preventDefault();
        var msgBox = document.getElementById('notifyStatusMsg');
        msgBox.style.display = 'none';
        msgBox.className = 'status-msg';

        var targetVal = document.getElementById('notifyTarget').value;
        var target = targetVal;
        if (targetVal === 'custom') {{
            target = document.getElementById('notifyCustomEmail').value.trim();
            if (!target) {{
                msgBox.textContent = 'Укажите email пользователя!';
                msgBox.className = 'status-msg msg-error';
                msgBox.style.display = 'block';
                return;
            }}
        }}

        var message = document.getElementById('notifyMessageText').value.trim();
        if (!message) return;

        try {{
            var res = await adminFetch('/api/notify', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ target: target, message: message }})
            }});
            var data = await res.json();
            if (res.ok && data.success) {{
                var info = 'Оповещение успешно отправлено! Доставлено онлайн: ' + (data.delivered_online || 0);
                if (data.saved_offline) {{
                    info += ', сохранено в офлайн-очередь: ' + data.saved_offline;
                }}
                msgBox.textContent = info;
                msgBox.className = 'status-msg msg-success';
                msgBox.style.display = 'block';
            }} else {{
                msgBox.textContent = data.error || 'Ошибка отправки оповещения';
                msgBox.className = 'status-msg msg-error';
                msgBox.style.display = 'block';
            }}
        }} catch (err) {{
            msgBox.textContent = 'Ошибка связи: ' + err.message;
            msgBox.className = 'status-msg msg-error';
            msgBox.style.display = 'block';
        }}
    }});

    // Ban Modal
    function openBanModal(email, isBanned) {{
        currentTargetEmail = email;
        document.getElementById('modalBanEmail').textContent = email;
        var msgBox = document.getElementById('modalBanMsg');
        msgBox.style.display = 'none';
        msgBox.className = 'status-msg';

        document.getElementById('btnLiftBan').style.display = isBanned ? 'inline-block' : 'none';
        document.getElementById('banModal').style.display = 'flex';
    }}

    async function submitBan(apply) {{
        var msgBox = document.getElementById('modalBanMsg');
        msgBox.style.display = 'none';

        if (!apply) {{
            // Lift ban
            try {{
                var res = await adminFetch('/api/users/unban', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ email: currentTargetEmail }})
                }});
                var data = await res.json();
                if (res.ok && data.success) {{
                    msgBox.textContent = 'Бан успешно снят!';
                    msgBox.className = 'status-msg msg-success';
                    msgBox.style.display = 'block';
                    setTimeout(function() {{ closeModal('banModal'); refreshAccountsList(); }}, 700);
                }} else {{
                    msgBox.textContent = data.error || 'Не удалось снять бан';
                    msgBox.className = 'status-msg msg-error';
                    msgBox.style.display = 'block';
                }}
            }} catch (e) {{
                msgBox.textContent = 'Ошибка: ' + e.message;
                msgBox.className = 'status-msg msg-error';
                msgBox.style.display = 'block';
            }}
            return;
        }}

        // Apply ban
        var dur = parseInt(document.getElementById('modalBanDuration').value);
        var reason = document.getElementById('modalBanReason').value.trim();

        try {{
            var res = await adminFetch('/api/users/ban', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{
                    email: currentTargetEmail,
                    duration_minutes: dur,
                    reason: reason
                }})
            }});
            var data = await res.json();
            if (res.ok && data.success) {{
                msgBox.textContent = 'Пользователь успешно забанен!';
                msgBox.className = 'status-msg msg-success';
                msgBox.style.display = 'block';
                setTimeout(function() {{ closeModal('banModal'); refreshAccountsList(); }}, 700);
            }} else {{
                msgBox.textContent = data.error || 'Ошибка при установке бана';
                msgBox.className = 'status-msg msg-error';
                msgBox.style.display = 'block';
            }}
        }} catch (e) {{
            msgBox.textContent = 'Ошибка: ' + e.message;
            msgBox.className = 'status-msg msg-error';
            msgBox.style.display = 'block';
        }}
    }}

    // Mute Modal
    function openMuteModal(email, isMuted) {{
        currentTargetEmail = email;
        document.getElementById('modalMuteEmail').textContent = email;
        var msgBox = document.getElementById('modalMuteMsg');
        msgBox.style.display = 'none';
        msgBox.className = 'status-msg';

        document.getElementById('btnLiftMute').style.display = isMuted ? 'inline-block' : 'none';
        document.getElementById('muteModal').style.display = 'flex';
    }}

    async function submitMute(apply) {{
        var msgBox = document.getElementById('modalMuteMsg');
        msgBox.style.display = 'none';

        if (!apply) {{
            // Lift mute
            try {{
                var res = await adminFetch('/api/users/unmute', {{
                    method: 'POST',
                    headers: {{ 'Content-Type': 'application/json' }},
                    body: JSON.stringify({{ email: currentTargetEmail }})
                }});
                var data = await res.json();
                if (res.ok && data.success) {{
                    msgBox.textContent = 'Мут успешно снят!';
                    msgBox.className = 'status-msg msg-success';
                    msgBox.style.display = 'block';
                    setTimeout(function() {{ closeModal('muteModal'); refreshAccountsList(); }}, 700);
                }} else {{
                    msgBox.textContent = data.error || 'Не удалось снять мут';
                    msgBox.className = 'status-msg msg-error';
                    msgBox.style.display = 'block';
                }}
            }} catch (e) {{
                msgBox.textContent = 'Ошибка: ' + e.message;
                msgBox.className = 'status-msg msg-error';
                msgBox.style.display = 'block';
            }}
            return;
        }}

        // Apply mute
        var dur = parseInt(document.getElementById('modalMuteDuration').value);
        var reason = document.getElementById('modalMuteReason').value.trim();

        try {{
            var res = await adminFetch('/api/users/mute', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{
                    email: currentTargetEmail,
                    duration_minutes: dur,
                    reason: reason
                }})
            }});
            var data = await res.json();
            if (res.ok && data.success) {{
                msgBox.textContent = 'Пользователь успешно замьючен!';
                msgBox.className = 'status-msg msg-success';
                msgBox.style.display = 'block';
                setTimeout(function() {{ closeModal('muteModal'); refreshAccountsList(); }}, 700);
            }} else {{
                msgBox.textContent = data.error || 'Ошибка при установке мута';
                msgBox.className = 'status-msg msg-error';
                msgBox.style.display = 'block';
            }}
        }} catch (e) {{
            msgBox.textContent = 'Ошибка: ' + e.message;
            msgBox.className = 'status-msg msg-error';
            msgBox.style.display = 'block';
        }}
    }}

    // Direct Message Modal
    function openDirectMsgModal(email) {{
        currentTargetEmail = email;
        document.getElementById('modalDirectEmail').textContent = email;
        document.getElementById('modalDirectText').value = '';
        var msgBox = document.getElementById('modalDirectStatus');
        msgBox.style.display = 'none';
        msgBox.className = 'status-msg';
        document.getElementById('directMsgModal').style.display = 'flex';
        document.getElementById('modalDirectText').focus();
    }}

    async function submitDirectMsg() {{
        var text = document.getElementById('modalDirectText').value.trim();
        var msgBox = document.getElementById('modalDirectStatus');
        if (!text) return;

        try {{
            var res = await adminFetch('/api/notify', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ target: currentTargetEmail, message: text }})
            }});
            var data = await res.json();
            if (res.ok && data.success) {{
                msgBox.textContent = 'Сообщение успешно отправлено адресату!';
                msgBox.className = 'status-msg msg-success';
                msgBox.style.display = 'block';
                setTimeout(function() {{ closeModal('directMsgModal'); }}, 800);
            }} else {{
                msgBox.textContent = data.error || 'Ошибка отправки сообщения';
                msgBox.className = 'status-msg msg-error';
                msgBox.style.display = 'block';
            }}
        }} catch (e) {{
            msgBox.textContent = 'Ошибка связи: ' + e.message;
            msgBox.className = 'status-msg msg-error';
            msgBox.style.display = 'block';
        }}
    }}

    // Password & Name Modals
    function openPasswordModal(email) {{
        currentTargetEmail = email;
        document.getElementById('modalPwdEmail').textContent = email;
        document.getElementById('modalNewPassword').value = '';
        var msgBox = document.getElementById('modalPwdMsg');
        msgBox.style.display = 'none';
        msgBox.className = 'status-msg';
        document.getElementById('passwordModal').style.display = 'flex';
        document.getElementById('modalNewPassword').focus();
    }}

    function openNameModal(email, currentName) {{
        currentTargetEmail = email;
        document.getElementById('modalNameEmail').textContent = email;
        document.getElementById('modalNewName').value = currentName || '';
        var msgBox = document.getElementById('modalNameMsg');
        msgBox.style.display = 'none';
        msgBox.className = 'status-msg';
        document.getElementById('nameModal').style.display = 'flex';
        document.getElementById('modalNewName').focus();
    }}

    function closeModal(modalId) {{
        document.getElementById(modalId).style.display = 'none';
        currentTargetEmail = '';
    }}

    async function submitPasswordChange() {{
        var newPwd = document.getElementById('modalNewPassword').value;
        var msgBox = document.getElementById('modalPwdMsg');
        if (!newPwd) {{
            msgBox.textContent = 'Пароль не может быть пустым!';
            msgBox.className = 'status-msg msg-error';
            msgBox.style.display = 'block';
            return;
        }}

        try {{
            var res = await adminFetch('/api/users/update_password', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ email: currentTargetEmail, password: newPwd }})
            }});
            var data = await res.json();
            if (res.ok && data.success) {{
                msgBox.textContent = 'Пароль успешно изменен!';
                msgBox.className = 'status-msg msg-success';
                msgBox.style.display = 'block';
                setTimeout(function() {{ closeModal('passwordModal'); }}, 800);
            }} else {{
                msgBox.textContent = data.error || 'Ошибка смены пароля';
                msgBox.className = 'status-msg msg-error';
                msgBox.style.display = 'block';
            }}
        }} catch (err) {{
            msgBox.textContent = 'Ошибка связи: ' + err.message;
            msgBox.className = 'status-msg msg-error';
            msgBox.style.display = 'block';
        }}
    }}

    async function submitNameChange() {{
        var newName = document.getElementById('modalNewName').value.trim();
        var msgBox = document.getElementById('modalNameMsg');

        try {{
            var res = await adminFetch('/api/users/update_name', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ email: currentTargetEmail, friendly_name: newName }})
            }});
            var data = await res.json();
            if (res.ok && data.success) {{
                msgBox.textContent = 'Отображаемое имя успешно обновлено!';
                msgBox.className = 'status-msg msg-success';
                msgBox.style.display = 'block';
                setTimeout(function() {{
                    closeModal('nameModal');
                    refreshAccountsList();
                }}, 700);
            }} else {{
                msgBox.textContent = data.error || 'Ошибка обновления имени';
                msgBox.className = 'status-msg msg-error';
                msgBox.style.display = 'block';
            }}
        }} catch (err) {{
            msgBox.textContent = 'Ошибка связи: ' + err.message;
            msgBox.className = 'status-msg msg-error';
            msgBox.style.display = 'block';
        }}
    }}

    async function disconnectUser(email) {{
        if (!confirm('Принудительно отключить активную сессию пользователя ' + email + '?')) return;
        try {{
            var res = await adminFetch('/api/users/disconnect', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ email: email }})
            }});
            var data = await res.json();
            if (res.ok && data.success) {{
                refreshAccountsList();
                refreshServerStatus();
            }} else {{
                alert(data.error || 'Не удалось отключить пользователя');
            }}
        }} catch (err) {{
            alert('Ошибка сети: ' + err.message);
        }}
    }}

    async function deleteUser(email) {{
        if (!confirm('ВНИМАНИЕ: Вы действительно хотите удалить учетную запись ' + email + '?\\n\\nВсе контакты, группы и сообщения этого пользователя будут безвозвратно стерты.')) return;
        try {{
            var res = await adminFetch('/api/users/delete', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ email: email }})
            }});
            var data = await res.json();
            if (res.ok && data.success) {{
                refreshAccountsList();
                refreshServerStatus();
            }} else {{
                alert(data.error || 'Не удалось удалить учетную запись');
            }}
        }} catch (err) {{
            alert('Ошибка сети: ' + err.message);
        }}
    }}

    async function refreshServerStatus() {{
        try {{
            var res = await adminFetch('/api/status');
            if (!res.ok) return;
            var data = await res.json();

            var sec = data.uptime_seconds || 0;
            var h = Math.floor(sec / 3600);
            var m = Math.floor((sec % 3600) / 60);
            var s = sec % 60;
            document.getElementById('serverUptimeText').innerHTML = '<strong>' + h + ' ч. ' + m + ' мин. ' + s + ' сек.</strong>';

            var stats = data.stats || {{}};
            document.getElementById('serverActiveCountText').textContent = data.active_users_count || 0;
            document.getElementById('serverTotalUsersText').textContent = stats.total_users || 0;
            document.getElementById('serverTotalContactsText').innerHTML = '<strong>' + (stats.total_contacts || 0) + '</strong>';
            document.getElementById('serverTotalGroupsText').textContent = stats.total_groups || 0;
            document.getElementById('serverPendingMsgsText').innerHTML = '<strong>' + (stats.pending_offline_messages || 0) + '</strong>';

            var now = new Date();
            var timeStr = now.toTimeString().split(' ')[0];
            document.getElementById('lastUpdatedStatus').textContent = 'Обновлено в ' + timeStr;

            var connections = data.active_users || [];
            var tbody = document.getElementById('connectionsTableBody');
            var rows = [];

            for (var i = 0; i < connections.length; i++) {{
                var c = connections[i];
                var isAlt = (i % 2 === 1) ? ' class="row-alt"' : '';
                var emailEsc = escapeHtml(c.email || '');
                var nameEsc = escapeHtml(c.friendly_name || '');
                var peerEsc = escapeHtml(c.peer ? String(c.peer) : '');
                var statusEsc = escapeHtml(c.status || 'NLN');
                var clientIdEsc = escapeHtml(String(c.client_id || '0'));
                var emailJs = (c.email || '').replace(/'/g, "\\'");

                rows.push(
                    '<tr' + isAlt + '>' +
                    '<td><strong>' + emailEsc + '</strong></td>' +
                    '<td>' + nameEsc + '</td>' +
                    '<td><span class="code-font">' + peerEsc + '</span></td>' +
                    '<td><span style="color: #008000; font-weight: bold;">' + statusEsc + '</span></td>' +
                    '<td><span class="code-font">' + clientIdEsc + '</span></td>' +
                    '<td align="center">' +
                        '<button type="button" class="btn-classic btn-sm btn-warn" onclick="disconnectUser(\\'' + emailJs + '\\')">Отключить</button>' +
                    '</td>' +
                    '</tr>'
                );
            }}

            if (rows.length === 0) {{
                tbody.innerHTML = '<tr><td colspan="6" align="center" style="color: #666; padding: 12px;">Нет активных подключений в данный момент</td></tr>';
            }} else {{
                tbody.innerHTML = rows.join('');
            }}
        }} catch (e) {{
            console.error('Error refreshing server status:', e);
        }}
    }}

    function toggleAutoRefresh(enabled) {{
        if (autoRefreshTimer) {{
            clearInterval(autoRefreshTimer);
            autoRefreshTimer = null;
        }}
        if (enabled) {{
            autoRefreshTimer = setInterval(function() {{
                var activePane = document.querySelector('.tab-pane.active');
                if (activePane && activePane.id === 'pane-server') {{
                    refreshServerStatus();
                }}
            }}, 5000);
        }}
    }}
</script>

</body>
</html>
"""
