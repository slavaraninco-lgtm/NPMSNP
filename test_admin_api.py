"""
Automated unit and integration tests for Admin Panel Tabs, REST API,
Service Account, Broadcast Notifications, and Ban/Mute Systems.
"""
import asyncio
import json
import os
import unittest
import urllib.request
import urllib.parse

import config
from db.database import Database
from protocol.auth import AuthManager
from protocol.ns_handler import NSClientHandler
from protocol.sb_handler import SBClientHandler
from services.session_manager import SessionManager
from services.switchboard_manager import SwitchboardManager
from services.http_server import HTTPServer


class DummyWriter:
    def __init__(self):
        self.messages = []
    def write(self, data):
        self.messages.append(data.decode("utf-8", errors="replace"))
    def get_extra_info(self, name):
        return ("127.0.0.1", 12345)
    def close(self):
        pass
    async def wait_closed(self):
        pass


class DummyReader:
    pass


class TestAdminAPI(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.test_db = "test_admin_database.db"
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except Exception:
                pass

        self.db = Database(self.test_db)
        self.auth_manager = AuthManager()
        self.session_manager = SessionManager(self.db)
        self.switchboard_manager = SwitchboardManager(self.auth_manager)
        self.db.ensure_service_account(config.SERVICE_ACCOUNT_EMAIL, config.SERVICE_ACCOUNT_NAME)

        # Populate test data
        self.db.create_user("alice@msn.local", "pass123", "Alice")
        self.db.create_user("bob@msn.local", "secret456", "Bob")
        self.db.add_or_update_contact("alice@msn.local", "bob@msn.local", add_flag=1)

        self.port = 19865
        self.http_server = HTTPServer(
            host="127.0.0.1",
            port=self.port,
            external_host="127.0.0.1",
            db=self.db,
            auth_manager=self.auth_manager,
            session_manager=self.session_manager,
            switchboard_manager=self.switchboard_manager,
            auto_register=True,
        )
        await self.http_server.start()

    async def asyncTearDown(self):
        await self.http_server.stop()
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except Exception:
                pass

    def _request(self, method: str, path: str, data: dict = None, headers: dict = None, use_auth: bool = True):
        url = f"http://127.0.0.1:{self.port}{path}"
        req_headers = {}
        if use_auth:
            req_headers["X-Admin-Password"] = "admin123"
        if headers:
            req_headers.update(headers)
        body = None
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=body, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                resp_body = resp.read().decode("utf-8")
                content_type = resp.headers.get("Content-Type", "")
                if "application/json" in content_type:
                    return resp.status, json.loads(resp_body)
                return resp.status, resp_body
        except urllib.error.HTTPError as ex:
            err_body = ex.read().decode("utf-8")
            try:
                return ex.code, json.loads(err_body)
            except Exception:
                return ex.code, err_body

    async def test_dashboard_html_contains_tabs(self):
        status, html_content = await asyncio.to_thread(self._request, "GET", "/")
        self.assertEqual(status, 200)
        self.assertIn("MSNP Server Administration Console", html_content)
        # Check all 4 tabs exist
        self.assertIn("tabBtn-reg", html_content)
        self.assertIn("tabBtn-accounts", html_content)
        self.assertIn("tabBtn-alerts", html_content)
        self.assertIn("tabBtn-server", html_content)
        self.assertIn("pane-reg", html_content)
        self.assertIn("pane-accounts", html_content)
        self.assertIn("pane-alerts", html_content)
        self.assertIn("pane-server", html_content)
        self.assertIn("Регистрация", html_content)
        self.assertIn("Управление учетными записями", html_content)
        self.assertIn("Оповещения", html_content)
        self.assertIn("Состояние сервера", html_content)
        # Check modals and templates
        self.assertIn("banModal", html_content)
        self.assertIn("muteModal", html_content)
        self.assertIn("directMsgModal", html_content)
        self.assertIn("template-btn", html_content)

    async def test_registration_flow(self):
        # Mismatched password
        status, res = await asyncio.to_thread(self._request, "POST", "/api/register", {
            "email": "test@msn.local",
            "password": "pwd1",
            "confirm_password": "pwd2"
        })
        self.assertEqual(status, 400)
        self.assertIn("не совпадают", res.get("error", ""))

        # Successful registration
        status, res = await asyncio.to_thread(self._request, "POST", "/api/register", {
            "email": "charlie@msn.local",
            "password": "securepassword",
            "confirm_password": "securepassword",
            "friendly_name": "Charlie Chaplin"
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("email"), "charlie@msn.local")
        self.assertEqual(res.get("friendly_name"), "Charlie Chaplin")

        # Duplicate registration
        status, res = await asyncio.to_thread(self._request, "POST", "/api/register", {
            "email": "charlie@msn.local",
            "password": "securepassword"
        })
        self.assertEqual(status, 409)

    async def test_get_users_list(self):
        status, res = await asyncio.to_thread(self._request, "GET", "/api/users")
        self.assertEqual(status, 200)
        users = res.get("users", [])
        # Alice, Bob, and Service Account
        self.assertGreaterEqual(len(users), 3)
        alice = next(u for u in users if u["email"] == "alice@msn.local")
        self.assertEqual(alice["friendly_name"], "Alice")
        self.assertEqual(alice["contact_count"], 1)
        self.assertFalse(alice.get("is_banned"))
        self.assertFalse(alice.get("is_muted"))

    async def test_update_name_and_password(self):
        # Update name
        status, res = await asyncio.to_thread(self._request, "POST", "/api/users/update_name", {
            "email": "alice@msn.local",
            "friendly_name": "Alice in Wonderland"
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        user = self.db.get_user("alice@msn.local")
        self.assertEqual(user.friendly_name, "Alice in Wonderland")

        # Update password
        status, res = await asyncio.to_thread(self._request, "POST", "/api/users/update_password", {
            "email": "alice@msn.local",
            "password": "newalicepassword"
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        user = self.db.get_user("alice@msn.local")
        self.assertEqual(user.password, "newalicepassword")

    async def test_server_status_api(self):
        status, res = await asyncio.to_thread(self._request, "GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertEqual(res.get("status"), "online")
        self.assertGreaterEqual(res.get("total_users"), 3)
        stats = res.get("stats", {})
        self.assertGreaterEqual(stats.get("total_users"), 3)
        self.assertGreaterEqual(stats.get("total_contacts"), 2)

    async def test_disconnect_and_delete_user(self):
        # Disconnect offline user -> success: True, disconnected: False
        status, res = await asyncio.to_thread(self._request, "POST", "/api/users/disconnect", {
            "email": "bob@msn.local"
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        self.assertFalse(res.get("disconnected"))

        # Delete user
        status, res = await asyncio.to_thread(self._request, "POST", "/api/users/delete", {
            "email": "bob@msn.local"
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        self.assertIsNone(self.db.get_user("bob@msn.local"))

    async def test_ban_and_unban_flow(self):
        # Ban user for 30 minutes
        status, res = await asyncio.to_thread(self._request, "POST", "/api/users/ban", {
            "email": "alice@msn.local",
            "duration_minutes": 30,
            "reason": "Флуд и спам в общем чате"
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        penalty = res.get("penalty", {})
        self.assertTrue(penalty.get("is_banned"))
        self.assertIn("мин.", penalty.get("ban_remaining"))
        self.assertEqual(penalty.get("ban_reason"), "Флуд и спам в общем чате")

        # Check in get_all_users
        status, res = await asyncio.to_thread(self._request, "GET", "/api/users")
        users = res.get("users", [])
        alice = next(u for u in users if u["email"] == "alice@msn.local")
        self.assertTrue(alice.get("is_banned"))
        self.assertIn("мин.", alice.get("ban_remaining"))

        # Unban user
        status, res = await asyncio.to_thread(self._request, "POST", "/api/users/unban", {
            "email": "alice@msn.local"
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))

        # Verify unbanned
        penalty = self.db.get_user_penalty_status("alice@msn.local")
        self.assertFalse(penalty.get("is_banned"))

    async def test_mute_and_unmute_flow(self):
        # Mute user for 120 minutes (2 hours)
        status, res = await asyncio.to_thread(self._request, "POST", "/api/users/mute", {
            "email": "alice@msn.local",
            "duration_minutes": 120,
            "reason": "Оскорбление пользователей"
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        penalty = res.get("penalty", {})
        self.assertTrue(penalty.get("is_muted"))
        self.assertIn("ч.", penalty.get("mute_remaining"))
        self.assertEqual(penalty.get("mute_reason"), "Оскорбление пользователей")

        # Verify muted in DB
        status = self.db.get_user_penalty_status("alice@msn.local")
        self.assertTrue(status.get("is_muted"))
        self.assertFalse(status.get("is_banned"))

        # Unmute user
        status, res = await asyncio.to_thread(self._request, "POST", "/api/users/unmute", {
            "email": "alice@msn.local"
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))

        # Verify unmuted
        status = self.db.get_user_penalty_status("alice@msn.local")
        self.assertFalse(status.get("is_muted"))

    async def test_notifications_flow(self):
        # 1. Broadcast to online users (none online in this mock)
        status, res = await asyncio.to_thread(self._request, "POST", "/api/notify", {
            "target": "online",
            "message": "Плановая перезагрузка сервера через 10 минут."
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("delivered_online"), 0)

        # 2. Broadcast to all users (saves offline messages for offline users)
        status, res = await asyncio.to_thread(self._request, "POST", "/api/notify", {
            "target": "all",
            "message": "Технические работы успешно завершены."
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        self.assertGreaterEqual(res.get("saved_offline"), 2)

        # Check offline message saved for Alice
        msgs = self.db.get_pending_offline_messages("alice@msn.local")
        self.assertTrue(any("Технические работы" in m.message for m in msgs))

        # 3. Direct notification to specific user
        status, res = await asyncio.to_thread(self._request, "POST", "/api/notify", {
            "target": "bob@msn.local",
            "message": "Ваш запрос в техподдержку обработан."
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("target"), "bob@msn.local")

        bob_msgs = self.db.get_pending_offline_messages("bob@msn.local")
        self.assertTrue(any("техподдержку" in m.message for m in bob_msgs))

    async def test_switchboard_penalty_enforcement(self):
        from protocol.sb_handler import SBClientHandler

        class DummyWriter:
            def __init__(self):
                self.messages = []
            def write(self, data):
                self.messages.append(data.decode("utf-8", errors="replace"))
            def get_extra_info(self, name):
                return ("127.0.0.1", 12345)
            def close(self):
                pass
            async def wait_closed(self):
                pass

        class DummyReader:
            pass

        writer_alice = DummyWriter()
        writer_bob = DummyWriter()

        handler_alice = SBClientHandler(DummyReader(), writer_alice, self.db, self.auth_manager, self.session_manager, self.switchboard_manager, "127.0.0.1", 1864)
        handler_alice.email = "alice@msn.local"
        handler_alice.friendly_name = "Alice"
        session_id, _ = self.switchboard_manager.allocate_session("alice@msn.local")
        handler_alice.session_id = session_id

        handler_bob = SBClientHandler(DummyReader(), writer_bob, self.db, self.auth_manager, self.session_manager, self.switchboard_manager, "127.0.0.1", 1864)
        handler_bob.email = "bob@msn.local"
        handler_bob.friendly_name = "Bob"
        handler_bob.session_id = session_id

        room = self.switchboard_manager.join_room(session_id, "alice@msn.local", handler_alice, is_callee=False)
        self.switchboard_manager.join_room(session_id, "bob@msn.local", handler_bob, is_callee=True)
        handler_alice.room = room
        handler_bob.room = room

        # Open 1-on-1 private chat with the bot for Alice
        writer_alice_bot = DummyWriter()
        handler_alice_bot = SBClientHandler(DummyReader(), writer_alice_bot, self.db, self.auth_manager, self.session_manager, self.switchboard_manager, "127.0.0.1", 1864)
        handler_alice_bot.email = "alice@msn.local"
        handler_alice_bot.friendly_name = "Alice"
        bot_session_alice, _ = self.switchboard_manager.allocate_session(config.SERVICE_ACCOUNT_EMAIL)
        bot_room_alice = self.switchboard_manager.get_room(bot_session_alice)
        bot_room_alice.has_service_bot = True
        handler_alice_bot.session_id = bot_session_alice
        handler_alice_bot.room = self.switchboard_manager.join_room(bot_session_alice, "alice@msn.local", handler_alice_bot, is_callee=True)

        # Open 1-on-1 private chat with the bot for Bob
        writer_bob_bot = DummyWriter()
        handler_bob_bot = SBClientHandler(DummyReader(), writer_bob_bot, self.db, self.auth_manager, self.session_manager, self.switchboard_manager, "127.0.0.1", 1864)
        handler_bob_bot.email = "bob@msn.local"
        handler_bob_bot.friendly_name = "Bob"
        bot_session_bob, _ = self.switchboard_manager.allocate_session(config.SERVICE_ACCOUNT_EMAIL)
        bot_room_bob = self.switchboard_manager.get_room(bot_session_bob)
        bot_room_bob.has_service_bot = True
        handler_bob_bot.session_id = bot_session_bob
        handler_bob_bot.room = self.switchboard_manager.join_room(bot_session_bob, "bob@msn.local", handler_bob_bot, is_callee=True)

        # 1. Normal message from Alice to Bob
        writer_alice.messages.clear()
        writer_bob.messages.clear()
        payload = b"MIME-Version: 1.0\r\n\r\nHello Bob!"
        await handler_alice._cmd_msg(["1", "N"], payload)
        self.assertTrue(any("Hello Bob!" in m for m in writer_bob.messages))

        # 2. Mute Alice: Alice sends message -> dropped, bot replies to Alice in private ("в личку")
        self.db.mute_user("alice@msn.local", 60, "Спам")
        writer_alice.messages.clear()
        writer_bob.messages.clear()
        writer_alice_bot.messages.clear()
        await handler_alice._cmd_msg(["2", "N"], b"MIME-Version: 1.0\r\n\r\nSpam message")
        # Bob must NOT receive it
        self.assertFalse(any("Spam message" in m for m in writer_bob.messages))
        # Alice's chat with Bob must NOT receive bot message (no conference created!)
        self.assertFalse(any("Вам временно ограничен доступ" in m for m in writer_alice.messages))
        # Alice must receive bot warning in her 1-on-1 PM with the bot
        self.assertTrue(any("Вам временно ограничен доступ" in m for m in writer_alice_bot.messages))

        # 3. Bob sends message to muted Alice -> Alice CAN receive it!
        writer_alice.messages.clear()
        writer_bob.messages.clear()
        await handler_bob._cmd_msg(["3", "N"], b"MIME-Version: 1.0\r\n\r\nAre you there, Alice?")
        self.assertTrue(any("Are you there, Alice?" in m for m in writer_alice.messages))

        # 4. Ban Alice: Alice sends message -> dropped, bot replies to Alice in private
        self.db.unmute_user("alice@msn.local")
        self.db.ban_user("alice@msn.local", 30, "Оскорбления")
        writer_alice.messages.clear()
        writer_bob.messages.clear()
        writer_alice_bot.messages.clear()
        await handler_alice._cmd_msg(["4", "N"], b"MIME-Version: 1.0\r\n\r\nAngry message")
        # Bob must NOT receive it
        self.assertFalse(any("Angry message" in m for m in writer_bob.messages))
        # Alice's chat with Bob must NOT receive bot message
        self.assertFalse(any("Ваша учетная запись заблокирована (бан)" in m for m in writer_alice.messages))
        # Alice must receive ban notice in her 1-on-1 PM with the bot
        self.assertTrue(any("Ваша учетная запись заблокирована (бан)" in m for m in writer_alice_bot.messages))

        # 5. Bob sends message while Alice is banned -> Alice CANNOT receive it, Bob is informed in private!
        writer_alice.messages.clear()
        writer_bob.messages.clear()
        writer_bob_bot.messages.clear()
        await handler_bob._cmd_msg(["5", "N"], b"MIME-Version: 1.0\r\n\r\nMessage to banned user")
        # Alice does NOT receive it
        self.assertFalse(any("Message to banned user" in m for m in writer_alice.messages))
        # Bob's chat with Alice does NOT receive bot message
        self.assertFalse(any("заблокирован администрацией" in m for m in writer_bob.messages))
        # Bob gets notice in his 1-on-1 PM with the bot
        self.assertTrue(any("заблокирован администрацией" in m for m in writer_bob_bot.messages))

    async def test_service_account_auto_contact_and_switchboard_call(self):
        # 1. Verify service account presence in users' contact lists
        alice_contacts = self.db.get_contacts("alice@msn.local")
        service_c = next((c for c in alice_contacts if c.contact_email == config.SERVICE_ACCOUNT_EMAIL), None)
        self.assertIsNotNone(service_c)
        self.assertEqual(service_c.list_flags, 11)
        self.assertEqual(service_c.friendly_name, config.SERVICE_ACCOUNT_NAME)

        # 2. Service account is always online
        self.assertTrue(self.session_manager.is_online(config.SERVICE_ACCOUNT_EMAIL))

        # 3. New user registration auto-adds service account
        self.db.create_user("david@msn.local", "pass", "David")
        david_contacts = self.db.get_contacts("david@msn.local")
        d_service_c = next((c for c in david_contacts if c.contact_email == config.SERVICE_ACCOUNT_EMAIL), None)
        self.assertIsNotNone(d_service_c)
        self.assertEqual(d_service_c.list_flags, 11)

        # 4. Switchboard CAL to service account must succeed with RINGING + JOI (no error 217)
        session_id, caller_cookie = self.switchboard_manager.allocate_session("alice@msn.local")
        writer = DummyWriter()
        handler = SBClientHandler(
            reader=DummyReader(),
            writer=writer,
            db=self.db,
            auth_manager=self.auth_manager,
            session_manager=self.session_manager,
            switchboard_manager=self.switchboard_manager,
            external_host="127.0.0.1",
            sb_port=1864
        )
        handler.email = "alice@msn.local"
        handler.friendly_name = "Alice"
        handler.session_id = session_id
        room = self.switchboard_manager.join_room(session_id, "alice@msn.local", handler, is_callee=False)
        handler.room = room

        writer.messages.clear()
        # Alice calls the service bot
        await handler._cmd_cal(["10", config.SERVICE_ACCOUNT_EMAIL], None)

        # Must have received CAL 10 RINGING and JOI system@msn.local
        self.assertTrue(any(f"CAL 10 RINGING {session_id}" in m for m in writer.messages))
        self.assertTrue(any("JOI" in m and config.SERVICE_ACCOUNT_EMAIL in m for m in writer.messages))
        # Must NOT have received 217 error
        self.assertFalse(any("217" in m for m in writer.messages))
        self.assertTrue(room.has_service_bot)

        # 5. Alice writes message to bot -> bot responds
        writer.messages.clear()
        await handler._cmd_msg(["11", "A"], b"MIME-Version: 1.0\r\n\r\nHello bot!")
        self.assertTrue(any("ACK 11" in m for m in writer.messages))
        self.assertTrue(any("автоматическая служба сообщений" in m for m in writer.messages))

    async def test_multiple_sequential_notifications_delivery(self):
        # Register an active NS session for Alice
        ns_writer = DummyWriter()
        ns_handler = NSClientHandler(
            reader=DummyReader(),
            writer=ns_writer,
            db=self.db,
            auth_manager=self.auth_manager,
            session_manager=self.session_manager,
            switchboard_manager=self.switchboard_manager,
            external_host="127.0.0.1",
            ns_port=1863,
            sb_port=1864,
            http_port=1865
        )
        ns_handler.email = "alice@msn.local"
        ns_handler.friendly_name = "Alice"
        ns_handler.status = "NLN"
        self.session_manager.register_session("alice@msn.local", ns_handler)

        # Send alert 1
        ns_writer.messages.clear()
        status1, res1 = await asyncio.to_thread(self._request, "POST", "/api/notify", {
            "target": "alice@msn.local",
            "message": "Notice 1: Server update in 15m"
        })
        self.assertEqual(status1, 200)
        self.assertEqual(res1.get("delivered_online"), 1)
        # Server rings user on NS to open dedicated 1-on-1 private chat
        self.assertTrue(any("RNG " in m for m in ns_writer.messages))

        # Send alert 2
        ns_writer.messages.clear()
        status2, res2 = await asyncio.to_thread(self._request, "POST", "/api/notify", {
            "target": "online",
            "message": "Notice 2: Technical works started"
        })
        self.assertEqual(status2, 200)
        self.assertGreaterEqual(res2.get("delivered_online"), 1)
        self.assertTrue(any("RNG " in m for m in ns_writer.messages))

        # Alice now opens a Switchboard room with the bot
        session_id, cookie = self.switchboard_manager.allocate_session("alice@msn.local")
        sb_writer = DummyWriter()
        sb_handler = SBClientHandler(
            reader=DummyReader(),
            writer=sb_writer,
            db=self.db,
            auth_manager=self.auth_manager,
            session_manager=self.session_manager,
            switchboard_manager=self.switchboard_manager,
            external_host="127.0.0.1",
            sb_port=1864
        )
        sb_handler.email = "alice@msn.local"
        sb_handler.friendly_name = "Alice"
        sb_handler.session_id = session_id
        room = self.switchboard_manager.join_room(session_id, "alice@msn.local", sb_handler, is_callee=False)
        sb_handler.room = room
        # Call bot in SB
        await sb_handler._cmd_cal(["1", config.SERVICE_ACCOUNT_EMAIL], None)

        # Send alert 3 (sent while SB room is active) -> must arrive directly in SB room!
        sb_writer.messages.clear()
        ns_writer.messages.clear()
        status3, res3 = await asyncio.to_thread(self._request, "POST", "/api/notify", {
            "target": "all",
            "message": "Notice 3: Technical works completed!"
        })
        self.assertEqual(status3, 200)
        self.assertGreaterEqual(res3.get("delivered_online"), 1)
        # Delivered into Switchboard room
        self.assertTrue(any("Notice 3: Technical works completed!" in m for m in sb_writer.messages))
        # Not duplicated into NS
        self.assertFalse(any("Notice 3: Technical works completed!" in m for m in ns_writer.messages))

        # Send alert 4 (another subsequent alert) -> also delivered smoothly into SB room
        sb_writer.messages.clear()
        status4, res4 = await asyncio.to_thread(self._request, "POST", "/api/notify", {
            "target": "online",
            "message": "Notice 4: All systems operational"
        })
        self.assertEqual(status4, 200)
        self.assertTrue(any("Notice 4: All systems operational" in m for m in sb_writer.messages))

    async def test_ansi_encoding_and_switchboard_delivery(self):
        """Tests that Trillian/ANSI clients receive CP1251 encoded names, and queued alerts deliver into chat window."""
        from protocol.ns_handler import NSClientHandler
        from protocol.sb_handler import SBClientHandler
        from urllib.parse import quote

        class RawWriter:
            def __init__(self):
                self.raw_data = []
            def write(self, data):
                self.raw_data.append(data)
            def get_extra_info(self, name):
                return ("127.0.0.1", 23456)
            def close(self):
                pass
            async def wait_closed(self):
                pass

        class DummyReader:
            pass

        # 1. Simulate Trillian connecting to NS
        trillian_writer = RawWriter()
        trillian_handler = NSClientHandler(
            reader=DummyReader(),
            writer=trillian_writer,
            db=self.db,
            auth_manager=self.auth_manager,
            session_manager=self.session_manager,
            switchboard_manager=self.switchboard_manager,
            external_host="127.0.0.1",
            ns_port=1863,
            sb_port=1864,
            http_port=1865
        )
        # Negotiate MSNP8, CVR identifying as TRILLIAN
        await trillian_handler._cmd_ver(["1", "MSNP8", "CVR0"], None)
        await trillian_handler._cmd_cvr(["2", "0x0409", "winnt", "5.1", "i386", "TRILLIAN", "0.74", "MSMSGS", "trillian_user@msn.local"], None)
        self.assertTrue(trillian_handler.is_ansi)

        # Login and change status to Online (NLN)
        user = self.db.create_user("trillian_user@msn.local", "123456", "TrillUser")
        await trillian_handler._login_successful("3", user)
        await trillian_handler._cmd_chg(["4", "NLN", "0"], None)

        # Send initial presence (ILN for bot)
        trillian_writer.raw_data.clear()
        self.session_manager.send_initial_presence(trillian_handler, "5")

        # Bot name should be encoded with CP1251 percent-encoding, NOT UTF-8!
        expected_cp1251_encoded = quote("Служба сообщений MSN", encoding="cp1251")
        all_raw = b"".join(trillian_writer.raw_data)
        self.assertIn(expected_cp1251_encoded.encode("ascii"), all_raw)

        # 2. Admin sends an alert to this user via /api/notify
        status, res = await asyncio.to_thread(self._request, "POST", "/api/notify", {
            "target": "trillian_user@msn.local",
            "message": "Важное системное оповещение для Trillian!"
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))

        # Verify message is queued in SwitchboardManager
        self.assertTrue(self.switchboard_manager.has_pending_service_messages("trillian_user@msn.local"))

        # 3. Trillian client connects to Switchboard and calls system bot (CAL system@msn.local)
        sb_raw_writer = RawWriter()
        sb_trillian = SBClientHandler(
            reader=DummyReader(),
            writer=sb_raw_writer,
            db=self.db,
            auth_manager=self.auth_manager,
            session_manager=self.session_manager,
            switchboard_manager=self.switchboard_manager,
            external_host="127.0.0.1",
            sb_port=1864
        )
        sb_trillian.email = "trillian_user@msn.local"
        self.assertTrue(sb_trillian.is_ansi)

        session_id, _ = self.switchboard_manager.allocate_session("trillian_user@msn.local")
        sb_trillian.session_id = session_id
        sb_trillian.room = self.switchboard_manager.join_room(session_id, "trillian_user@msn.local", sb_trillian, is_callee=False)

        # When Trillian calls bot, pending alerts MUST be sent into room immediately!
        sb_raw_writer.raw_data.clear()
        await sb_trillian._cmd_cal(["1", config.SERVICE_ACCOUNT_EMAIL], None)

        sb_data = b"".join(sb_raw_writer.raw_data)
        # JOI must have CP1251 encoded friendly name (so window title displays in Russian)
        self.assertIn(expected_cp1251_encoded.encode("ascii"), sb_data)
        # MSG must contain charset=UTF-8 and UTF-8 encoded text (so chat message text renders in Russian without tofu squares)
        self.assertIn(b"charset=UTF-8", sb_data)
        self.assertIn("Важное системное оповещение".encode("utf-8"), sb_data)
        # Queue should now be empty
        self.assertFalse(self.switchboard_manager.has_pending_service_messages("trillian_user@msn.local"))

    async def test_switchboard_delivery_on_ans(self):
        """Tests that when server rings user with bot invitation, user ANS delivers the queued alert in UTF-8."""
        from protocol.ns_handler import NSClientHandler
        from protocol.sb_handler import SBClientHandler

        class RawWriter:
            def __init__(self):
                self.raw_data = []
            def write(self, data):
                self.raw_data.append(data)
            def get_extra_info(self, name):
                return ("127.0.0.1", 34567)
            def close(self):
                pass
            async def wait_closed(self):
                pass

        class DummyReader:
            pass

        # 1. Connect Gaim user (UTF-8)
        gaim_writer = RawWriter()
        gaim_handler = NSClientHandler(
            reader=DummyReader(),
            writer=gaim_writer,
            db=self.db,
            auth_manager=self.auth_manager,
            session_manager=self.session_manager,
            switchboard_manager=self.switchboard_manager,
            external_host="127.0.0.1",
            ns_port=1863,
            sb_port=1864,
            http_port=1865
        )
        await gaim_handler._cmd_ver(["1", "MSNP9", "CVR0"], None)
        await gaim_handler._cmd_cvr(["2", "0x0409", "winnt", "5.1", "i386", "MSNMSGR", "6.0.0602", "MSMSGS", "gaim_user@msn.local"], None)
        self.assertFalse(gaim_handler.is_ansi)

        user = self.db.create_user("gaim_user@msn.local", "123456", "GaimUser")
        await gaim_handler._login_successful("3", user)
        await gaim_handler._cmd_chg(["4", "NLN", "0"], None)

        # 2. Admin sends alert via /api/notify
        gaim_writer.raw_data.clear()
        status, res = await asyncio.to_thread(self._request, "POST", "/api/notify", {
            "target": "gaim_user@msn.local",
            "message": "Внимание! Тестовое сообщение для Gaim!"
        })
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))

        # Verify RNG was sent to user on NS
        all_ns_data = b"".join(gaim_writer.raw_data)
        self.assertIn(b"RNG ", all_ns_data)

        # Extract session_id and cookie from RNG line: RNG session_id host:port CKI cookie caller_email caller_name
        rng_line = [l for l in all_ns_data.split(b"\r\n") if l.startswith(b"RNG ")][0].decode("ascii")
        parts = rng_line.split(" ")
        session_id = int(parts[1])
        cookie = parts[4]

        # 3. Gaim connects to SB and answers: ANS trid gaim_user@msn.local cookie session_id
        sb_writer = RawWriter()
        sb_gaim = SBClientHandler(
            reader=DummyReader(),
            writer=sb_writer,
            db=self.db,
            auth_manager=self.auth_manager,
            session_manager=self.session_manager,
            switchboard_manager=self.switchboard_manager,
            external_host="127.0.0.1",
            sb_port=1864
        )
        await sb_gaim._cmd_ans(["1", "gaim_user@msn.local", cookie, str(session_id)], None)

        sb_data = b"".join(sb_writer.raw_data)
        # Callee receives IRO for bot and the queued MSG with UTF-8
        self.assertIn(b"IRO ", sb_data)
        self.assertIn(b"charset=UTF-8", sb_data)
        self.assertIn("Внимание! Тестовое сообщение для Gaim!".encode("utf-8"), sb_data)
        self.assertFalse(self.switchboard_manager.has_pending_service_messages("gaim_user@msn.local"))

    async def test_service_notice_leaves_friend_chat_untouched_and_opens_pm(self):
        """
        Critical regression test:
        Verifies that when an alert is sent to a user who is chatting with a friend:
        1. The friend chat is NOT modified, NOT sent JOI, and NEVER converted to a conference.
        2. The alert is delivered strictly to a dedicated 1-on-1 PM with the service bot.
        3. Users cannot invite the service bot into a multi-user conference.
        """
        from protocol.ns_handler import NSClientHandler
        from protocol.sb_handler import SBClientHandler

        class RawWriter:
            def __init__(self):
                self.raw_data = []
            def write(self, data):
                self.raw_data.append(data)
            def get_extra_info(self, name):
                return ("127.0.0.1", 34567)
            def close(self):
                pass
            async def wait_closed(self):
                pass

        class DummyReader:
            pass

        # 1. Setup online NS session for Alice
        self.db.create_user("zalupa@msn.local", "123456", "Zalupa")
        self.db.create_user("jopa@msn.local", "123456", "Jopa")

        alice_ns_writer = RawWriter()
        alice_ns = NSClientHandler(DummyReader(), alice_ns_writer, self.db, self.auth_manager, self.session_manager, self.switchboard_manager)
        alice_ns.email = "zalupa@msn.local"
        alice_ns.friendly_name = "Zalupa"
        alice_ns.status = "NLN"
        self.session_manager.register_session("zalupa@msn.local", alice_ns)

        # 2. Setup active 1-on-1 chat between Alice (Zalupa) and Bob (Jopa)
        chat_sess_id, _ = self.switchboard_manager.allocate_session("zalupa@msn.local")
        friend_room = self.switchboard_manager.get_room(chat_sess_id)

        alice_sb_writer = RawWriter()
        alice_sb = SBClientHandler(DummyReader(), alice_sb_writer, self.db, self.auth_manager, self.session_manager, self.switchboard_manager)
        alice_sb.email = "zalupa@msn.local"
        alice_sb.friendly_name = "Zalupa"
        alice_sb.session_id = chat_sess_id
        self.switchboard_manager.join_room(chat_sess_id, "zalupa@msn.local", alice_sb, is_callee=False)

        bob_sb_writer = RawWriter()
        bob_sb = SBClientHandler(DummyReader(), bob_sb_writer, self.db, self.auth_manager, self.session_manager, self.switchboard_manager)
        bob_sb.email = "jopa@msn.local"
        bob_sb.friendly_name = "Jopa"
        bob_sb.session_id = chat_sess_id
        self.switchboard_manager.join_room(chat_sess_id, "jopa@msn.local", bob_sb, is_callee=True)

        self.assertEqual(len(friend_room.participants), 2)
        self.assertFalse(getattr(friend_room, "has_service_bot", False))

        # 3. Admin sends alert to Alice
        alice_ns_writer.raw_data.clear()
        alice_sb_writer.raw_data.clear()
        bob_sb_writer.raw_data.clear()

        status, res = await asyncio.to_thread(self._request, "POST", "/api/notify", {
            "target": "zalupa@msn.local",
            "message": "Технические работы через 10 минут!"
        })
        self.assertEqual(status, 200)
        self.assertEqual(res.get("delivered_online"), 1)

        # 4. Verify Alice's chat with Bob was NOT barged into!
        alice_chat_data = b"".join(alice_sb_writer.raw_data)
        bob_chat_data = b"".join(bob_sb_writer.raw_data)
        self.assertNotIn(b"JOI ", alice_chat_data)
        self.assertNotIn(b"JOI ", bob_chat_data)
        self.assertNotIn(b"system@msn.local", alice_chat_data)
        self.assertNotIn(b"system@msn.local", bob_chat_data)
        self.assertFalse(getattr(friend_room, "has_service_bot", False))
        self.assertEqual(len(friend_room.participants), 2)

        # 5. Verify Alice received RNG on NS to open a separate 1-on-1 PM
        all_ns = b"".join(alice_ns_writer.raw_data)
        self.assertIn(b"RNG ", all_ns)
        rng_line = [l for l in all_ns.split(b"\r\n") if l.startswith(b"RNG ")][0].decode("ascii")
        parts = rng_line.split(" ")
        bot_sess_id = int(parts[1])
        cookie = parts[4]
        self.assertNotEqual(bot_sess_id, chat_sess_id)

        # 6. Alice connects to SB for the bot PM
        bot_pm_writer = RawWriter()
        bot_pm_sb = SBClientHandler(DummyReader(), bot_pm_writer, self.db, self.auth_manager, self.session_manager, self.switchboard_manager)
        await bot_pm_sb._cmd_ans(["1", "zalupa@msn.local", cookie, str(bot_sess_id)], None)

        bot_pm_data = b"".join(bot_pm_writer.raw_data)
        self.assertIn(b"ANS 1 OK", bot_pm_data)
        self.assertIn(b"IRO 1 1 1 system@msn.local", bot_pm_data)
        self.assertIn("Технические работы через 10 минут!".encode("utf-8"), bot_pm_data)
        self.assertEqual(len(bot_pm_sb.room.participants), 1)

        # 7. While bot PM is open, admin sends another alert -> delivered directly into PM without JOI
        bot_pm_writer.raw_data.clear()
        status2, res2 = await asyncio.to_thread(self._request, "POST", "/api/notify", {
            "target": "zalupa@msn.local",
            "message": "Второе оповещение в личку"
        })
        self.assertEqual(status2, 200)
        bot_pm_data2 = b"".join(bot_pm_writer.raw_data)
        self.assertNotIn(b"JOI ", bot_pm_data2)
        self.assertIn("Второе оповещение в личку".encode("utf-8"), bot_pm_data2)

        # 8. User attempts to invite bot into group chat with Bob -> rejected
        alice_sb_writer.raw_data.clear()
        await alice_sb._cmd_cal(["10", config.SERVICE_ACCOUNT_EMAIL], None)
        alice_chat_data3 = b"".join(alice_sb_writer.raw_data)
        # Must return error, NOT RINGING
        self.assertNotIn(b"RINGING", alice_chat_data3)
        self.assertNotIn(b"JOI ", alice_chat_data3)

    async def test_unauthenticated_api_endpoints_are_blocked(self):
        """Verify that all admin API endpoints return 401 Unauthorized without auth."""
        # /api/users
        status, res = await asyncio.to_thread(self._request, "GET", "/api/users", use_auth=False)
        self.assertEqual(status, 401)
        self.assertTrue(res.get("auth_required"))

        # /api/status
        status, res = await asyncio.to_thread(self._request, "GET", "/api/status", use_auth=False)
        self.assertEqual(status, 401)

        # /api/notify
        status, res = await asyncio.to_thread(self._request, "POST", "/api/notify", {"target": "all", "message": "Test"}, use_auth=False)
        self.assertEqual(status, 401)

        # /api/users/ban
        status, res = await asyncio.to_thread(self._request, "POST", "/api/users/ban", {"email": "alice@msn.local"}, use_auth=False)
        self.assertEqual(status, 401)

        # /api/users/update_name
        status, res = await asyncio.to_thread(self._request, "POST", "/api/users/update_name", {"email": "alice@msn.local", "friendly_name": "New"}, use_auth=False)
        self.assertEqual(status, 401)

    async def test_registration_is_public_without_auth(self):
        """Verify that registration endpoint (/api/register) remains completely public."""
        status, res = await asyncio.to_thread(self._request, "POST", "/api/register", {
            "email": "public_user@msn.local",
            "password": "mypassword123",
            "confirm_password": "mypassword123",
            "friendly_name": "Public User"
        }, use_auth=False)
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("email"), "public_user@msn.local")

    async def test_admin_login_and_token_flow(self):
        """Verify admin login, token check, token-authenticated requests, and logout."""
        # 1. Login with invalid password -> 401
        status, res = await asyncio.to_thread(self._request, "POST", "/api/admin/login", {
            "password": "incorrect_password"
        }, use_auth=False)
        self.assertEqual(status, 401)
        self.assertIn("Неверный пароль", res.get("error", ""))

        # 2. Login with valid password -> 200 + token
        status, res = await asyncio.to_thread(self._request, "POST", "/api/admin/login", {
            "password": "admin123"
        }, use_auth=False)
        self.assertEqual(status, 200)
        self.assertTrue(res.get("success"))
        token = res.get("token")
        self.assertTrue(bool(token))

        # 3. Check auth with token in header
        status, res = await asyncio.to_thread(self._request, "GET", "/api/admin/check",
                                              headers={"X-Admin-Token": token}, use_auth=False)
        self.assertEqual(status, 200)
        self.assertTrue(res.get("authenticated"))

        # 4. Access protected endpoint /api/users using token
        status, res = await asyncio.to_thread(self._request, "GET", "/api/users",
                                              headers={"X-Admin-Token": token}, use_auth=False)
        self.assertEqual(status, 200)
        self.assertIn("users", res)

        # 5. Logout
        status, res = await asyncio.to_thread(self._request, "POST", "/api/admin/logout",
                                              headers={"X-Admin-Token": token}, use_auth=False)
        self.assertEqual(status, 200)

        # 6. Check auth after logout -> False
        status, res = await asyncio.to_thread(self._request, "GET", "/api/admin/check",
                                              headers={"X-Admin-Token": token}, use_auth=False)
        self.assertEqual(status, 200)
        self.assertFalse(res.get("authenticated"))

        # 7. Access /api/users after logout -> 401
        status, res = await asyncio.to_thread(self._request, "GET", "/api/users",
                                              headers={"X-Admin-Token": token}, use_auth=False)
        self.assertEqual(status, 401)

    async def test_guest_dashboard_view(self):
        """Verify guest loading dashboard gets login prompt and loginModal."""
        status, html_content = await asyncio.to_thread(self._request, "GET", "/", use_auth=False)
        self.assertEqual(status, 200)
        self.assertIn("loginModal", html_content)
        self.assertIn("Вход администратора", html_content)
        self.assertIn("adminLoginForm", html_content)


if __name__ == "__main__":
    unittest.main()


