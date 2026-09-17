"""
Comprehensive Automated Test Suite for MSNP Server.
Tests:
1. SQLite Database operations (database.db)
2. MSNP protocol packet framing and payload handling
3. Authentication: MD5 Challenge-Response and TWN Passport tickets
4. End-to-end integration test with simulated clients:
   - Protocol negotiation (VER, CVR)
   - Login handshake (USR MD5)
   - Contact list synchronization (SYN, ADD, REM, REA)
   - Real-time presence updates (CHG, NLN, ILN, FLN)
   - Switchboard chat session (XFR, CAL, RNG, ANS, IRO, JOI, MSG, NOT, BYE)
   - HTTP Nexus, Tweener login, and Web API
"""
import asyncio
import hashlib
import json
import os
import unittest
import urllib.request

import config
from db.database import Database
from protocol.constants import ListMask, UserStatus, MSNPError
from protocol.packet import MSNPReader, MSNPWriter
from protocol.auth import AuthManager
from server import MSNPServer


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.test_db = "test_database.db"
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except Exception:
                pass
        self.db = Database(self.test_db)

    def tearDown(self):
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except Exception:
                pass

    def test_user_crud(self):
        user = self.db.create_user("user1@msn.local", "pass123", "User One")
        self.assertIsNotNone(user)
        self.assertEqual(user.email, "user1@msn.local")
        self.assertEqual(user.friendly_name, "User One")

        # Fetch
        fetched = self.db.get_user("user1@msn.local")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.friendly_name, "User One")

        # Update status
        self.db.update_user_status("user1@msn.local", "BSY", custom_message="Coding...")
        updated = self.db.get_user("user1@msn.local")
        self.assertEqual(updated.status, "BSY")
        self.assertEqual(updated.custom_message, "Coding...")

        # Update friendly name
        self.db.update_friendly_name("user1@msn.local", "New User One")
        self.assertEqual(self.db.get_user("user1@msn.local").friendly_name, "New User One")

    def test_contacts_and_groups(self):
        self.db.create_user("alice@msn.local", "pass1", "Alice")
        self.db.create_user("bob@msn.local", "pass2", "Bob")

        # Add Bob to Alice's FL
        c = self.db.add_or_update_contact("alice@msn.local", "bob@msn.local", ListMask.FL, friendly_name="Bobby")
        self.assertTrue(bool(c.list_flags & ListMask.FL))
        self.assertTrue(bool(c.list_flags & ListMask.AL))

        # Check Bob has Alice on his RL
        bob_contact = self.db.get_contact("bob@msn.local", "alice@msn.local")
        self.assertIsNotNone(bob_contact)
        self.assertTrue(bool(bob_contact.list_flags & ListMask.RL))

        # Group operations
        group = self.db.add_group("alice@msn.local", "Friends")
        self.assertEqual(group.name, "Friends")
        groups = self.db.get_groups("alice@msn.local")
        self.assertEqual(len(groups), 1)

        self.db.rename_group("alice@msn.local", group.id, "Best Friends")
        self.assertEqual(self.db.get_groups("alice@msn.local")[0].name, "Best Friends")

        self.db.remove_group("alice@msn.local", group.id)
        self.assertEqual(len(self.db.get_groups("alice@msn.local")), 0)

    def test_offline_messages(self):
        msg_id = self.db.save_offline_message("sender@msn.local", "receiver@msn.local", "Hello while away!")
        self.assertGreater(msg_id, 0)

        pending = self.db.get_pending_offline_messages("receiver@msn.local")
        self.assertEqual(len(pending), 1)
        self.assertEqual(pending[0].message, "Hello while away!")

        self.db.mark_offline_messages_delivered("receiver@msn.local")
        self.assertEqual(len(self.db.get_pending_offline_messages("receiver@msn.local")), 0)


class TestProtocolPacket(unittest.TestCase):
    def test_packet_framing_simple(self):
        reader = MSNPReader()
        data = b"VER 1 MSNP9 MSNP8 CVR0\r\nCVR 2 test\r\n"
        cmds = reader.feed_data(data)
        self.assertEqual(len(cmds), 2)
        self.assertEqual(cmds[0][0], "VER")
        self.assertEqual(cmds[0][1], ["1", "MSNP9", "MSNP8", "CVR0"])
        self.assertIsNone(cmds[0][2])
        self.assertEqual(cmds[1][0], "CVR")

    def test_packet_framing_with_payload(self):
        reader = MSNPReader()
        payload = b"Hello world! This is a test message."
        cmd_line = f"MSG 1 U {len(payload)}\r\n".encode("utf-8") + payload

        # Feed in two chunks to test stream buffering
        chunk1 = cmd_line[:10]
        chunk2 = cmd_line[10:]

        cmds1 = reader.feed_data(chunk1)
        self.assertEqual(len(cmds1), 0)  # Incomplete

        cmds2 = reader.feed_data(chunk2)
        self.assertEqual(len(cmds2), 1)
        cmd, args, body = cmds2[0]
        self.assertEqual(cmd, "MSG")
        self.assertEqual(args, ["1", "U"])
        self.assertEqual(body, payload)

    def test_writer_formatting(self):
        # Without payload
        data = MSNPWriter.format_command("VER", 1, "MSNP9")
        self.assertEqual(data, b"VER 1 MSNP9\r\n")

        # With payload
        payload = b"Sample Body"
        data2 = MSNPWriter.format_command("MSG", "sender@msn.local", "Sender", payload=payload)
        expected_line = f"MSG sender@msn.local Sender {len(payload)}\r\n".encode("utf-8") + payload
        self.assertEqual(data2, expected_line)


class TestAuthManager(unittest.TestCase):
    def test_md5_challenge(self):
        auth = AuthManager()
        challenge = auth.create_md5_challenge("user@msn.local")
        self.assertTrue(len(challenge) > 0)

        password = "secretpassword"
        valid_hash = hashlib.md5((challenge + password).encode("utf-8")).hexdigest()
        self.assertTrue(auth.verify_md5_response("user@msn.local", valid_hash, password))
        self.assertFalse(auth.verify_md5_response("user@msn.local", "wronghash", password))

    def test_twn_ticket(self):
        auth = AuthManager()
        ticket = auth.create_twn_ticket("user@msn.local")
        self.assertTrue(ticket.startswith("t="))
        self.assertTrue(auth.verify_twn_ticket(ticket, "user@msn.local"))
        self.assertFalse(auth.verify_twn_ticket("invalid_ticket", "user@msn.local"))

    def test_sb_cookie(self):
        auth = AuthManager()
        cookie = auth.create_sb_cookie("user@msn.local", session_id=1001, role="caller")
        res = auth.verify_and_consume_sb_cookie(cookie, "user@msn.local")
        self.assertEqual(res, (1001, "caller"))
        # Consumed, cannot reuse
        self.assertIsNone(auth.verify_and_consume_sb_cookie(cookie, "user@msn.local"))


class TestClient:
    """Helper client using an asyncio queue for non-blocking message consumption."""
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.msnp_reader = MSNPReader()
        self.queue = asyncio.Queue()
        self.read_task = asyncio.create_task(self._read_loop())

    async def _read_loop(self):
        try:
            while True:
                data = await self.reader.read(4096)
                if not data:
                    break
                for cmd in self.msnp_reader.feed_data(data):
                    await self.queue.put(cmd)
        except Exception:
            pass

    async def send(self, line_or_bytes):
        if isinstance(line_or_bytes, str):
            line_or_bytes = line_or_bytes.encode("utf-8")
        self.writer.write(line_or_bytes)
        await self.writer.drain()

    async def next_cmd(self, timeout=4.0):
        return await asyncio.wait_for(self.queue.get(), timeout=timeout)

    async def close(self):
        self.read_task.cancel()
        self.writer.close()
        try:
            await self.writer.wait_closed()
        except Exception:
            pass


class TestEndToEndIntegration(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.test_db = "test_e2e_database.db"
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except Exception:
                pass

        # Dedicated test ports
        self.ns_port = 11863
        self.sb_port = 11864
        self.http_port = 11865

        config.AUTO_ADD_SERVICE_CONTACT = False
        self.server = MSNPServer(
            bind_host="127.0.0.1",
            external_host="127.0.0.1",
            ns_port=self.ns_port,
            sb_port=self.sb_port,
            http_port=self.http_port,
            db_path=self.test_db
        )
        self.server_task = asyncio.create_task(self.server.start())
        await asyncio.sleep(0.3)  # Wait for sockets to bind

        # Pre-seed users in database
        self.server.db.create_user("alice@msn.local", "alicepass", "Alice")
        self.server.db.create_user("bob@msn.local", "bobpass", "Bob")

    async def asyncTearDown(self):
        config.PREFER_MD5_AUTH = False
        config.AUTO_ADD_SERVICE_CONTACT = True
        await self.server.stop()
        try:
            self.server_task.cancel()
            await self.server_task
        except (asyncio.CancelledError, Exception):
            pass

        await asyncio.sleep(0.1)
        if os.path.exists(self.test_db):
            try:
                os.remove(self.test_db)
            except Exception:
                pass

    async def _connect_client(self, port: int) -> TestClient:
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        return TestClient(reader, writer)

    async def test_full_client_chat_and_presence(self):
        config.PREFER_MD5_AUTH = False
        # 1. Alice connects to NS
        alice = await self._connect_client(self.ns_port)

        # Alice: Handshake
        await alice.send("VER 1 MSNP9 MSNP8 CVR0\r\n")
        cmd, args, _ = await alice.next_cmd()
        self.assertEqual(cmd, "VER")
        self.assertEqual(args[1], "MSNP9")

        # Alice: CVR
        await alice.send("CVR 2 0x0409 winnt 5.1 i386 MSNMSGR 6.2.0137 MSMSGS alice@msn.local\r\n")
        cmd, args, _ = await alice.next_cmd()
        self.assertEqual(cmd, "CVR")

        # Alice: USR MD5 I
        await alice.send("USR 3 MD5 I alice@msn.local\r\n")
        cmd, args, _ = await alice.next_cmd()
        self.assertEqual(cmd, "USR")
        self.assertEqual(args[1], "MD5")
        self.assertEqual(args[2], "S")
        challenge = args[3]

        # Alice: Computes MD5 and sends USR MD5 S
        hash_val = hashlib.md5((challenge + "alicepass").encode("utf-8")).hexdigest()
        await alice.send(f"USR 4 MD5 S {hash_val}\r\n")
        cmd, args, _ = await alice.next_cmd()
        self.assertEqual(cmd, "USR")
        self.assertEqual(args[1], "OK")
        self.assertEqual(args[2], "alice@msn.local")

        # Alice: SYN
        await alice.send("SYN 5 0\r\n")
        cmd, args, _ = await alice.next_cmd()
        self.assertEqual(cmd, "SYN")
        # Consume GTC, BLP, LSG
        cmd, args, _ = await alice.next_cmd()
        self.assertEqual(cmd, "GTC")
        cmd, args, _ = await alice.next_cmd()
        self.assertEqual(cmd, "BLP")
        cmd, args, _ = await alice.next_cmd()
        self.assertEqual(cmd, "LSG")

        # Alice: Set status to Online (NLN)
        await alice.send("CHG 6 NLN 1073741824\r\n")
        cmd, args, _ = await alice.next_cmd()
        self.assertEqual(cmd, "CHG")
        self.assertEqual(args[1], "NLN")

        # 2. Bob connects to NS
        bob = await self._connect_client(self.ns_port)

        await bob.send("VER 1 MSNP9 CVR0\r\n")
        await bob.next_cmd()

        await bob.send("CVR 2 0x0409 winnt 5.1 i386 MSNMSGR 6.2.0137 MSMSGS bob@msn.local\r\n")
        await bob.next_cmd()

        await bob.send("USR 3 MD5 I bob@msn.local\r\n")
        cmd, args, _ = await bob.next_cmd()
        bob_challenge = args[3]

        bob_hash = hashlib.md5((bob_challenge + "bobpass").encode("utf-8")).hexdigest()
        await bob.send(f"USR 4 MD5 S {bob_hash}\r\n")
        await bob.next_cmd()  # USR OK

        # Bob adds Alice to FL
        await bob.send("ADD 5 FL alice@msn.local Alice\r\n")
        cmd, args, _ = await bob.next_cmd()
        self.assertEqual(cmd, "ADD")
        self.assertEqual(args[1], "FL")

        # Alice is already online, so server immediately sends Alice's ILN to Bob!
        cmd, args, _ = await bob.next_cmd()
        self.assertEqual(cmd, "ILN")
        self.assertEqual(args[1], "NLN")
        self.assertEqual(args[2], "alice@msn.local")

        # Also Alice receives ADD RL notification from Bob
        cmd, args, _ = await alice.next_cmd()
        self.assertEqual(cmd, "ADD")
        self.assertEqual(args[1], "RL")
        self.assertEqual(args[3], "bob@msn.local")

        # Alice adds Bob to her FL as well
        await alice.send("ADD 7 FL bob@msn.local Bob\r\n")
        cmd, args, _ = await alice.next_cmd()
        self.assertEqual(cmd, "ADD")
        self.assertEqual(args[1], "FL")

        # Bob receives ADD RL notification from Alice
        cmd, args, _ = await bob.next_cmd()
        self.assertEqual(cmd, "ADD")
        self.assertEqual(args[1], "RL")
        self.assertEqual(args[3], "alice@msn.local")

        # Bob sets status to Online (NLN)
        await bob.send("CHG 6 NLN 1073741824\r\n")
        cmd, args, _ = await bob.next_cmd()  # CHG response
        self.assertEqual(cmd, "CHG")
        self.assertEqual(args[1], "NLN")

        # Bob receives initial presence (ILN) for online contact Alice
        cmd, args, _ = await bob.next_cmd()
        self.assertEqual(cmd, "ILN")
        self.assertEqual(args[1], "NLN")
        self.assertEqual(args[2], "alice@msn.local")

        # Alice receives Bob's presence (NLN)
        alice_presence_cmd, alice_presence_args, _ = await alice.next_cmd()
        self.assertEqual(alice_presence_cmd, "NLN")
        self.assertEqual(alice_presence_args[0], "NLN")
        self.assertEqual(alice_presence_args[1], "bob@msn.local")

        # 3. Switchboard Chat Session Test
        # Alice requests Switchboard transfer: XFR 8 SB
        await alice.send("XFR 8 SB\r\n")
        cmd, args, _ = await alice.next_cmd()
        self.assertEqual(cmd, "XFR")
        self.assertEqual(args[1], "SB")
        sb_host_port = args[2]
        self.assertEqual(args[3], "CKI")
        alice_sb_cookie = args[4]

        # Alice connects to Switchboard
        sb_host, sb_port_str = sb_host_port.split(":")
        alice_sb = await self._connect_client(int(sb_port_str))

        # Alice authenticates to SB: USR 1 alice@msn.local <cookie>
        await alice_sb.send(f"USR 1 alice@msn.local {alice_sb_cookie}\r\n")
        cmd, args, _ = await alice_sb.next_cmd()
        self.assertEqual(cmd, "USR")
        self.assertEqual(args[1], "OK")

        # Alice invites Bob: CAL 2 bob@msn.local
        await alice_sb.send("CAL 2 bob@msn.local\r\n")
        cmd, args, _ = await alice_sb.next_cmd()
        self.assertEqual(cmd, "CAL")
        self.assertEqual(args[1], "RINGING")
        session_id = args[2]

        # Bob receives RNG over his NS connection!
        cmd, args, _ = await bob.next_cmd()
        self.assertEqual(cmd, "RNG")
        self.assertEqual(args[0], session_id)
        bob_sb_host_port = args[1]
        self.assertEqual(args[2], "CKI")
        bob_sb_cookie = args[3]
        self.assertEqual(args[4], "alice@msn.local")

        # Bob connects to Switchboard
        bob_sb = await self._connect_client(int(sb_port_str))

        # Bob answers: ANS 1 bob@msn.local <cookie> <session_id>
        await bob_sb.send(f"ANS 1 bob@msn.local {bob_sb_cookie} {session_id}\r\n")
        cmd, args, _ = await bob_sb.next_cmd()
        self.assertEqual(cmd, "ANS")
        self.assertEqual(args[1], "OK")

        # Bob receives IRO for Alice
        cmd, args, _ = await bob_sb.next_cmd()
        self.assertEqual(cmd, "IRO")
        self.assertEqual(args[3], "alice@msn.local")

        # Alice receives JOI for Bob
        cmd, args, _ = await alice_sb.next_cmd()
        self.assertEqual(cmd, "JOI")
        self.assertEqual(args[0], "bob@msn.local")

        # 4. Chat messaging test
        # Alice sends MSG to Bob
        chat_body = (
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/plain; charset=UTF-8\r\n\r\n"
            "Hi Bob! How are you?"
        ).encode("utf-8")
        await alice_sb.send(f"MSG 3 A {len(chat_body)}\r\n".encode("utf-8") + chat_body)

        # Alice receives ACK 3
        cmd, args, _ = await alice_sb.next_cmd()
        self.assertEqual(cmd, "ACK")
        self.assertEqual(args[0], "3")

        # Bob receives MSG from Alice
        cmd, args, body = await bob_sb.next_cmd()
        self.assertEqual(cmd, "MSG")
        self.assertEqual(args[0], "alice@msn.local")
        self.assertEqual(body, chat_body)

        # 5. Typing notification test
        typing_payload = (
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/x-msmsgscontrol\r\n"
            "TypingUser: bob@msn.local\r\n\r\n"
        ).encode("utf-8")
        await bob_sb.send(f"NOT {len(typing_payload)}\r\n".encode("utf-8") + typing_payload)

        # Alice receives NOT from Bob
        cmd, args, body = await alice_sb.next_cmd()
        self.assertEqual(cmd, "NOT")
        self.assertEqual(args[0], "bob@msn.local")
        self.assertEqual(body, typing_payload)

        # 6. Bob leaves Switchboard
        await bob_sb.close()

        # Alice receives BYE for Bob
        cmd, args, _ = await alice_sb.next_cmd()
        self.assertEqual(cmd, "BYE")
        self.assertEqual(args[0], "bob@msn.local")

        # Clean up
        await alice.close()
        await bob.close()
        await alice_sb.close()

    async def test_http_nexus_and_api(self):
        # 1. Test Nexus Redirection
        def fetch_nexus():
            req = urllib.request.Request(f"http://127.0.0.1:{self.http_port}/rdr/pprdr.asp")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.headers.get("PassportURLs")

        status, passport_urls = await asyncio.to_thread(fetch_nexus)
        self.assertEqual(status, 200)
        self.assertIsNotNone(passport_urls)
        self.assertIn("DALogin=", passport_urls)

        # 2. Test Tweener Login
        def fetch_tweener():
            req = urllib.request.Request(f"http://127.0.0.1:{self.http_port}/login.srf")
            req.add_header("Authorization", "Passport1.4 sign-in=alice%40msn.local,pwd=alicepass")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.headers.get("Authentication-Info")

        status, auth_info = await asyncio.to_thread(fetch_tweener)
        self.assertEqual(status, 200)
        self.assertIsNotNone(auth_info)
        self.assertIn("da-status=success", auth_info)
        self.assertIn("tkt=t=", auth_info)

        # 3. Test API Register
        def post_register():
            reg_payload = json.dumps({
                "email": "charlie@msn.local",
                "password": "charliepass",
                "friendly_name": "Charlie"
            }).encode("utf-8")
            req = urllib.request.Request(
                f"http://127.0.0.1:{self.http_port}/api/register",
                data=reg_payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))

        status, reg_data = await asyncio.to_thread(post_register)
        self.assertEqual(status, 200)
        self.assertTrue(reg_data.get("success"))
        self.assertEqual(reg_data.get("email"), "charlie@msn.local")

        # 4. Test API Status
        def fetch_status():
            req = urllib.request.Request(f"http://127.0.0.1:{self.http_port}/api/status")
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))

        status, status_data = await asyncio.to_thread(fetch_status)
        self.assertEqual(status, 200)
        self.assertEqual(status_data.get("status"), "online")
        self.assertGreaterEqual(status_data.get("total_users"), 3)

    async def test_msnp5_client_login_and_sync(self):
        """Tests the exact MSNP5 client handshake (Gaim/Trillian retro mode)."""
        client = await self._connect_client(self.ns_port)

        # 1. VER MSNP5
        await client.send("VER 1 MSNP5\r\n")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "VER")
        self.assertEqual(args[1], "MSNP5")

        # 2. INF
        await client.send("INF 2\r\n")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "INF")
        self.assertEqual(args[1], "MD5")

        # 3. USR MD5 I
        await client.send("USR 3 MD5 I alice@msn.local\r\n")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "USR")
        self.assertEqual(args[1], "MD5")
        self.assertEqual(args[2], "S")
        challenge = args[3]

        # 4. USR MD5 S
        hash_val = hashlib.md5((challenge + "alicepass").encode("utf-8")).hexdigest()
        await client.send(f"USR 4 MD5 S {hash_val}\r\n")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "USR")
        self.assertEqual(args[1], "OK")
        self.assertEqual(args[2], "alice@msn.local")
        self.assertEqual(args[3], "Alice")
        # In MSNP5, no verified bit or account restriction bit is appended
        self.assertEqual(len(args), 4)

        # 5. SYN
        await client.send("SYN 5 0\r\n")
        # In MSNP5: SYN trid ser
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "SYN")
        self.assertEqual(len(args), 2)  # [trid, sync_serial]

        # In MSNP5: GTC trid ser val
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "GTC")
        self.assertEqual(len(args), 3)  # [trid, sync_serial, "A"]

        # In MSNP5: BLP trid ser val
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "BLP")
        self.assertEqual(len(args), 3)  # [trid, sync_serial, "AL"]

        # In MSNP5: 4 LST commands (FL, AL, BL, RL)
        for expected_list in ("FL", "AL", "BL", "RL"):
            cmd, args, _ = await client.next_cmd()
            self.assertEqual(cmd, "LST")
            self.assertEqual(args[1], expected_list)

        # 6. CHG
        await client.send("CHG 6 NLN\r\n")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "CHG")
        self.assertEqual(args[1], "NLN")
        self.assertEqual(len(args), 2)  # In MSNP5, no client_id is in reply

        # 7. REA
        await client.send("REA 7 alice@msn.local NewAlice\r\n")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "REA")
        self.assertEqual(args[3], "NewAlice")

        await client.close()

    async def test_msnp5_with_contacts_and_presence(self):
        # Pre-populate contact for alice
        self.server.db.add_or_update_contact("alice@msn.local", "bob@msn.local", 1, 0, "Bob")

        client = await self._connect_client(self.ns_port)
        await client.send("VER 1 MSNP5\r\n")
        await client.next_cmd()

        await client.send("INF 2\r\n")
        await client.next_cmd()

        await client.send("USR 3 MD5 I alice@msn.local\r\n")
        cmd, args, _ = await client.next_cmd()
        ch = args[3]
        hv = hashlib.md5((ch + "alicepass").encode("utf-8")).hexdigest()
        await client.send(f"USR 4 MD5 S {hv}\r\n")
        await client.next_cmd()

        # SYN
        await client.send("SYN 5 0\r\n")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "SYN")
        self.assertEqual(len(args), 2)

        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "GTC")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "BLP")

        # FL has 1 contact: LST trid FL ser item_idx total email fname
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "LST")
        self.assertEqual(args[1], "FL")
        self.assertEqual(args[3], "1")  # item 1
        self.assertEqual(args[4], "1")  # total 1
        self.assertEqual(args[5], "bob@msn.local")
        self.assertEqual(args[6], "Bob")

        # AL also has 1 contact (FL contacts are auto-allowed)
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "LST")
        self.assertEqual(args[1], "AL")
        self.assertEqual(args[3], "1")
        self.assertEqual(args[4], "1")
        self.assertEqual(args[5], "bob@msn.local")

        # BL, RL empty
        for expected_list in ("BL", "RL"):
            cmd, args, _ = await client.next_cmd()
            self.assertEqual(cmd, "LST")
            self.assertEqual(args[1], expected_list)
            self.assertEqual(args[3], "0")
            self.assertEqual(args[4], "0")

        await client.close()

    async def test_gaim_msnp9_direct_twn_login(self):
        # Real Gaim 0.80 sequence:
        # Gaim connects, negotiates MSNP9, sends CVR, then sends USR 3 TWN I <email>.
        # With BYPASS_PASSPORT_FOR_TWN=True, server immediately replies USR 3 OK,
        # allowing Gaim to retrieve buddy list and come online without hanging on dead passport HTTPS!
        client = await self._connect_client(self.ns_port)
        await client.send("VER 1 MSNP9 MSNP8 CVR0\r\n")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "VER")
        self.assertEqual(args[1], "MSNP9")

        # Gaim sends CVR
        await client.send("CVR 2 0x0409 winnt 5.1 i386 MSNMSGR 6.0.0602 MSMSGS jopa@msn.local\r\n")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "CVR")

        # Gaim sends USR 3 TWN I jopa@msn.local
        await client.send("USR 3 TWN I jopa@msn.local\r\n")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "USR")
        self.assertEqual(args[1], "OK")
        self.assertEqual(args[2], "jopa@msn.local")

        # Gaim sends SYN 4 0
        await client.send("SYN 4 0\r\n")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "SYN")

        # MSNP9 sends: GTC, BLP, LSG (no LST since jopa has 0 contacts)
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "GTC")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "BLP")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "LSG")

        # Gaim sends CHG 5 NLN
        await client.send("CHG 5 NLN 1073741824\r\n")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "CHG")
        self.assertEqual(args[1], "NLN")

        await client.close()

    async def test_gaim_msnp9_fallback_to_msnp7(self):
        # When PREFER_MD5_AUTH is explicitly set, server selects MSNP7
        old_pref = getattr(config, "PREFER_MD5_AUTH", False)
        config.PREFER_MD5_AUTH = True
        try:
            client = await self._connect_client(self.ns_port)
            await client.send("VER 1 MSNP9 MSNP8 CVR0\r\n")
            cmd, args, _ = await client.next_cmd()
            self.assertEqual(cmd, "VER")
            self.assertEqual(args[1], "MSNP7")

            # Client sends INF 2
            await client.send("INF 2\r\n")
            cmd, args, _ = await client.next_cmd()
            self.assertEqual(cmd, "INF")
            self.assertEqual(args[1], "MD5")

            # Client sends USR 3 MD5 I
            await client.send("USR 3 MD5 I alice@msn.local\r\n")
            cmd, args, _ = await client.next_cmd()
            self.assertEqual(cmd, "USR")
            self.assertEqual(args[1], "MD5")
            self.assertEqual(args[2], "S")
            challenge = args[3]

            # Client computes MD5 and sends USR 4 MD5 S
            hash_val = hashlib.md5((challenge + "alicepass").encode("utf-8")).hexdigest()
            await client.send(f"USR 4 MD5 S {hash_val}\r\n")
            cmd, args, _ = await client.next_cmd()
            self.assertEqual(cmd, "USR")
            self.assertEqual(args[1], "OK")
            self.assertEqual(args[2], "alice@msn.local")

            await client.close()
        finally:
            config.PREFER_MD5_AUTH = old_pref

    async def test_cyrillic_encoding_and_contact_saving(self):
        """Tests that Cyrillic group names and contact friendly names save and round-trip without mojibake."""
        # 1. Connect user1
        client = await self._connect_client(self.ns_port)
        await client.send("VER 1 MSNP9 CVR0\r\n")
        await client.next_cmd()
        await client.send("CVR 2 0x0409 winnt 5.1 i386 MSNMSGR 6.2.0137 MSMSGS rus_user@msn.local\r\n")
        await client.next_cmd()

        await client.send("USR 3 TWN I rus_user@msn.local\r\n")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "USR")
        self.assertEqual(args[1], "OK")

        # 2. Add group with Cyrillic name using Gaim's mixed bug representation
        # b'ADG 4 \xd0\x9f\xd0\xbe\xd0%bb\xd1\x8c\xd0%b7\xd0\xbe\xd0\xb2\xd0%b0\xd1%82\xd0\xb5\xd0%bb\xd0\xb8 0\r\n'
        gaim_adg = b"ADG 4 \xd0\x9f\xd0\xbe\xd0%bb\xd1\x8c\xd0%b7\xd0\xbe\xd0\xb2\xd0%b0\xd1%82\xd0\xb5\xd0%bb\xd0\xb8 0\r\n"
        client.writer.write(gaim_adg)
        await client.writer.drain()

        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "ADG")
        self.assertEqual(args[2], "Пользователи")
        group_id = int(args[3])
        self.assertGreater(group_id, 0)

        # Verify in DB directly
        groups = self.server.db.get_groups("rus_user@msn.local")
        self.assertTrue(any(g.name == "Пользователи" for g in groups))

        # 3. Add contact with Cyrillic name to FL in that group
        # Gaim sends: ADD 5 FL friend_rus@msn.local <friendly_name> <group_id>
        await client.send(f"ADD 5 FL friend_rus@msn.local Иван {group_id}\r\n")
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "ADD")
        self.assertEqual(args[1], "FL")
        self.assertEqual(args[3], "friend_rus@msn.local")
        self.assertEqual(args[4], "Иван")
        self.assertEqual(int(args[5]), group_id)

        # Verify contact in DB: must have FL (1) and AL (2) set, so list_flags & 1 != 0
        c = self.server.db.get_contact("rus_user@msn.local", "friend_rus@msn.local")
        self.assertIsNotNone(c)
        self.assertTrue(c.list_flags & 1)  # FL is set!
        self.assertTrue(c.list_flags & 2)  # AL is set!
        self.assertEqual(c.friendly_name, "Иван")
        self.assertEqual(c.group_id, group_id)

        # 4. Now test SYN response: ensure LSG and LST correctly deliver Cyrillic names
        await client.send("SYN 6 0\r\n")
        cmd, args, _ = await client.next_cmd()  # SYN
        self.assertEqual(cmd, "SYN")
        await client.next_cmd()  # GTC
        await client.next_cmd()  # BLP

        # Groups (LSG 0 Other Contacts, LSG 1 Пользователи)
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "LSG")

        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "LSG")
        self.assertEqual(int(args[0]), group_id)
        self.assertEqual(args[1], "Пользователи")

        # Contact (LST)
        cmd, args, _ = await client.next_cmd()
        self.assertEqual(cmd, "LST")
        self.assertEqual(args[0], "friend_rus@msn.local")
        self.assertEqual(args[1], "Иван")
        self.assertEqual(int(args[2]) & 1, 1)  # FL flag is present!
        self.assertEqual(int(args[3]), group_id)

        await client.close()


if __name__ == "__main__":
    unittest.main()

