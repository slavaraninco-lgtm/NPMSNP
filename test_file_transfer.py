"""
Unit and Integration Tests for MSNP Server File Transfer
- MSNFTP Relay protocol (VER, USR, FIL, TFR, binary chunk streaming)
- Switchboard invitation interception and NAT IP rewriting
- Database file records CRUD and download counting
- HTTP REST API for file upload, listing, bot delivery, and deletion
- Public file download without authentication
"""

import asyncio
import io
import os
import shutil
import struct
import tempfile
import unittest
import urllib.parse
from http import HTTPStatus

import config
from db.database import Database
from protocol.sb_handler import SBClientHandler
from protocol.auth import AuthManager
from services.http_server import HTTPServer
from services.msnftp_relay import MSNFTPRelayServer
from db.security import encrypt_password
from services.session_manager import SessionManager


class TestFileTransfer(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.db_path = os.path.join(self.test_dir, "test.db")
        self.files_dir = os.path.join(self.test_dir, "files")
        os.makedirs(self.files_dir, exist_ok=True)

        self._orig_base_dir = config.BASE_DIR
        self._orig_storage_dir = getattr(config, "FILES_STORAGE_DIR", None)
        self._orig_ext_host = getattr(config, "EXTERNAL_HOST", None)
        self._orig_msnftp_port = getattr(config, "MSNFTP_PORT", None)

        config.BASE_DIR = self.test_dir
        config.FILES_STORAGE_DIR = self.files_dir
        config.EXTERNAL_HOST = "127.0.0.1"

        self.db = Database(self.db_path)
        self.session_manager = SessionManager(self.db)
        self.auth_manager = AuthManager(self.db)

        # Start MSNFTP relay on an ephemeral port
        self.msnftp_relay = MSNFTPRelayServer(
            bind_host="127.0.0.1",
            port=0,
            external_host="127.0.0.1"
        )
        await self.msnftp_relay.start()
        self.msnftp_port = self.msnftp_relay._server.sockets[0].getsockname()[1]
        self.msnftp_relay.port = self.msnftp_port
        config.MSNFTP_PORT = self.msnftp_port

        # Start HTTP server on ephemeral port
        self.http_server = HTTPServer(
            db=self.db,
            session_manager=self.session_manager,
            auth_manager=self.auth_manager,
            host="127.0.0.1",
            port=0,
            external_host="127.0.0.1",
            switchboard_manager=None,
            msnftp_relay=self.msnftp_relay
        )
        await self.http_server.start()
        self.http_port = self.http_server._server.sockets[0].getsockname()[1]
        self.http_server.port = self.http_port

    async def asyncTearDown(self):
        if self.http_server:
            await self.http_server.stop()
        if self.msnftp_relay:
            await self.msnftp_relay.stop()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

        config.BASE_DIR = self._orig_base_dir
        if self._orig_storage_dir is not None:
            config.FILES_STORAGE_DIR = self._orig_storage_dir
        if self._orig_ext_host is not None:
            config.EXTERNAL_HOST = self._orig_ext_host
        if self._orig_msnftp_port is not None:
            config.MSNFTP_PORT = self._orig_msnftp_port

    # -------------------------------------------------------------
    # 1. Database File Operations
    # -------------------------------------------------------------
    def test_database_file_crud(self):
        file_rec = self.db.save_uploaded_file(
            file_id="abc12345",
            original_name="test_photo.jpg",
            stored_name="abc12345_test_photo.jpg",
            file_size=2048,
            uploaded_by="test_user"
        )
        self.assertEqual(file_rec["file_id"], "abc12345")
        self.assertEqual(file_rec["original_name"], "test_photo.jpg")
        self.assertEqual(file_rec["file_size"], 2048)
        self.assertEqual(file_rec["download_count"], 0)

        # Get file
        fetched = self.db.get_uploaded_file("abc12345")
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["original_name"], "test_photo.jpg")

        # Increment download count
        self.db.increment_download_count("abc12345")
        self.db.increment_download_count("abc12345")
        updated = self.db.get_uploaded_file("abc12345")
        self.assertEqual(updated["download_count"], 2)

        # List files
        all_files = self.db.get_all_uploaded_files()
        self.assertEqual(len(all_files), 1)

        # Delete file
        del_ok = self.db.delete_uploaded_file("abc12345")
        self.assertTrue(del_ok)
        self.assertIsNone(self.db.get_uploaded_file("abc12345"))

    # -------------------------------------------------------------
    # 2. MSNFTP Relay Protocol Handshake and Data Transfer
    # -------------------------------------------------------------
    async def test_msnftp_relay_file_transfer(self):
        # Create a sample test file on disk
        test_content = b"MSNFTP Transfer Content " * 200  # 4800 bytes
        file_path = os.path.join(self.files_dir, "sample.txt")
        with open(file_path, "wb") as f:
            f.write(test_content)

        cookie = "testcookie123"
        self.msnftp_relay.register_session(
            sender_email="alice@msn.local",
            receiver_email="bob@msn.local",
            auth_cookie=cookie,
            file_name="sample.txt",
            file_size=len(test_content),
            file_path=file_path
        )

        # Connect as receiver
        reader, writer = await asyncio.open_connection("127.0.0.1", self.msnftp_port)

        # Step 1: VER
        writer.write(b"VER MSNFTP\r\n")
        await writer.drain()
        line = await reader.readline()
        self.assertEqual(line.strip(), b"VER MSNFTP")

        # Step 2: USR
        writer.write(f"USR bob@msn.local {cookie}\r\n".encode("latin-1"))
        await writer.drain()

        # Step 3: FIL response from relay
        fil_line = await reader.readline()
        self.assertTrue(fil_line.startswith(b"FIL "))
        filesize = int(fil_line.strip().split()[1])
        self.assertEqual(filesize, len(test_content))

        # Step 4: TFR
        writer.write(b"TFR\r\n")
        await writer.drain()

        # Step 5: Read binary blocks
        received_data = bytearray()
        while len(received_data) < len(test_content):
            hdr = await reader.readexactly(3)
            is_last, chunk_len = struct.unpack("<BH", hdr)
            chunk = await reader.readexactly(chunk_len)
            received_data.extend(chunk)
            if is_last:
                break

        writer.close()
        await writer.wait_closed()

        self.assertEqual(bytes(received_data), test_content)

    # -------------------------------------------------------------
    # 3. Switchboard Invitation NAT Rewriting and Bridging
    # -------------------------------------------------------------
    async def test_sb_handler_nat_rewrite(self):
        handler = SBClientHandler.__new__(SBClientHandler)
        handler.msnftp_relay = self.msnftp_relay
        handler.email = "sender@msn.local"
        handler.friendly_name = "Sender"
        handler.peername = ("192.168.1.105", 54321)
        handler.external_host = "127.0.0.1"
        handler.room = None

        raw_invite = (
            "Invitation-Command: ACCEPT\r\n"
            "Application-Name: File Transfer\r\n"
            "Application-GUID: {5D3E02AB-6190-11d3-BBBB-00C04F795683}\r\n"
            "Invitation-Cookie: 987654\r\n"
            "IP-Address: 192.168.1.105\r\n"
            "Port: 6891\r\n"
            "AuthCookie: cookieXYZ\r\n"
            "\r\n"
        ).encode("utf-8")

        res = await handler._process_file_transfer_payload(raw_invite)
        self.assertIsNotNone(res)
        processed = res.decode("utf-8")

        self.assertIn("IP-Address: 127.0.0.1", processed)
        self.assertIn(f"Port: {self.msnftp_port}", processed)
        self.assertIn("AuthCookie: cookieXYZ", processed)
        self.assertNotIn("192.168.1.105", processed)

        # Check relay registered session
        sess = self.msnftp_relay.get_session("cookieXYZ")
        self.assertIsNotNone(sess)
        self.assertEqual(sess.sender_email, "sender@msn.local")
        self.assertEqual(sess.sender_host, "192.168.1.105")
        self.assertEqual(sess.sender_port, 6891)

    async def test_msnftp_receive_file_from_sender(self):
        """Tests that MSNFTPRelayServer can connect to an MSNFTP sender and receive file data."""
        test_data = b"PHOTO BINARY DATA " * 300  # 5400 bytes

        # Start simulated sender
        async def handle_sender(r, w):
            line1 = await r.readline()
            self.assertEqual(line1.strip(), b"VER MSNFTP")
            w.write(b"VER MSNFTP\r\n")
            await w.drain()

            line2 = await r.readline()
            self.assertTrue(line2.startswith(b"USR "))
            w.write(f"FIL {len(test_data)}\r\n".encode("ascii"))
            await w.drain()

            line3 = await r.readline()
            self.assertEqual(line3.strip(), b"TFR")

            # Stream chunks
            offset = 0
            while offset < len(test_data):
                chunk = test_data[offset:offset+1024]
                offset += len(chunk)
                is_last = 1 if offset >= len(test_data) else 0
                w.write(struct.pack("<BH", is_last, len(chunk)) + chunk)
                await w.drain()

            try:
                bye_line = await asyncio.wait_for(r.readline(), timeout=3.0)
                self.assertTrue(bye_line.startswith(b"BYE"))
            except Exception:
                pass
            w.close()
            await w.wait_closed()

        server = await asyncio.start_server(handle_sender, "127.0.0.1", 0)
        sender_port = server.sockets[0].getsockname()[1]

        received = await self.msnftp_relay.receive_file_from_sender(
            sender_host="127.0.0.1",
            sender_port=sender_port,
            auth_cookie="cookieABC",
            receiver_email="receiver@msn.local",
            file_name="sample.jpg",
            file_size=len(test_data)
        )

        server.close()
        await server.wait_closed()

        self.assertIsNotNone(received)
        self.assertEqual(received, test_data)

    async def test_sb_handler_auto_accept_for_gaim(self):
        """Tests that SBClientHandler automatically accepts an INVITE when recipient is Gaim."""
        handler = SBClientHandler.__new__(SBClientHandler)
        handler.msnftp_relay = self.msnftp_relay
        handler.email = "trillian_user@msn.local"
        handler.friendly_name = "TrillianUser"
        handler.peername = ("127.0.0.1", 55555)
        handler.external_host = "127.0.0.1"
        handler.session_manager = self.session_manager
        handler.session_id = 9999
        handler.http_port = self.http_port
        handler.db = self.db

        sent_commands = []
        handler.send_cmd = lambda cmd, *args, payload=None: sent_commands.append((cmd, args, payload))

        # Setup room with Gaim recipient
        class DummyRoom:
            def get_participants(self):
                class DummyParticipant:
                    email = "gaim_user@msn.local"
                    friendly_name = "GaimUser"
                return [DummyParticipant()]

        handler.room = DummyRoom()

        # Register Gaim user in session manager with gaim in client_app
        class DummyNSHandler:
            client_app = "winnt 5.1 i386 gaim 0.80"
        self.session_manager._active_sessions["gaim_user@msn.local"] = DummyNSHandler()

        raw_invite = (
            "MIME-Version: 1.0\r\n"
            "Content-Type: text/x-msmsgsinvite; charset=UTF-8\r\n\r\n"
            "Application-Name: File Transfer\r\n"
            "Application-GUID: {5D3E02AB-6190-11d3-BBBB-00C04F795683}\r\n"
            "Invitation-Command: INVITE\r\n"
            "Invitation-Cookie: 112233\r\n"
            "Application-File: my_photo.png\r\n"
            "Application-FileSize: 5000\r\n"
        ).encode("utf-8")

        res = await handler._process_file_transfer_payload(raw_invite)
        # Should return None because it was auto-accepted by server and not forwarded to Gaim
        self.assertIsNone(res)

        # Verify ACCEPT was sent back to sender on behalf of GaimUser
        self.assertEqual(len(sent_commands), 1)
        cmd, args, payload = sent_commands[0]
        self.assertEqual(cmd, "MSG")
        self.assertIn("gaim_user@msn.local", args)
        self.assertIn(b"Invitation-Command: ACCEPT", payload)
        self.assertIn(b"Invitation-Cookie: 112233", payload)
        self.assertIn(b"Request-Data: IP-Address:", payload)

    # -------------------------------------------------------------
    # 4. HTTP API File Upload, Download, Send, and Delete
    # -------------------------------------------------------------
    async def _http_request(self, method: str, path: str, headers: dict = None, body: bytes = b"") -> tuple[int, dict, bytes]:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.http_port)
        headers = headers or {}
        req_lines = [f"{method} {path} HTTP/1.1", f"Host: 127.0.0.1:{self.http_port}"]
        for k, v in headers.items():
            req_lines.append(f"{k}: {v}")
        if body:
            req_lines.append(f"Content-Length: {len(body)}")
        else:
            if "Content-Length" not in headers:
                req_lines.append("Content-Length: 0")

        req = "\r\n".join(req_lines) + "\r\n\r\n"
        writer.write(req.encode("latin-1") + body)
        await writer.drain()

        # Read response status
        status_line = await reader.readline()
        parts = status_line.decode("latin-1").split(" ", 2)
        status_code = int(parts[1])

        # Read headers
        resp_headers = {}
        while True:
            hline = await reader.readline()
            if hline in (b"\r\n", b"\n", b""):
                break
            if b":" in hline:
                hk, hv = hline.decode("latin-1").split(":", 1)
                resp_headers[hk.strip().lower()] = hv.strip()

        # Read body
        content_len = int(resp_headers.get("content-length", 0))
        resp_body = await reader.readexactly(content_len) if content_len > 0 else await reader.read()

        writer.close()
        await writer.wait_closed()
        return status_code, resp_headers, resp_body

    async def test_http_file_upload_and_download(self):
        # 1. Upload without admin password -> 401 Unauthorized
        test_file_bytes = b"Hello from Retro MSN Messenger File Storage!"
        boundary = "----TestBoundary12345"
        body_parts = (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="retro_hello.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\n"
        ).encode("utf-8") + test_file_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

        status, _, _ = await self._http_request(
            "POST",
            "/api/files/upload",
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
            body=body_parts
        )
        self.assertEqual(status, HTTPStatus.UNAUTHORIZED)

        # 2. Upload with admin credentials -> 200 OK
        status, _, body = await self._http_request(
            "POST",
            "/api/files/upload",
            headers={
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "X-Admin-Password": "admin123"
            },
            body=body_parts
        )
        self.assertEqual(status, HTTPStatus.OK)
        import json
        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data["success"])
        file_rec = data["file"]
        file_id = file_rec["file_id"]
        self.assertEqual(file_rec["original_name"], "retro_hello.txt")

        # 3. List files via GET /api/files
        status, _, body = await self._http_request(
            "GET",
            "/api/files",
            headers={"X-Admin-Password": "admin123"}
        )
        self.assertEqual(status, HTTPStatus.OK)
        list_data = json.loads(body.decode("utf-8"))
        self.assertEqual(len(list_data["files"]), 1)
        self.assertEqual(list_data["files"][0]["file_id"], file_id)

        # 4. Public download via GET /files/<file_id>/<filename> WITHOUT any auth!
        dl_url = f"/files/{file_id}/retro_hello.txt"
        status, headers, dl_body = await self._http_request("GET", dl_url)
        self.assertEqual(status, HTTPStatus.OK)
        self.assertEqual(dl_body, test_file_bytes)
        self.assertIn("attachment", headers.get("content-disposition", ""))

        # Check that download count was incremented
        rec = self.db.get_uploaded_file(file_id)
        self.assertEqual(rec["download_count"], 1)

        # 5. Delete file via POST /api/files/delete
        status, _, body = await self._http_request(
            "POST",
            "/api/files/delete",
            headers={
                "Content-Type": "application/json",
                "X-Admin-Password": "admin123"
            },
            body=json.dumps({"file_id": file_id}).encode("utf-8")
        )
        self.assertEqual(status, HTTPStatus.OK)
        del_data = json.loads(body.decode("utf-8"))
        self.assertTrue(del_data["success"])

        # Try to download again -> 404
        status, _, _ = await self._http_request("GET", dl_url)
        self.assertEqual(status, HTTPStatus.NOT_FOUND)

    async def test_http_file_send_bot(self):
        file_rec = self.db.save_uploaded_file(
            file_id="botfile99",
            original_name="document.pdf",
            stored_name="botfile99_document.pdf",
            file_size=1024,
            uploaded_by="Admin"
        )
        import json
        status, _, body = await self._http_request(
            "POST",
            "/api/files/send",
            headers={
                "Content-Type": "application/json",
                "X-Admin-Password": "admin123"
            },
            body=json.dumps({
                "file_id": "botfile99",
                "target": "targetuser@msn.local",
                "message": "Пожалуйста, ознакомьтесь с документом."
            }).encode("utf-8")
        )
        self.assertEqual(status, HTTPStatus.OK)
        data = json.loads(body.decode("utf-8"))
        self.assertTrue(data["success"])
        self.assertEqual(data["file_id"], "botfile99")

        # When target is offline or no switchboard, notice is queued in offline_messages
        offline_msgs = self.db.get_pending_offline_messages("targetuser@msn.local")
        self.assertEqual(len(offline_msgs), 1)
        msg_text = offline_msgs[0].message
        self.assertIn("document.pdf", msg_text)
        self.assertIn("/files/botfile99/document.pdf", msg_text)
        self.assertIn("Пожалуйста, ознакомьтесь с документом.", msg_text)


if __name__ == "__main__":
    unittest.main()
