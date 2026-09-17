"""
MSNFTP (MSN File Transfer Protocol) Relay and File Sender Service.
Supports:
1. P2P Relay / Bridge between MSN Messenger clients (bypassing NAT/firewalls)
2. Native MSNFTP Server File Sender: sends files directly to MSN clients (Gaim, Pidgin, Trillian, MSN Messenger)
3. Handshake: VER MSNFTP, USR, FIL, TFR, and 3-byte binary block streaming.
"""
import asyncio
import logging
import os
import struct
import time
from typing import Dict, Optional, Any, Tuple

import config

logger = logging.getLogger("MSNP.MSNFTP")


class MSNFTPTransferSession:
    """Represents an active or pending MSNFTP transfer session."""
    def __init__(self, session_id: str, sender_email: str, receiver_email: str,
                 auth_cookie: str, file_name: str, file_size: int,
                 file_path: Optional[str] = None,
                 sender_host: Optional[str] = None, sender_port: Optional[int] = None):
        self.session_id = session_id
        self.sender_email = sender_email.lower().strip()
        self.receiver_email = receiver_email.lower().strip()
        self.auth_cookie = str(auth_cookie).strip()
        self.file_name = file_name
        self.file_size = file_size
        self.file_path = file_path  # If local server file to send
        self.sender_host = sender_host  # If relaying to peer's listening socket
        self.sender_port = sender_port
        self.created_at = time.time()
        self.completed = False


class MSNFTPRelayServer:
    def __init__(self, bind_host: str = config.BIND_HOST,
                 port: int = getattr(config, "MSNFTP_PORT", 1866),
                 external_host: str = config.EXTERNAL_HOST):
        self.bind_host = bind_host
        self.port = port
        self.external_host = external_host
        self._server: Optional[asyncio.Server] = None
        self._sessions: Dict[str, MSNFTPTransferSession] = {}  # keyed by auth_cookie
        self._running = False

    def register_session(self, sender_email: str, receiver_email: str,
                         auth_cookie: str, file_name: str, file_size: int,
                         file_path: Optional[str] = None,
                         sender_host: Optional[str] = None,
                         sender_port: Optional[int] = None) -> MSNFTPTransferSession:
        """Registers an MSNFTP transfer session for incoming client connections."""
        session_id = f"msnftp_{int(time.time())}_{auth_cookie}"
        sess = MSNFTPTransferSession(
            session_id=session_id,
            sender_email=sender_email,
            receiver_email=receiver_email,
            auth_cookie=auth_cookie,
            file_name=file_name,
            file_size=file_size,
            file_path=file_path,
            sender_host=sender_host,
            sender_port=sender_port,
        )
        self._sessions[str(auth_cookie).strip()] = sess
        # Also clean up old sessions (> 10 minutes old)
        now = time.time()
        expired = [k for k, s in self._sessions.items() if now - s.created_at > 600]
        for k in expired:
            self._sessions.pop(k, None)
        logger.info(f"Registered MSNFTP session for {file_name} ({file_size}b) [cookie={auth_cookie}]")
        return sess

    def get_session(self, auth_cookie: str) -> Optional[MSNFTPTransferSession]:
        return self._sessions.get(str(auth_cookie).strip())

    async def start(self) -> None:
        self._running = True
        try:
            self._server = await asyncio.start_server(
                self._handle_connection, self.bind_host, self.port
            )
            logger.info(f"MSNFTP Relay / File Server listening on {self.bind_host}:{self.port} (Public: {self.external_host}:{self.port})")
        except Exception as ex:
            logger.warning(f"Could not bind MSNFTP Server on port {self.port}: {ex}")

    async def stop(self) -> None:
        self._running = False
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            logger.info("MSNFTP Relay Server stopped.")

    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peername = writer.get_extra_info("peername") or ("0.0.0.0", 0)
        logger.debug(f"MSNFTP connection accepted from {peername}")
        try:
            # 1. Receiver sends: VER MSNFTP\r\n
            line1 = await asyncio.wait_for(reader.readline(), timeout=15.0)
            if not line1:
                writer.close()
                return

            cmd_line1 = line1.decode("ascii", errors="replace").strip()
            parts1 = cmd_line1.split()
            if not parts1 or parts1[0].upper() != "VER":
                writer.close()
                return

            # Reply: VER MSNFTP\r\n
            writer.write(b"VER MSNFTP\r\n")
            await writer.drain()

            # 2. Receiver sends: USR <user_email> <auth_cookie>\r\n
            line2 = await asyncio.wait_for(reader.readline(), timeout=15.0)
            if not line2:
                writer.close()
                return

            cmd_line2 = line2.decode("utf-8", errors="replace").strip()
            parts2 = cmd_line2.split()
            if len(parts2) < 3 or parts2[0].upper() != "USR":
                writer.close()
                return

            client_email = parts2[1].strip().lower()
            auth_cookie = parts2[2].strip()

            sess = self.get_session(auth_cookie)
            if not sess:
                logger.warning(f"MSNFTP session not found for auth cookie: {auth_cookie}")
                writer.close()
                return

            # Check if this is a Server-Sent File (e.g. Bot or HTTP upload sent to user)
            if sess.file_path and os.path.exists(sess.file_path):
                await self._serve_local_file(reader, writer, sess)
            elif sess.sender_host and sess.sender_port:
                # Relay between Receiver and Sender's listening socket
                await self._relay_to_sender(reader, writer, sess)
            else:
                logger.warning(f"MSNFTP session {sess.session_id} has neither local file nor sender endpoint.")
                writer.close()

        except asyncio.TimeoutError:
            logger.debug(f"MSNFTP connection timeout from {peername}")
        except Exception as ex:
            logger.warning(f"Error in MSNFTP connection from {peername}: {ex}")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _serve_local_file(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                                sess: MSNFTPTransferSession) -> None:
        """Sends a local file to the receiver over MSNFTP."""
        file_size = os.path.getsize(sess.file_path)
        logger.info(f"Serving file '{sess.file_name}' ({file_size}b) via MSNFTP to {sess.receiver_email}")

        # 3. Server sends: FIL <filesize>\r\n
        writer.write(f"FIL {file_size}\r\n".encode("ascii"))
        await writer.drain()

        # 4. Receiver sends: TFR\r\n
        line3 = await asyncio.wait_for(reader.readline(), timeout=15.0)
        if not line3:
            return
        cmd_line3 = line3.decode("ascii", errors="replace").strip()
        if not cmd_line3.startswith("TFR"):
            return

        # 5. Stream binary blocks: 3-byte header [flag: 1 byte, length: 2 bytes little-endian] + chunk
        chunk_size = 2045  # 2045 + 3 = 2048 total per packet
        bytes_sent = 0

        with open(sess.file_path, "rb") as f:
            while bytes_sent < file_size:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                bytes_sent += len(chunk)
                is_last = (bytes_sent >= file_size)
                flag = 1 if is_last else 0
                header = struct.pack("<BH", flag, len(chunk))
                writer.write(header + chunk)
                # Avoid flooding socket buffer on large files
                if bytes_sent % (chunk_size * 16) == 0:
                    await writer.drain()

        await writer.drain()
        sess.completed = True
        logger.info(f"MSNFTP transfer completed for '{sess.file_name}' to {sess.receiver_email} ({bytes_sent} bytes sent)")

    async def _relay_to_sender(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                               sess: MSNFTPTransferSession) -> None:
        """Relays MSNFTP stream from Receiver to Sender's listening socket."""
        logger.info(f"Relaying MSNFTP between {sess.receiver_email} and sender at {sess.sender_host}:{sess.sender_port}")
        try:
            sender_reader, sender_writer = await asyncio.open_connection(sess.sender_host, sess.sender_port)
        except Exception as ex:
            logger.warning(f"Could not connect to MSNFTP sender {sess.sender_host}:{sess.sender_port}: {ex}")
            writer.close()
            return

        try:
            # Send VER to sender and consume sender's VER response so receiver does not get a duplicate
            sender_writer.write(b"VER MSNFTP\r\n")
            await sender_writer.drain()
            try:
                sender_ver = await asyncio.wait_for(sender_reader.readline(), timeout=10.0)
                logger.debug(f"Sender VER response: {sender_ver.strip() if sender_ver else b''}")
            except Exception as ex:
                logger.warning(f"Timeout waiting for sender VER response: {ex}")

            # Send USR to sender
            sender_writer.write(f"USR {sess.receiver_email} {sess.auth_cookie}\r\n".encode("utf-8"))
            await sender_writer.drain()

            # Bidirectional pipe
            async def forward(src: asyncio.StreamReader, dst: asyncio.StreamWriter):
                try:
                    while True:
                        buf = await src.read(4096)
                        if not buf:
                            break
                        dst.write(buf)
                        await dst.drain()
                except Exception:
                    pass
                finally:
                    try:
                        dst.close()
                    except Exception:
                        pass

            await asyncio.gather(
                forward(reader, sender_writer),
                forward(sender_reader, writer),
                return_exceptions=True
            )
            sess.completed = True
            logger.info(f"MSNFTP relay finished for {sess.session_id}")
        finally:
            try:
                sender_writer.close()
                await sender_writer.wait_closed()
            except Exception:
                pass

    async def receive_file_from_sender(self, sender_host: str, sender_port: int,
                                        auth_cookie: str, receiver_email: str,
                                        file_name: str, file_size: int,
                                        timeout: float = 30.0) -> Optional[bytes]:
        """
        Connects as an MSNFTP client directly to an MSNFTP sender (e.g. Trillian),
        completes the protocol handshake, downloads the file data, and returns the raw bytes.
        """
        logger.info(f"Connecting to MSNFTP sender at {sender_host}:{sender_port} for file '{file_name}' ({file_size}b)...")
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(sender_host, sender_port),
                timeout=10.0
            )
        except Exception as ex:
            logger.warning(f"Could not connect to MSNFTP sender {sender_host}:{sender_port}: {ex}")
            return None

        try:
            # 1. Send: VER MSNFTP\r\n
            writer.write(b"VER MSNFTP\r\n")
            await writer.drain()
            ver_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not ver_line or not ver_line.strip().startswith(b"VER"):
                logger.warning(f"Unexpected VER response from MSNFTP sender: {ver_line}")
                writer.close()
                return None

            # 2. Send: USR <receiver_email> <auth_cookie>\r\n
            writer.write(f"USR {receiver_email} {auth_cookie}\r\n".encode("utf-8"))
            await writer.drain()
            fil_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not fil_line or not fil_line.strip().startswith(b"FIL"):
                logger.warning(f"Unexpected FIL response from MSNFTP sender: {fil_line}")
                writer.close()
                return None

            fil_parts = fil_line.decode("ascii", errors="replace").strip().split()
            actual_size = int(fil_parts[1]) if len(fil_parts) > 1 and fil_parts[1].isdigit() else file_size

            # 3. Send: TFR\r\n
            writer.write(b"TFR\r\n")
            await writer.drain()

            # 4. Read binary blocks: 3-byte header [flag: 1 byte, chunk_len: 2 bytes little-endian] + chunk
            received_data = bytearray()
            while len(received_data) < actual_size:
                hdr = await asyncio.wait_for(reader.readexactly(3), timeout=timeout)
                is_last, chunk_len = struct.unpack("<BH", hdr)
                chunk = await asyncio.wait_for(reader.readexactly(chunk_len), timeout=timeout)
                received_data.extend(chunk)
                if is_last:
                    break

            # 5. Send BYE to finish gracefully
            try:
                writer.write(b"BYE 16777989\r\n")
                await writer.drain()
            except Exception:
                pass

            writer.close()
            await writer.wait_closed()
            logger.info(f"Successfully received {len(received_data)} bytes of '{file_name}' from MSNFTP sender.")
            return bytes(received_data)

        except Exception as ex:
            logger.warning(f"Error receiving file from MSNFTP sender {sender_host}:{sender_port}: {ex}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return None

