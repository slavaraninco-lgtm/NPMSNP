"""
MSNP Server - Main Entry Point.
Starts:
1. Notification Server (NS) on port 1863
2. Switchboard Server (SB) on port 1864
3. HTTP Passport / Nexus & Web Dashboard on port 1865
Uses SQLite database at database.db.
"""
import argparse
import asyncio
import logging
import signal
import sys
import os

import config
from db.database import Database
from protocol.auth import AuthManager
from protocol.ns_handler import NSClientHandler
from protocol.sb_handler import SBClientHandler
from services.session_manager import SessionManager
from services.switchboard_manager import SwitchboardManager
from services.http_server import HTTPServer


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    log_format = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
    logging.basicConfig(level=level, format=log_format, datefmt="%Y-%m-%d %H:%M:%S")


class MSNPServer:
    def __init__(self, bind_host: str = config.BIND_HOST, external_host: str = config.EXTERNAL_HOST,
                 ns_port: int = config.NS_PORT, sb_port: int = config.SB_PORT,
                 http_port: int = config.HTTP_PORT, db_path: str = config.DB_PATH):
        self.bind_host = bind_host
        self.external_host = external_host
        self.ns_port = ns_port
        self.sb_port = sb_port
        self.http_port = http_port
        self.db_path = db_path

        # Core Components
        self.db = Database(self.db_path)
        self.auth_manager = AuthManager()
        self.session_manager = SessionManager(self.db)
        self.switchboard_manager = SwitchboardManager(self.auth_manager)
        self.db.ensure_service_account(config.SERVICE_ACCOUNT_EMAIL, config.SERVICE_ACCOUNT_NAME)
        self.http_server = HTTPServer(
            host=self.bind_host,
            port=self.http_port,
            external_host=self.external_host,
            db=self.db,
            auth_manager=self.auth_manager,
            session_manager=self.session_manager,
            switchboard_manager=self.switchboard_manager,
            auto_register=config.AUTO_REGISTER_UNKNOWN_USERS
        )

        self._ns_server = None
        self._sb_server = None
        self._running = False

    async def _handle_ns_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        handler = NSClientHandler(
            reader=reader,
            writer=writer,
            db=self.db,
            auth_manager=self.auth_manager,
            session_manager=self.session_manager,
            switchboard_manager=self.switchboard_manager,
            external_host=self.external_host,
            ns_port=self.ns_port,
            sb_port=self.sb_port,
            http_port=self.http_port,
        )
        await handler.run()

    async def _handle_sb_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        handler = SBClientHandler(
            reader=reader,
            writer=writer,
            db=self.db,
            auth_manager=self.auth_manager,
            session_manager=self.session_manager,
            switchboard_manager=self.switchboard_manager,
            external_host=self.external_host,
            sb_port=self.sb_port,
        )
        await handler.run()

    async def start(self) -> None:
        self._running = True

        # Start Notification Server
        self._ns_server = await asyncio.start_server(
            self._handle_ns_connection, self.bind_host, self.ns_port
        )
        logging.info(f"Notification Server (NS) listening on {self.bind_host}:{self.ns_port}")

        # Start Switchboard Server
        self._sb_server = await asyncio.start_server(
            self._handle_sb_connection, self.bind_host, self.sb_port
        )
        logging.info(f"Switchboard Server (SB) listening on {self.bind_host}:{self.sb_port}")

        # Start HTTP / Nexus / Web Admin Server
        await self.http_server.start()

        print("\n" + "=" * 65)
        print(f"  {config.SERVER_NAME} v{config.SERVER_VERSION} RUNNING")
        print("=" * 65)
        print(f"  * Notification Server (NS): {self.external_host}:{self.ns_port}")
        print(f"  * Switchboard Server  (SB): {self.external_host}:{self.sb_port}")
        print(f"  * Web Dashboard / HTTP    : http://{self.external_host}:{self.http_port}/")
        print(f"  * SQLite Database         : {os.path.abspath(self.db_path)}")
        print("=" * 65 + "\n")

        # Keep server running
        while self._running:
            await asyncio.sleep(1)

    async def stop(self) -> None:
        logging.info("Stopping MSNP Server...")
        self._running = False

        if self._ns_server:
            self._ns_server.close()
            await self._ns_server.wait_closed()

        if self._sb_server:
            self._sb_server.close()
            await self._sb_server.wait_closed()

        await self.http_server.stop()
        logging.info("MSNP Server stopped successfully.")


def main() -> None:
    parser = argparse.ArgumentParser(description="MSNP Server (MSN Messenger Protocol)")
    parser.add_argument("--host", default=config.BIND_HOST, help="Bind host IP")
    parser.add_argument("--external-host", default=config.EXTERNAL_HOST, help="Reported public/LAN host IP")
    parser.add_argument("--ns-port", type=int, default=config.NS_PORT, help="Notification Server port")
    parser.add_argument("--sb-port", type=int, default=config.SB_PORT, help="Switchboard Server port")
    parser.add_argument("--http-port", type=int, default=config.HTTP_PORT, help="HTTP/Web Dashboard port")
    parser.add_argument("--db", default=config.DB_PATH, help="Path to database.db")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")

    args = parser.parse_args()
    setup_logging(args.debug)

    server = MSNPServer(
        bind_host=args.host,
        external_host=args.external_host,
        ns_port=args.ns_port,
        sb_port=args.sb_port,
        http_port=args.http_port,
        db_path=args.db,
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Signal handlers (for graceful shutdown)
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: asyncio.create_task(server.stop()))
        except (NotImplementedError, RuntimeError):
            # Windows may not support add_signal_handler in all loop policies
            pass

    try:
        loop.run_until_complete(server.start())
    except (KeyboardInterrupt, SystemExit):
        logging.info("Received interrupt signal, stopping...")
        loop.run_until_complete(server.stop())
    finally:
        loop.close()


if __name__ == "__main__":
    main()
