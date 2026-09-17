"""
Authentication helper for MSNP Server.
Supports:
1. MD5 Challenge-Response (MSNP2 - MSNP8)
2. TWN (Tweener / Passport tickets for MSNP8 - MSNP12)
"""
import hashlib
import hmac
import secrets
import time
from typing import Dict, Tuple, Optional


class AuthManager:
    def __init__(self, secret_key: Optional[str] = None):
        self.secret_key = secret_key or secrets.token_hex(16)
        # In-memory challenge storage: email -> (challenge, timestamp)
        self._md5_challenges: Dict[str, Tuple[str, float]] = {}
        # In-memory TWN ticket storage: token -> (email, expiry)
        self._twn_tickets: Dict[str, Tuple[str, float]] = {}
        # Switchboard join cookies: cookie -> (email, session_id, role, expiry)
        self._sb_cookies: Dict[str, Tuple[str, int, str, float]] = {}

    # MD5 Challenge-Response
    def create_md5_challenge(self, email: str) -> str:
        """Generates a random challenge string for MD5 authentication"""
        challenge = str(secrets.randbelow(900000000) + 100000000)
        self._md5_challenges[email.lower()] = (challenge, time.time())
        return challenge

    def verify_md5_response(self, email: str, response_hash: str, actual_password: str) -> bool:
        """
        Validates MD5 response hash: MD5(challenge + password).
        """
        email_key = email.lower()
        if email_key not in self._md5_challenges:
            return False

        challenge, timestamp = self._md5_challenges.pop(email_key)
        # 2-minute challenge timeout
        if time.time() - timestamp > 120:
            return False

        expected = hashlib.md5((challenge + actual_password).encode("utf-8")).hexdigest().lower()
        return response_hash.lower() == expected

    # TWN (Passport / Tweener)
    def create_twn_ticket(self, email: str, lifetime: int = 3600) -> str:
        """
        Creates a Passport ticket for TWN authentication.
        Format: t=TOKEN_STRING
        """
        raw_token = secrets.token_hex(16)
        token_str = f"t={raw_token}"
        expiry = time.time() + lifetime
        self._twn_tickets[token_str] = (email.lower(), expiry)
        self._twn_tickets[raw_token] = (email.lower(), expiry)
        return token_str

    def verify_twn_ticket(self, token: str, expected_email: str) -> bool:
        """
        Validates a TWN ticket string.
        """
        token = token.strip()
        data = self._twn_tickets.get(token)
        if not data:
            # Check without 't=' prefix or with 't=' prefix
            if token.startswith("t="):
                data = self._twn_tickets.get(token[2:])
            else:
                data = self._twn_tickets.get(f"t={token}")

        if not data:
            return False

        email, expiry = data
        if time.time() > expiry:
            return False

        return email == expected_email.lower()

    # Switchboard Cookies (CKI)
    def create_sb_cookie(self, email: str, session_id: int, role: str = "caller", lifetime: int = 120) -> str:
        """
        Creates a Switchboard CKI authorization cookie.
        role: 'caller' or 'callee'
        """
        cookie = secrets.token_hex(12)
        expiry = time.time() + lifetime
        self._sb_cookies[cookie] = (email.lower(), session_id, role, expiry)
        return cookie

    def verify_and_consume_sb_cookie(self, cookie: str, expected_email: str) -> Optional[Tuple[int, str]]:
        """
        Validates and consumes a Switchboard CKI cookie.
        Returns (session_id, role) if valid, or None.
        """
        data = self._sb_cookies.pop(cookie, None)
        if not data:
            return None

        email, session_id, role, expiry = data
        if time.time() > expiry:
            return None

        if email != expected_email.lower():
            return None

        return session_id, role
