"""
MSNP packet framing, stream reading, and stream writing.
Handles newline-delimited command lines and binary payload commands.
"""
import re
from typing import List, Tuple, Optional, Any, Iterable
from urllib.parse import quote, unquote

from .constants import PAYLOAD_COMMANDS


def encode_arg(arg: Any, encoding: str = "utf-8") -> str:
    """
    Encodes spaces, non-ASCII characters, and special characters
    for MSNP command line arguments using standard percent-encoding.
    Safe characters include standard ASCII characters used in email addresses,
    URLs, parameters, IPs, etc.
    """
    if arg is None:
        return ""
    s = str(arg)
    # Standard MSNP RFC 1738 percent-encoding for non-ASCII and special characters
    try:
        return quote(s, safe="@/:-_.~,={}+*&!$()#", encoding=encoding)
    except Exception:
        return quote(s, safe="@/:-_.~,={}+*&!$()#", encoding="utf-8")


def decode_arg_bytes(raw: bytes) -> str:
    """
    Decodes an MSNP command argument from raw bytes:
    1. Unquotes percent-encoded %XX sequences at the byte level first.
       This handles:
       - Standard percent-encoded UTF-8 (%D0%9F...)
       - Gaim Windows locale bug (mixed raw UTF-8 lead bytes + %XX continuation bytes)
       - Standard percent-encoded CP1251 (%CF%EE...)
       - Standard ASCII percent-encoding (%20, %25, etc.)
       - Raw bytes without percent-encoding
    2. Decodes the unquoted raw bytes to string:
       - First attempts UTF-8 (strict)
       - If not valid UTF-8, attempts CP1251 (Russian Windows ANSI)
       - Fallback to UTF-8 with errors="replace"
    """
    if not raw:
        return ""
    # Unquote %XX at byte level
    unquoted = re.sub(rb'%([0-9a-fA-F]{2})', lambda m: bytes([int(m.group(1), 16)]), raw)
    try:
        return unquoted.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return unquoted.decode("cp1251")
        except UnicodeDecodeError:
            return unquoted.decode("utf-8", errors="replace")


def decode_arg(arg: Any) -> str:
    """Decodes percent-encoded MSNP command line argument."""
    if isinstance(arg, bytes):
        return decode_arg_bytes(arg)
    if not isinstance(arg, str):
        arg = str(arg)
    if "%" in arg:
        try:
            return decode_arg_bytes(arg.encode("latin-1"))
        except Exception:
            return unquote(arg)
    return arg


class MSNPReader:
    """
    Stateful buffer for reading MSNP commands and payloads from a TCP stream.
    """
    def __init__(self):
        self._buffer = bytearray()

    def feed_data(self, data: bytes) -> List[Tuple[str, List[str], Optional[bytes]]]:
        """
        Feed incoming data chunk and extract all complete MSNP commands.
        Returns list of (command, args, payload)
        """
        self._buffer.extend(data)
        messages = []

        while True:
            # Find newline
            nl_pos = self._buffer.find(b"\n")
            if nl_pos < 0:
                break

            # Extract raw line up to newline
            raw_line = bytes(self._buffer[:nl_pos]).rstrip(b"\r")
            if not raw_line:
                # Empty line, drop it
                self._buffer = self._buffer[nl_pos + 1:]
                continue

            # Split command line by space at byte level to avoid corrupting multi-byte sequences
            raw_parts = raw_line.split(b" ")
            cmd = raw_parts[0].decode("ascii", errors="ignore").upper()
            raw_args = raw_parts[1:]

            # Check if this command expects a payload
            if cmd in PAYLOAD_COMMANDS and raw_args:
                try:
                    payload_len = int(raw_args[-1].decode("ascii", errors="ignore"))
                except ValueError:
                    payload_len = 0

                # Check if buffer has enough bytes for the payload
                total_needed = nl_pos + 1 + payload_len
                if len(self._buffer) < total_needed:
                    # Not all payload bytes received yet; wait for more data
                    break

                # Payload is fully available
                payload = bytes(self._buffer[nl_pos + 1:total_needed])
                args = [decode_arg_bytes(a) for a in raw_args[:-1]]
                self._buffer = self._buffer[total_needed:]
                messages.append((cmd, args, payload))
            else:
                # Normal command without payload
                args = [decode_arg_bytes(a) for a in raw_args]
                self._buffer = self._buffer[nl_pos + 1:]
                messages.append((cmd, args, None))

        return messages


class MSNPWriter:
    """
    Formats MSNP commands into bytes for transmission over a TCP stream.
    """
    @staticmethod
    def format_command(cmd: str, *args: Any, payload: Optional[bytes] = None, encoding: str = "utf-8") -> bytes:
        """
        Builds a single MSNP packet.
        If payload is provided, the payload length is automatically appended as the last argument
        before \r\n, followed by the raw payload bytes.
        """
        cmd = cmd.upper()
        arg_list = [encode_arg(a, encoding=encoding) for a in args if a is not None]

        if payload is not None:
            arg_list.append(str(len(payload)))

        line = f"{cmd} {' '.join(arg_list)}".rstrip() + "\r\n"
        data = bytearray(line.encode("utf-8", errors="replace"))

        if payload is not None:
            data.extend(payload)

        return bytes(data)
