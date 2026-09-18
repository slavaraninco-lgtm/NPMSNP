"""
Constants for MSNP (Microsoft Notification Protocol)
"""
from enum import Enum, IntFlag


class ProtocolVersion(str, Enum):
    MSNP2 = "MSNP2"
    MSNP3 = "MSNP3"
    MSNP4 = "MSNP4"
    MSNP5 = "MSNP5"
    MSNP6 = "MSNP6"
    MSNP7 = "MSNP7"
    MSNP8 = "MSNP8"
    MSNP9 = "MSNP9"
    MSNP10 = "MSNP10"
    MSNP11 = "MSNP11"
    MSNP12 = "MSNP12"


SUPPORTED_DIALECTS = [
    "MSNP9", "MSNP8", "MSNP10", "MSNP11", "MSNP12",
    "MSNP7", "MSNP6", "MSNP5", "MSNP4", "MSNP3", "MSNP2"
]


class ListMask(IntFlag):
    FL = 1   # Forward List (Buddies)
    AL = 2   # Allow List (Allowed to see presence)
    BL = 4   # Block List (Blocked)
    RL = 8   # Reverse List (Who has you on their list)
    PL = 16  # Pending List (Users requesting authorization)


class UserStatus(str, Enum):
    ONLINE = "NLN"     # Available
    BUSY = "BSY"       # Busy
    IDLE = "IDL"       # Idle
    BRB = "BRB"        # Be Right Back
    AWAY = "AWY"       # Away
    PHONE = "PHN"      # On The Phone
    LUNCH = "LUN"      # Out To Lunch
    HIDDEN = "HDN"     # Appear Offline
    OFFLINE = "FLN"    # Offline

    def __str__(self) -> str:
        return self.value


# MSNP Numeric Error Codes
class MSNPError:
    SYNTAX_ERROR = 200
    INVALID_PARAMETER = 201
    INVALID_USER = 205
    DOMAIN_NOT_FOUND = 206
    ALREADY_LOGGED_IN = 207
    INVALID_USERNAME = 208
    INVALID_FULLNAME = 209
    USER_ALREADY_THERE = 210
    ALREADY_ON_LIST = 215
    NOT_ON_LIST = 216
    NOT_IN_GROUP = 218
    GROUP_ALREADY_EXISTS = 219
    PRINCIPAL_NOT_ONLINE = 217
    SWITCHBOARD_FAILED = 280
    TRANSFER_FAILED = 281
    INTERNAL_SERVER_ERROR = 500
    DATABASE_SERVER_ERROR = 501
    SERVER_IS_FULL = 510
    SERVER_CONNECTING = 520
    SERVER_BAD_REQUEST = 540
    BAD_CHALLENGE_RESPONSE = 541
    CONNECTION_CLOSING = 600
    BAD_FRIEND_NAME = 601
    NOT_ALLOWED_WHILE_HDN = 602
    NOT_EXPECTED = 700
    NOT_ALLOWED = 700
    BAD_PASSPORT = 710
    WRITE_DATA_FAILED = 711
    SERVER_TOO_BUSY = 712
    CALLING_TOO_RAPIDLY = 713
    USER_NOT_ONLINE = 715
    CHANGING_NAME_TOO_FAST = 800
    AUTH_FAILED = 911
    SERVER_NOT_AVAILABLE = 924


# Commands whose last argument is the byte length of a following payload
PAYLOAD_COMMANDS = {
    "MSG", "NOT", "UUX", "ADL", "RML", "SDG", "SDC", "PUT", "QRY", "UUN", "UUM", "VAS"
}
