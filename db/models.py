"""
Data models for MSNP entities stored in database.db
"""
from dataclasses import dataclass
from typing import Optional


@dataclass
class UserRecord:
    email: str
    password: str
    friendly_name: str
    status: str = "FLN"
    client_id: str = "0"
    custom_message: str = ""
    msn_obj: str = ""
    phone_home: str = ""
    phone_work: str = ""
    phone_mobile: str = ""
    created_at: str = ""
    last_seen: str = ""


@dataclass
class ContactRecord:
    user_email: str
    contact_email: str
    list_flags: int = 1  # 1=FL, 2=AL, 4=BL, 8=RL, 16=PL
    group_id: int = 0
    friendly_name: str = ""
    created_at: str = ""


@dataclass
class GroupRecord:
    id: int
    user_email: str
    name: str


@dataclass
class OfflineMessageRecord:
    id: int
    sender: str
    recipient: str
    message: str
    timestamp: str
    delivered: int = 0
