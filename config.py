"""
MSNP Server Configuration
"""
import os

# Server binding
BIND_HOST = os.getenv("MSNP_BIND_HOST", "0.0.0.0")

# External host/IP reported to clients in XFR / RNG commands
# For local testing, 127.0.0.1. Change to LAN IP or public domain if connecting across network.
EXTERNAL_HOST = os.getenv("MSNP_EXTERNAL_HOST", "127.0.0.1")

# Ports
NS_PORT = int(os.getenv("MSNP_NS_PORT", "1863"))          # Notification / Dispatch Server
SB_PORT = int(os.getenv("MSNP_SB_PORT", "1864"))          # Switchboard Server (Chats)
HTTP_PORT = int(os.getenv("MSNP_HTTP_PORT", "1865"))      # HTTP Nexus, Tweener & Web Admin

# Database file path (required: database.db in project root)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
# Secret key used to encrypt passwords stored in database.db and admin credentials
DB_SECRET_KEY = os.getenv("MSNP_DB_SECRET_KEY", "msnp_server_default_master_salt_key_2026")

# Administrator credentials for Web Admin Dashboard and Admin API
# The password is encrypted using DB_SECRET_KEY (default plaintext: admin123)
# To generate a new encrypted password, run: python generate_admin_password.py
ADMIN_PASSWORD = os.getenv(
    "MSNP_ADMIN_PASSWORD",
    "enc:v1:gAAAAABqrGOFz73J-WDRDYZdK2mk8lVVVicqvqxuIceBUQK-_J_kfnmUtnWN3fdrSS8cXj5gopHxwW8V6Bi2dupcwhkW2ibZew=="
)

# Server Identification
SERVER_NAME = "Python MSNP Server"
SERVER_VERSION = "1.0.0"
DEFAULT_DOMAIN = "msn.local"

# Security & Behavior
AUTO_REGISTER_UNKNOWN_USERS = True  # If True, unknown user will be auto-created on first valid login
DEFAULT_USER_FRIENDLY_NAME_SUFFIX = ""
SESSION_TIMEOUT_SECONDS = 300       # Keep-alive timeout
SB_AUTH_TIMEOUT_SECONDS = 60        # Switchboard join ticket expiration

# Authentication preferences
# When BYPASS_PASSPORT_FOR_TWN is True (recommended), if a client (such as Gaim/Pidgin or MSN Messenger)
# sends "USR trid TWN I email", the server immediately authenticates the user with "USR trid OK ...".
# This completely prevents clients from freezing when attempting to contact Microsoft's dead nexus.passport.com:443 HTTPS.
BYPASS_PASSPORT_FOR_TWN = True
PREFER_MD5_AUTH = False

# Service Account for System Alerts, Bans & Maintenance
SERVICE_ACCOUNT_EMAIL = os.getenv("MSNP_SERVICE_EMAIL", "system@msn.local")
SERVICE_ACCOUNT_NAME = os.getenv("MSNP_SERVICE_NAME", "Служба сообщений MSN")
AUTO_ADD_SERVICE_CONTACT = os.getenv("MSNP_AUTO_ADD_SERVICE_CONTACT", "true").lower() in ("true", "1", "yes")

# File Transfer & Storage Configuration
MSNFTP_PORT = int(os.getenv("MSNP_MSNFTP_PORT", "1866"))      # MSNFTP Relay / Bridge port
FILES_STORAGE_DIR = os.getenv("MSNP_FILES_DIR", os.path.join(BASE_DIR, "storage", "files"))
MAX_FILE_SIZE_MB = int(os.getenv("MSNP_MAX_FILE_SIZE_MB", "100"))
ENABLE_MSNFTP_NAT_REWRITE = os.getenv("MSNP_ENABLE_MSNFTP_NAT_REWRITE", "true").lower() in ("true", "1", "yes")

