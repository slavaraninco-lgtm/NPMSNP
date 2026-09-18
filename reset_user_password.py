"""
CLI tool to manage and reset user passwords in database.db.
Usage:
  python reset_user_password.py <email> <new_password>
  python reset_user_password.py --list
"""
import argparse
import os
import sys

# Ensure UTF-8 output on Windows console
if sys.platform == "win32":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import config
from db.database import Database
from db.security import is_encrypted


def main():
    parser = argparse.ArgumentParser(description="NPMSNP - User Password Manager")
    parser.add_argument("email", nargs="?", default="", help="User email address")
    parser.add_argument("password", nargs="?", default="", help="New plaintext password")
    parser.add_argument("--list", action="store_true", help="List all users and password status")
    parser.add_argument("--db", default=config.DB_PATH, help="Path to database.db")

    args = parser.parse_args()

    db_path = os.path.abspath(args.db)
    if not os.path.exists(db_path):
        print(f"[ERROR] Database file not found at: {db_path}")
        sys.exit(1)

    # Check cryptography availability
    try:
        import cryptography
        crypto_ok = True
    except ImportError:
        crypto_ok = False
        print("[WARNING] 'cryptography' library is NOT installed!")
        print("          Run 'pip install cryptography' to properly decrypt stored passwords.\n")

    db = Database(db_path)

    if args.list:
        users = db.get_all_users()
        print(f"\nRegistered users in {db_path} ({len(users)} total):")
        print("-" * 75)
        print(f"{'Email':<30} | {'Friendly Name':<20} | {'Password'}")
        print("-" * 75)
        for u in users:
            pwd_disp = u.password
            if pwd_disp.startswith("enc:"):
                pwd_disp = "<ENCRYPTED - pip install cryptography required>"
            print(f"{u.email:<30} | {u.friendly_name:<20} | {pwd_disp}")
        print("-" * 75)
        print()
        return

    if not args.email:
        parser.print_help()
        return

    email = args.email.strip()
    if "@" not in email:
        print(f"[ERROR] Invalid email: {email}")
        sys.exit(1)

    new_password = args.password
    if not new_password:
        import getpass
        new_password = getpass.getpass(f"Enter new password for {email}: ")

    if not new_password:
        print("[ERROR] Password cannot be empty.")
        sys.exit(1)

    user = db.get_user(email)
    if not user:
        print(f"[INFO] User {email} not found. Creating new user...")
        db.create_user(email, new_password)
        print(f"[OK] User {email} created successfully with password '{new_password}'.")
    else:
        # Update existing user password
        from db.security import encrypt_password
        enc_pwd = encrypt_password(new_password, db.secret_key)
        with db._lock:
            with db._connection() as conn:
                conn.execute("UPDATE users SET password = ? WHERE email = ?;", (enc_pwd, email))
                conn.commit()
        print(f"[OK] Password for {email} updated successfully to '{new_password}'.")


if __name__ == "__main__":
    main()
