"""
Unit tests for password encryption, decryption, SQLite storage, and automatic migration.
"""
import os
import sqlite3
import tempfile
import unittest

from db.database import Database
from db.security import encrypt_password, decrypt_password, is_encrypted, _fallback_encrypt, _fallback_decrypt


class TestPasswordSecurity(unittest.TestCase):
    def setUp(self):
        self.secret = "test_super_secret_key_12345"
        self.temp_db_fd, self.temp_db_path = tempfile.mkstemp(suffix=".db")
        os.close(self.temp_db_fd)

    def tearDown(self):
        if os.path.exists(self.temp_db_path):
            try:
                os.remove(self.temp_db_path)
            except Exception:
                pass

    def test_encrypt_decrypt_roundtrip(self):
        plain = "MySecretP@ssw0rd!123"
        enc = encrypt_password(plain, self.secret)
        self.assertTrue(is_encrypted(enc))
        self.assertTrue(enc.startswith("enc:v1:"))
        self.assertNotIn(plain, enc)

        dec = decrypt_password(enc, self.secret)
        self.assertEqual(dec, plain)

    def test_encrypt_idempotency(self):
        plain = "Pass1234"
        enc1 = encrypt_password(plain, self.secret)
        enc2 = encrypt_password(enc1, self.secret)
        self.assertEqual(enc1, enc2)

    def test_decrypt_legacy_plaintext(self):
        plain = "old_unencrypted_pass"
        dec = decrypt_password(plain, self.secret)
        self.assertEqual(dec, plain)

    def test_fallback_encryption(self):
        plain = "FallbackSecretTest987"
        token = _fallback_encrypt(plain, self.secret)
        self.assertNotIn(plain, token)
        dec = _fallback_decrypt(token, self.secret)
        self.assertEqual(dec, plain)

    def test_sqlite_storage_is_encrypted(self):
        db = Database(self.temp_db_path, secret_key=self.secret)
        raw_pass = "user_plain_password_xyz"
        db.create_user("user1@msn.local", raw_pass, "User 1")

        # 1. Check raw SQLite database content
        conn = sqlite3.connect(self.temp_db_path)
        row = conn.execute("SELECT password FROM users WHERE email = 'user1@msn.local'").fetchone()
        conn.close()
        self.assertIsNotNone(row)
        stored_password = row[0]

        # Must NOT be stored in plaintext
        self.assertNotEqual(stored_password, raw_pass)
        self.assertTrue(stored_password.startswith("enc:v1:"))
        self.assertNotIn(raw_pass, stored_password)

        # 2. Check Database.get_user returns decrypted password
        user = db.get_user("user1@msn.local")
        self.assertIsNotNone(user)
        self.assertEqual(user.password, raw_pass)

        # 3. Check Database.update_password
        new_pass = "new_updated_secret_321"
        db.update_password("user1@msn.local", new_pass)

        conn = sqlite3.connect(self.temp_db_path)
        row2 = conn.execute("SELECT password FROM users WHERE email = 'user1@msn.local'").fetchone()
        conn.close()
        self.assertTrue(row2[0].startswith("enc:v1:"))
        self.assertNotIn(new_pass, row2[0])

        user_updated = db.get_user("user1@msn.local")
        self.assertEqual(user_updated.password, new_pass)

    def test_automatic_migration_of_plaintext_passwords(self):
        # 1. Initialize schema
        db = Database(self.temp_db_path, secret_key=self.secret)

        # 2. Inject raw unencrypted plaintext passwords directly into SQLite
        conn = sqlite3.connect(self.temp_db_path)
        conn.execute("INSERT OR REPLACE INTO users (email, password, friendly_name) VALUES (?, ?, ?);",
                     ("legacy1@msn.local", "plain_legacy_111", "Legacy 1"))
        conn.execute("INSERT OR REPLACE INTO users (email, password, friendly_name) VALUES (?, ?, ?);",
                     ("legacy2@msn.local", "plain_legacy_222", "Legacy 2"))
        conn.commit()
        conn.close()

        # Verify they are currently plaintext
        conn = sqlite3.connect(self.temp_db_path)
        rows = conn.execute("SELECT email, password FROM users WHERE email LIKE 'legacy%'").fetchall()
        conn.close()
        self.assertEqual(rows[0][1], "plain_legacy_111")
        self.assertEqual(rows[1][1], "plain_legacy_222")

        # 3. Re-open database with Database class (triggers _migrate_plain_passwords)
        db2 = Database(self.temp_db_path, secret_key=self.secret)

        # 4. Verify SQLite disk storage is now encrypted
        conn = sqlite3.connect(self.temp_db_path)
        rows_migrated = conn.execute("SELECT email, password FROM users WHERE email LIKE 'legacy%'").fetchall()
        conn.close()

        for r in rows_migrated:
            self.assertTrue(r[1].startswith("enc:v1:"), f"Password for {r[0]} was not encrypted: {r[1]}")
            self.assertNotIn("plain_legacy", r[1])

        # 5. Verify get_user returns transparently decrypted passwords
        u1 = db2.get_user("legacy1@msn.local")
        u2 = db2.get_user("legacy2@msn.local")
        self.assertEqual(u1.password, "plain_legacy_111")
        self.assertEqual(u2.password, "plain_legacy_222")


if __name__ == "__main__":
    unittest.main()
