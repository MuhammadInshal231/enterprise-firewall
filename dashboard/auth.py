import hashlib
import hmac
import os
import secrets
import sqlite3
import threading
import time

class AuthManager:
    def __init__(self, db_path=None):
        if db_path is None:
            base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            self.db_path = os.path.normpath(os.path.join(base_dir, "firewall.db"))
        else:
            self.db_path = os.path.normpath(os.path.abspath(db_path))
        self.lock = threading.Lock()
        self._init_tables()

    def _get_connection(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=15.0)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS users ("
                    "username TEXT PRIMARY KEY, "
                    "salt TEXT NOT NULL, "
                    "password_hash TEXT NOT NULL, "
                    "role TEXT CHECK(role IN ('ADMIN', 'AUDITOR')) NOT NULL"
                    ");"
                )
                cursor.execute(
                    "CREATE TABLE IF NOT EXISTS sessions ("
                    "token TEXT PRIMARY KEY, "
                    "username TEXT NOT NULL, "
                    "role TEXT NOT NULL, "
                    "created_at REAL NOT NULL, "
                    "expires_at REAL NOT NULL"
                    ");"
                )
                conn.commit()
                cursor.execute("SELECT COUNT(*) AS count FROM users;")
                if cursor.fetchone()["count"] == 0:
                    self._create_user_internal(cursor, "admin", "admin123", "ADMIN")
                    self._create_user_internal(cursor, "auditor", "auditor123", "AUDITOR")
                    conn.commit()
            finally:
                conn.close()

    def _create_user_internal(self, cursor, username, password, role):
        salt_hex, hash_hex = self.hash_password(password)
        cursor.execute(
            "INSERT INTO users (username, salt, password_hash, role) VALUES (?, ?, ?, ?);",
            (username, salt_hex, hash_hex, role)
        )

    @staticmethod
    def hash_password(password, salt=None):
        if salt is None:
            salt_bytes = secrets.token_bytes(16)
        elif isinstance(salt, str):
            salt_bytes = bytes.fromhex(salt)
        else:
            salt_bytes = salt
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 100000)
        return salt_bytes.hex(), derived.hex()

    @staticmethod
    def verify_password(password, salt_hex, hash_hex):
        salt_bytes = bytes.fromhex(salt_hex)
        derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 100000)
        return hmac.compare_digest(derived.hex(), hash_hex)

    def authenticate(self, username, password):
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT salt, password_hash, role FROM users WHERE username = ?;", (username,))
                row = cursor.fetchone()
                if not row:
                    return None, None
                salt_hex = row["salt"]
                hash_hex = row["password_hash"]
                role = row["role"]
                if self.verify_password(password, salt_hex, hash_hex):
                    token = secrets.token_hex(32)
                    created_at = time.time()
                    expires_at = created_at + 86400.0
                    cursor.execute(
                        "INSERT INTO sessions (token, username, role, created_at, expires_at) VALUES (?, ?, ?, ?, ?);",
                        (token, username, role, created_at, expires_at)
                    )
                    conn.commit()
                    return token, role
                return None, None
            finally:
                conn.close()

    def validate_session(self, token):
        if not token:
            return False, None, None
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("SELECT username, role, expires_at FROM sessions WHERE token = ?;", (token,))
                row = cursor.fetchone()
                if not row:
                    return False, None, None
                if row["expires_at"] < time.time():
                    cursor.execute("DELETE FROM sessions WHERE token = ?;", (token,))
                    conn.commit()
                    return False, None, None
                return True, row["username"], row["role"]
            finally:
                conn.close()

    def revoke_session(self, token):
        if not token:
            return
        with self.lock:
            conn = self._get_connection()
            try:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM sessions WHERE token = ?;", (token,))
                conn.commit()
            finally:
                conn.close()

    @staticmethod
    def is_authorized(user_role, required_role):
        if not user_role:
            return False
        if required_role == "AUDITOR":
            return user_role in ("ADMIN", "AUDITOR")
        if required_role == "ADMIN":
            return user_role == "ADMIN"
        return False

