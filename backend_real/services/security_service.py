from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import struct
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


class SecurityDataStore:
    def __init__(self, db_path: Optional[str] = None) -> None:
        default_path = Path(__file__).resolve().parents[1] / "security.sqlite3"
        configured = db_path or os.getenv("SECURITY_DB_PATH", str(default_path))
        self._db_path = Path(configured)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS otp_challenges (
                    email TEXT NOT NULL,
                    purpose TEXT NOT NULL,
                    otp_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    max_attempts INTEGER NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(email, purpose)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    token_id TEXT PRIMARY KEY,
                    user_email TEXT NOT NULL,
                    token_hash TEXT NOT NULL,
                    expires_at INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rate_limits (
                    key TEXT PRIMARY KEY,
                    window_start INTEGER NOT NULL,
                    counter INTEGER NOT NULL,
                    blocked_until INTEGER NOT NULL DEFAULT 0
                )
                """
            )

    @staticmethod
    def _now_ts() -> int:
        return int(time.time())

    def put_otp(self, *, email: str, purpose: str, otp_hash: str, salt: str, ttl_seconds: int, max_attempts: int) -> None:
        expires_at = self._now_ts() + ttl_seconds
        with self._conn() as conn:
            conn.execute(
                """
                INSERT INTO otp_challenges(email, purpose, otp_hash, salt, expires_at, max_attempts, attempts)
                VALUES(?, ?, ?, ?, ?, ?, 0)
                ON CONFLICT(email, purpose)
                DO UPDATE SET otp_hash=excluded.otp_hash, salt=excluded.salt, expires_at=excluded.expires_at,
                              max_attempts=excluded.max_attempts, attempts=0
                """,
                (email, purpose, otp_hash, salt, expires_at, max_attempts),
            )

    def get_otp(self, *, email: str, purpose: str) -> Optional[dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT email, purpose, otp_hash, salt, expires_at, max_attempts, attempts FROM otp_challenges WHERE email=? AND purpose=?",
                (email, purpose),
            ).fetchone()
        return dict(row) if row else None

    def increment_otp_attempt(self, *, email: str, purpose: str) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE otp_challenges SET attempts = attempts + 1 WHERE email=? AND purpose=?",
                (email, purpose),
            )

    def delete_otp(self, *, email: str, purpose: str) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM otp_challenges WHERE email=? AND purpose=?", (email, purpose))

    def upsert_rate_limit(self, *, key: str, window_seconds: int, max_attempts: int, block_seconds: int) -> tuple[bool, int]:
        now = self._now_ts()
        with self._conn() as conn:
            row = conn.execute("SELECT key, window_start, counter, blocked_until FROM rate_limits WHERE key=?", (key,)).fetchone()
            if not row:
                conn.execute(
                    "INSERT INTO rate_limits(key, window_start, counter, blocked_until) VALUES(?, ?, 1, 0)",
                    (key, now),
                )
                return True, 0

            window_start = row["window_start"]
            counter = row["counter"]
            blocked_until = row["blocked_until"]

            if blocked_until and now < blocked_until:
                return False, blocked_until - now

            if now - window_start >= window_seconds:
                window_start = now
                counter = 1
            else:
                counter += 1

            if counter > max_attempts:
                blocked_until = now + block_seconds
                conn.execute(
                    "UPDATE rate_limits SET window_start=?, counter=?, blocked_until=? WHERE key=?",
                    (window_start, counter, blocked_until, key),
                )
                return False, block_seconds

            conn.execute(
                "UPDATE rate_limits SET window_start=?, counter=?, blocked_until=0 WHERE key=?",
                (window_start, counter, key),
            )
            return True, 0

    def store_refresh_token(self, *, token_id: str, user_email: str, token_hash: str, ttl_seconds: int) -> None:
        expires_at = self._now_ts() + ttl_seconds
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO refresh_tokens(token_id, user_email, token_hash, expires_at, revoked) VALUES (?, ?, ?, ?, 0)",
                (token_id, user_email, token_hash, expires_at),
            )

    def get_refresh_token(self, token_id: str) -> Optional[dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT token_id, user_email, token_hash, expires_at, revoked FROM refresh_tokens WHERE token_id=?",
                (token_id,),
            ).fetchone()
        return dict(row) if row else None

    def revoke_refresh_token(self, token_id: str) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE refresh_tokens SET revoked=1 WHERE token_id=?", (token_id,))


class PasswordHasher:
    def __init__(self, iterations: int = 310000) -> None:
        self._iterations = iterations

    def hash_password(self, password: str) -> str:
        salt = secrets.token_hex(16)
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), self._iterations)
        return f"pbkdf2_sha256${self._iterations}${salt}${base64.urlsafe_b64encode(digest).decode('utf-8')}"

    def verify_password(self, password: str, password_hash: str) -> bool:
        try:
            algo, iter_raw, salt, expected = password_hash.split("$", 3)
            if algo != "pbkdf2_sha256":
                return False
            iterations = int(iter_raw)
        except ValueError:
            return False
        digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
        encoded = base64.urlsafe_b64encode(digest).decode("utf-8")
        return hmac.compare_digest(encoded, expected)


class OTPService:
    def __init__(self, store: SecurityDataStore, secret_key: Optional[str] = None) -> None:
        self._store = store
        self._secret_key = (secret_key or os.getenv("OTP_PEPPER", "change-me-otp-pepper")).encode("utf-8")

    def _hash_otp(self, otp: str, salt: str) -> str:
        return hmac.new(self._secret_key, f"{salt}:{otp}".encode("utf-8"), hashlib.sha256).hexdigest()

    def create(self, *, email: str, purpose: str, ttl_seconds: int = 300, max_attempts: int = 5) -> str:
        otp = f"{secrets.randbelow(1_000_000):06d}"
        salt = secrets.token_hex(16)
        otp_hash = self._hash_otp(otp, salt)
        self._store.put_otp(email=email, purpose=purpose, otp_hash=otp_hash, salt=salt, ttl_seconds=ttl_seconds, max_attempts=max_attempts)
        return otp

    def verify(self, *, email: str, purpose: str, otp: str) -> tuple[bool, str]:
        record = self._store.get_otp(email=email, purpose=purpose)
        if not record:
            return False, "No hay OTP pendiente"
        if int(time.time()) > int(record["expires_at"]):
            self._store.delete_otp(email=email, purpose=purpose)
            return False, "OTP expirado"
        computed = self._hash_otp(otp, record["salt"])
        if not hmac.compare_digest(computed, record["otp_hash"]):
            self._store.increment_otp_attempt(email=email, purpose=purpose)
            refreshed = self._store.get_otp(email=email, purpose=purpose)
            if refreshed and int(refreshed["attempts"]) >= int(refreshed["max_attempts"]):
                self._store.delete_otp(email=email, purpose=purpose)
                return False, "OTP inválido: demasiados intentos"
            return False, "OTP inválido"
        self._store.delete_otp(email=email, purpose=purpose)
        return True, "OK"

    def clear(self, *, email: str, purpose: str) -> None:
        self._store.delete_otp(email=email, purpose=purpose)


class RateLimiter:
    def __init__(self, store: SecurityDataStore) -> None:
        self._store = store

    def check(self, *, action: str, key: str, window_seconds: int, max_attempts: int, block_seconds: int) -> tuple[bool, int]:
        return self._store.upsert_rate_limit(
            key=f"{action}:{key}",
            window_seconds=window_seconds,
            max_attempts=max_attempts,
            block_seconds=block_seconds,
        )


@dataclass
class AccessTokenPayload:
    sub: str
    exp: int
    iat: int
    jti: str


class TokenService:
    def __init__(self, store: SecurityDataStore, secret: Optional[str] = None) -> None:
        self._store = store
        self._secret = (secret or os.getenv("JWT_SECRET", "change-me-jwt-secret")).encode("utf-8")
        self._access_ttl = int(os.getenv("ACCESS_TOKEN_TTL_SECONDS", "900"))
        self._refresh_ttl = int(os.getenv("REFRESH_TOKEN_TTL_SECONDS", "604800"))

    @staticmethod
    def _b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode("utf-8")

    @staticmethod
    def _unb64(value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value + padding)

    def _sign(self, header: dict[str, Any], payload: dict[str, Any]) -> str:
        h = self._b64(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        p = self._b64(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        sig = hmac.new(self._secret, f"{h}.{p}".encode("utf-8"), hashlib.sha256).digest()
        return f"{h}.{p}.{self._b64(sig)}"

    def issue_tokens(self, subject: str) -> dict[str, str | int]:
        now = int(time.time())
        access_payload = {
            "sub": subject,
            "iat": now,
            "exp": now + self._access_ttl,
            "jti": str(uuid.uuid4()),
            "typ": "access",
        }
        access_token = self._sign({"alg": "HS256", "typ": "JWT"}, access_payload)

        refresh_raw = secrets.token_urlsafe(48)
        token_id = str(uuid.uuid4())
        refresh_hash = hashlib.sha256(refresh_raw.encode("utf-8")).hexdigest()
        self._store.store_refresh_token(token_id=token_id, user_email=subject, token_hash=refresh_hash, ttl_seconds=self._refresh_ttl)
        refresh_token = f"{token_id}.{refresh_raw}"
        return {
            "accessToken": access_token,
            "refreshToken": refresh_token,
            "tokenType": "bearer",
            "expiresIn": self._access_ttl,
        }

    def refresh(self, refresh_token: str) -> dict[str, str | int]:
        try:
            token_id, raw = refresh_token.split(".", 1)
        except ValueError as exc:
            raise ValueError("Refresh token inválido") from exc
        record = self._store.get_refresh_token(token_id)
        if not record or record["revoked"]:
            raise ValueError("Refresh token inválido o revocado")
        if int(record["expires_at"]) < int(time.time()):
            raise ValueError("Refresh token expirado")
        incoming_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(incoming_hash, record["token_hash"]):
            raise ValueError("Refresh token inválido")
        self._store.revoke_refresh_token(token_id)
        return self.issue_tokens(subject=record["user_email"])

    def revoke_refresh(self, refresh_token: str) -> None:
        try:
            token_id, _ = refresh_token.split(".", 1)
        except ValueError:
            return
        self._store.revoke_refresh_token(token_id)


class TotpService:
    def __init__(self, issuer: str = "CryptoLock") -> None:
        self._issuer = issuer

    @staticmethod
    def generate_secret() -> str:
        return base64.b32encode(secrets.token_bytes(20)).decode("utf-8").strip("=")

    def provisioning_uri(self, *, email: str, secret: str) -> str:
        return f"otpauth://totp/{self._issuer}:{email}?secret={secret}&issuer={self._issuer}&algorithm=SHA1&digits=6&period=30"

    @staticmethod
    def _hotp(secret: str, counter: int, digits: int = 6) -> str:
        key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
        msg = struct.pack(">Q", counter)
        hmac_digest = hmac.new(key, msg, hashlib.sha1).digest()
        offset = hmac_digest[-1] & 0x0F
        code_int = (struct.unpack(">I", hmac_digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
        return f"{code_int:0{digits}d}"

    def verify(self, *, secret: str, code: str, drift_windows: int = 1) -> bool:
        timestep = int(time.time() // 30)
        normalized = (code or "").strip()
        for delta in range(-drift_windows, drift_windows + 1):
            candidate = self._hotp(secret, timestep + delta)
            if hmac.compare_digest(candidate, normalized):
                return True
        return False


security_store = SecurityDataStore()
otp_service = OTPService(security_store)
rate_limiter = RateLimiter(security_store)
token_service = TokenService(security_store)
totp_service = TotpService()