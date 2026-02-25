import time
from pathlib import Path

import pytest

from backend_real.services.security_service import (
    OTPService,
    PasswordHasher,
    SecurityDataStore,
    TokenService,
    TotpService,
)


def _build_store(tmp_path: Path) -> SecurityDataStore:
    return SecurityDataStore(db_path=str(tmp_path / "security_test.sqlite3"))


def test_password_hasher_hash_and_verify() -> None:
    hasher = PasswordHasher(iterations=1000)

    password_hash = hasher.hash_password("super-secret")

    assert password_hash.startswith("pbkdf2_sha256$")
    assert hasher.verify_password("super-secret", password_hash) is True
    assert hasher.verify_password("wrong", password_hash) is False


def test_otp_service_create_and_verify_ok(tmp_path: Path) -> None:
    store = _build_store(tmp_path)
    otp_service = OTPService(store=store, secret_key="pepper")

    otp = otp_service.create(email="user@example.com", purpose="login", ttl_seconds=60)
    ok, message = otp_service.verify(email="user@example.com", purpose="login", otp=otp)

    assert ok is True
    assert message == "OK"


def test_otp_service_blocks_after_max_attempts(tmp_path: Path) -> None:
    store = _build_store(tmp_path)
    otp_service = OTPService(store=store, secret_key="pepper")

    otp_service.create(email="user@example.com", purpose="login", ttl_seconds=60, max_attempts=2)

    ok1, msg1 = otp_service.verify(email="user@example.com", purpose="login", otp="000000")
    ok2, msg2 = otp_service.verify(email="user@example.com", purpose="login", otp="000000")

    assert ok1 is False
    assert msg1 == "OTP inválido"
    assert ok2 is False
    assert msg2 == "OTP inválido: demasiados intentos"


def test_token_service_issue_refresh_and_revoke(tmp_path: Path) -> None:
    store = _build_store(tmp_path)
    token_service = TokenService(store=store, secret="jwt-secret")

    issued = token_service.issue_tokens("user@example.com")
    assert "accessToken" in issued
    assert "refreshToken" in issued

    refreshed = token_service.refresh(str(issued["refreshToken"]))
    assert "accessToken" in refreshed
    assert "refreshToken" in refreshed

    token_service.revoke_refresh(str(refreshed["refreshToken"]))
    with pytest.raises(ValueError, match="inválido o revocado"):
        token_service.refresh(str(refreshed["refreshToken"]))


def test_totp_service_verify_code_with_fixed_time(monkeypatch: pytest.MonkeyPatch) -> None:
    totp = TotpService(issuer="CryptoLock")
    secret = TotpService.generate_secret()

    fixed_epoch = 1_700_000_000
    monkeypatch.setattr(time, "time", lambda: fixed_epoch)

    timestep = int(fixed_epoch // 30)
    valid_code = totp._hotp(secret, timestep)

    assert totp.verify(secret=secret, code=valid_code) is True
    assert totp.verify(secret=secret, code="123456") is False