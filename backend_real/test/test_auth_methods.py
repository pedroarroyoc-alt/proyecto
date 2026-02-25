import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

cryptography = pytest.importorskip("cryptography")

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import api.auth as auth_module
from api.auth import AuthService, FaceIdLoginRequest, LoginRequest, LoginVerify, LogoutRequest, RefreshTokenRequest
from domain.usuarios import EstadoUsuario, UsuarioHumano
from services.faceid_service import FaceVerificationResult


@dataclass
class _FakeAudit:
    events: list

    def registrar_evento(self, **kwargs):
        self.events.append(kwargs)
        return kwargs


class _Repo:
    def __init__(self, user: UsuarioHumano):
        self.user = user

    def get_by_email(self, email: str):
        if email.strip().lower() == self.user.email:
            return self.user
        return None

    def save(self, user):
        self.user = user
        return user


class _RateLimiter:
    @staticmethod
    def check(**_kwargs):
        return True, 0


class _OtpService:
    @staticmethod
    def create(**_kwargs):
        return "123456"


class _TotpService:
    @staticmethod
    def generate_secret() -> str:
        return "SECRET123"

    @staticmethod
    def verify(*, secret: str, code: str) -> bool:
        return secret == "SECRET123" and code == "111111"

    @staticmethod
    def provisioning_uri(*, email: str, secret: str) -> str:
        return f"otpauth://totp/CryptoLock:{email}?secret={secret}"


class _TokenService:
    def __init__(self):
        self.revoked = []

    @staticmethod
    def issue_tokens(subject: str):
        return {
            "accessToken": f"access-{subject}",
            "refreshToken": f"refresh-{subject}",
            "tokenType": "bearer",
            "expiresIn": 900,
        }

    @staticmethod
    def refresh(_refresh_token: str):
        return {
            "accessToken": "access-new",
            "refreshToken": "refresh-new",
            "tokenType": "bearer",
            "expiresIn": 900,
        }

    def revoke_refresh(self, refresh_token: str):
        self.revoked.append(refresh_token)


class _FaceIdService:
    def __init__(self, authorized: bool):
        self.authorized = authorized

    def verify_user(self, _email: str, _image_b64: str):
        return FaceVerificationResult(
            autorizado=self.authorized,
            confianza_lbph=20.0 if self.authorized else None,
            rostros_detectados=1,
        )


@pytest.fixture
def service(monkeypatch: pytest.MonkeyPatch):
    user = UsuarioHumano(email="user@gmail.com", nombre="User")
    user.estado = EstadoUsuario.ACTIVO
    user.emailVerificado = True
    user.passwordHash = "hash"

    svc = AuthService()
    svc._users_repo = _Repo(user)
    svc._audit = _FakeAudit(events=[])
    svc._pwd_hasher = type("Pwd", (), {"verify_password": staticmethod(lambda p, _h: p == "pass1234")})()

    monkeypatch.setattr(auth_module, "rate_limiter", _RateLimiter())
    monkeypatch.setattr(auth_module, "otp_service", _OtpService())
    monkeypatch.setattr(auth_module, "totp_service", _TotpService())
    monkeypatch.setattr(auth_module, "token_service", _TokenService())
    monkeypatch.setattr(auth_module, "send_otp_email", lambda _email, _otp: None)

    return svc, user


def test_request_login_otp_unverified_user_requests_email_verification(service):
    svc, user = service
    user.emailVerificado = False
    user.estado = EstadoUsuario.PENDIENTE

    resp = svc.request_login_otp(LoginRequest(email=user.email, password="pass1234"))

    assert resp["requiresEmailVerification"] is True
    assert resp["emailSent"] is True


def test_request_login_otp_active_user_without_totp_creates_enrollment(service):
    svc, user = service
    user.totpSecret = ""

    resp = svc.request_login_otp(LoginRequest(email=user.email, password="pass1234"))

    assert resp["mfaRequired"] is True
    assert resp["mfaMethod"] == "totp"
    assert "totpEnrollment" in resp
    assert user.totpSecret == "SECRET123"


def test_verify_login_otp_totp_success_returns_tokens(service):
    svc, user = service
    user.totpSecret = "SECRET123"
    user.mfaHabilitado = False
    user.mfaMetodo = "totp_pending"

    resp = svc.verify_login_otp(LoginVerify(email=user.email, otp="111111"))

    assert resp["message"].startswith("Acceso verificado")
    assert "accessToken" in resp
    assert user.mfaHabilitado is True
    assert user.mfaMetodo == "totp"


def test_login_faceid_success_returns_tokens(service, monkeypatch: pytest.MonkeyPatch):
    svc, user = service
    user.faceIdEnabled = True
    user.faceIdEnrolled = True

    monkeypatch.setattr(auth_module, "faceid_service", _FaceIdService(authorized=True))

    resp = svc.login_faceid(FaceIdLoginRequest(email=user.email, imageBase64="abc"))

    assert resp["message"].startswith("Acceso verificado")
    assert "accessToken" in resp


def test_login_faceid_denied_raises_401(service, monkeypatch: pytest.MonkeyPatch):
    svc, user = service
    user.faceIdEnabled = True
    user.faceIdEnrolled = True
    monkeypatch.setattr(auth_module, "faceid_service", _FaceIdService(authorized=False))

    with pytest.raises(auth_module.HTTPException) as exc:
        svc.login_faceid(FaceIdLoginRequest(email=user.email, imageBase64="abc"))

    assert exc.value.status_code == 401


def test_refresh_and_logout(service):
    svc, _user = service

    refreshed = svc.refresh_token(RefreshTokenRequest(refreshToken="r1"))
    assert refreshed["message"] == "Token renovado"

    logout_resp = svc.logout(LogoutRequest(refreshToken="r2"))
    assert logout_resp["message"] == "Sesion revocada"