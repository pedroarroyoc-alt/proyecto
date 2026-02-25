import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

import pytest

cryptography = pytest.importorskip("cryptography")

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import api.users as users_module
from api.users import (
    ConfirmTotpEnrollmentRequest,
    CreateHumanUser,
    EnableMfaRequest,
    EnrollFaceIdRequest,
    ResendVerificationOtpRequest,
    UpdateCryptoSignatureMethodRequest,
    UpdateFaceIdMethodRequest,
    UserError,
    UserService,
    VerifyEmailRequest,
    VerifyRecoveryCodeRequest,
)
from domain.usuarios import EstadoUsuario, UsuarioHumano


@dataclass
class _FakeAudit:
    events: list

    def registrar_evento(self, **kwargs):
        self.events.append(kwargs)
        return kwargs


class _Repo:
    def __init__(self):
        self.users = {}

    def save(self, user):
        self.users[str(user.id)] = user
        return user

    def get_by_id(self, user_id: str):
        return self.users.get(user_id)

    def get_by_email(self, email: str):
        email = email.strip().lower()
        for user in self.users.values():
            if user.email.lower() == email:
                return user
        return None

    def list_all(self):
        return list(self.users.values())


class _OtpManager:
    def __init__(self):
        self.generated = {}

    def generate_for_email(self, email: str) -> str:
        code = "999000"
        self.generated[email] = code
        return code

    def verify(self, email: str, otp: str) -> bool:
        return self.generated.get(email) == otp

    def clear(self, email: str) -> None:
        self.generated.pop(email, None)


class _Hasher:
    @staticmethod
    def hash_password(password: str) -> str:
        return f"h::{password}"

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        return password_hash == f"h::{password}"


class _TotpService:
    @staticmethod
    def generate_secret() -> str:
        return "TOTPSECRET"

    @staticmethod
    def provisioning_uri(*, email: str, secret: str) -> str:
        return f"otpauth://totp/CryptoLock:{email}?secret={secret}"

    @staticmethod
    def verify(*, secret: str, code: str) -> bool:
        return secret == "TOTPSECRET" and code == "222222"


class _FaceIdService:
    @staticmethod
    def enroll_user(_email: str, _images: list[str], overwrite: bool = True) -> int:
        return 3


@pytest.fixture
def user_service(monkeypatch: pytest.MonkeyPatch):
    repo = _Repo()
    otp = _OtpManager()
    hasher = _Hasher()

    svc = UserService(repository=repo, otp_manager=otp, password_hasher=hasher)
    svc._audit = _FakeAudit(events=[])

    monkeypatch.setattr(users_module, "send_otp_email", lambda _email, _otp: None)
    monkeypatch.setattr(users_module, "totp_service", _TotpService())
    monkeypatch.setattr(users_module, "faceid_service", _FaceIdService())
    monkeypatch.setattr(users_module, "secrets", type("S", (), {"token_hex": staticmethod(lambda _n: "deadbeef")})())

    return svc, repo, otp


def _new_user(email: str = "base@gmail.com") -> UsuarioHumano:
    u = UsuarioHumano(email=email, nombre="Base")
    u.id = uuid.uuid4()
    return u


def test_create_verify_resend_user_flow(user_service):
    svc, repo, otp = user_service

    created = svc.create_human_user(
        CreateHumanUser(email="new@gmail.com", nombre="Nuevo", password="password123", telefono="999")
    )
    assert created["requiresEmailVerification"] is True

    verify = svc.verify_email(VerifyEmailRequest(email="new@gmail.com", otp="999000"))
    assert verify["message"].lower().startswith("correo verificado")

    pending = _new_user("pending@gmail.com")
    pending.estado = EstadoUsuario.PENDIENTE
    pending.emailVerificado = False
    repo.save(pending)
    resend = svc.resend_verification_otp(ResendVerificationOtpRequest(email="pending@gmail.com"))
    assert resend["requiresEmailVerification"] is True
    assert otp.generated["pending@gmail.com"] == "999000"


def test_update_user_mfa_and_faceid_and_crypto_methods(user_service, monkeypatch: pytest.MonkeyPatch):
    svc, repo, _ = user_service
    user = _new_user("methods@gmail.com")
    user.estado = EstadoUsuario.ACTIVO
    user.emailVerificado = True
    repo.save(user)

    mfa = svc.update_user_mfa(str(user.id), EnableMfaRequest(mfaHabilitado=True))
    assert mfa["user"]["mfaHabilitado"] is True

    monkeypatch.setattr(UserService, "_validate_crypto_public_key_pem", staticmethod(lambda pem: pem.strip() or "pem"))
    crypto = svc.update_crypto_signature_method(
        str(user.id),
        UpdateCryptoSignatureMethodRequest(habilitado=True, publicKeyPem="-----BEGIN PUBLIC KEY-----x"),
    )
    assert crypto["user"]["cryptoAuthEnabled"] is True

    faceid = svc.update_faceid_method(str(user.id), UpdateFaceIdMethodRequest(habilitado=True))
    assert faceid["user"]["faceIdEnabled"] is True


def test_enroll_faceid_and_totp_and_recovery_code(user_service):
    svc, repo, _ = user_service
    user = _new_user("mfa@gmail.com")
    user.estado = EstadoUsuario.ACTIVO
    user.emailVerificado = True
    repo.save(user)

    enrolled = svc.enroll_faceid(str(user.id), EnrollFaceIdRequest(imagenes=["a", "b", "c"]))
    assert enrolled["acceptedSamples"] == 3

    start = svc.start_totp_enrollment(str(user.id))
    assert start["secret"] == "TOTPSECRET"
    assert len(start["recoveryCodes"]) == 8

    confirm = svc.confirm_totp_enrollment(str(user.id), ConfirmTotpEnrollmentRequest(codigo="222222"))
    assert confirm["user"]["mfaMetodo"] == "totp"

    first_code = start["recoveryCodes"][0]
    ok = svc.verify_recovery_code(str(user.id), VerifyRecoveryCodeRequest(codigo=first_code))
    assert ok["message"].lower().startswith("recovery code válido")


def test_list_and_get_user(user_service):
    svc, repo, _ = user_service
    user = _new_user("list@gmail.com")
    repo.save(user)

    all_users = svc.list_users()
    assert len(all_users) >= 1

    one = svc.get_user(str(user.id))
    assert one["email"] == "list@gmail.com"

    with pytest.raises(UserError):
        svc.get_user("missing-id")