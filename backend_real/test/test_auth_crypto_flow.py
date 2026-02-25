import base64
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

cryptography = pytest.importorskip("cryptography")

# Permite resolver imports absolutos internos tipo `from api...`, `from services...`
BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

import api.auth as auth_module
from api.auth import AuthService, CryptoChallengeRequest, CryptoExchangeRequest, CryptoVerifyRequest
from domain.usuarios import EstadoUsuario, UsuarioHumano
from services.security_service import SecurityDataStore, TokenService


@dataclass
class _FakeAudit:
    events: list

    def registrar_evento(self, **kwargs):
        self.events.append(kwargs)
        return kwargs


class _FakeRepo:
    def __init__(self, user: UsuarioHumano) -> None:
        self._user = user

    def get_by_email(self, email: str):
        if email.strip().lower() == self._user.email:
            return self._user
        return None

    def save(self, user):
        self._user = user
        return user


class _RateLimiterAlwaysAllow:
    @staticmethod
    def check(**_kwargs):
        return True, 0


@pytest.fixture
def crypto_user():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    user = UsuarioHumano(email="crypto@gmail.com", nombre="Crypto User")
    user.passwordHash = "unused"
    user.estado = EstadoUsuario.ACTIVO
    user.emailVerificado = True
    user.cryptoAuthEnabled = True
    user.cryptoPublicKeyPem = public_key_pem
    return user, private_key


@pytest.fixture
def auth_service(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, crypto_user):
    user, _ = crypto_user

    store = SecurityDataStore(db_path=str(tmp_path / "auth_crypto.sqlite3"))
    token_service = TokenService(store=store, secret="unit-test-jwt")

    monkeypatch.setattr(auth_module, "security_store", store)
    monkeypatch.setattr(auth_module, "token_service", token_service)
    monkeypatch.setattr(auth_module, "rate_limiter", _RateLimiterAlwaysAllow())

    svc = AuthService()
    svc._users_repo = _FakeRepo(user)
    svc._audit = _FakeAudit(events=[])
    svc._crypto_challenge_ttl = 120
    svc._crypto_login_grant_ttl = 120
    svc._crypto_max_attempts = 3
    return svc, store


def test_crypto_signature_login_end_to_end_success(auth_service, crypto_user) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    svc, _store = auth_service
    user, private_key = crypto_user

    challenge_resp = svc.request_crypto_challenge(CryptoChallengeRequest(email=user.email))
    challenge_id = challenge_resp["challengeId"]
    challenge_value = challenge_resp["challenge"]

    signature = private_key.sign(
        challenge_value.encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    verify_resp = svc.verify_crypto_signature(
        CryptoVerifyRequest(
            email=user.email,
            challengeId=challenge_id,
            signature=signature_b64,
        )
    )

    assert verify_resp["approved"] is True
    assert verify_resp["challengeId"] == challenge_id
    assert verify_resp["loginGrant"]

    exchange_resp = svc.exchange_crypto_login(
        CryptoExchangeRequest(challengeId=challenge_id, loginGrant=verify_resp["loginGrant"])
    )
    assert exchange_resp["user"]["email"] == user.email
    assert "accessToken" in exchange_resp
    assert "refreshToken" in exchange_resp


def test_crypto_verify_rejects_invalid_base64_signature(auth_service, crypto_user) -> None:
    svc, store = auth_service
    user, _ = crypto_user

    challenge_resp = svc.request_crypto_challenge(CryptoChallengeRequest(email=user.email))
    challenge_id = challenge_resp["challengeId"]

    with pytest.raises(auth_module.HTTPException) as exc:
        svc.verify_crypto_signature(
            CryptoVerifyRequest(
                email=user.email,
                challengeId=challenge_id,
                signature="no-es-base64",
            )
        )

    assert exc.value.status_code == 400
    assert "base64" in str(exc.value.detail).lower()

    row = store.get_crypto_challenge(challenge_id)
    assert row is not None
    assert int(row["attempts"]) == 1


def test_crypto_verify_rejects_invalid_signature(auth_service, crypto_user) -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    svc, store = auth_service
    user, private_key = crypto_user

    challenge_resp = svc.request_crypto_challenge(CryptoChallengeRequest(email=user.email))
    challenge_id = challenge_resp["challengeId"]

    # Firma otra cadena para forzar InvalidSignature
    wrong_signature = private_key.sign(
        b"otro-challenge",
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )
    wrong_signature_b64 = base64.b64encode(wrong_signature).decode("utf-8")

    with pytest.raises(auth_module.HTTPException) as exc:
        svc.verify_crypto_signature(
            CryptoVerifyRequest(
                email=user.email,
                challengeId=challenge_id,
                signature=wrong_signature_b64,
            )
        )

    assert exc.value.status_code == 401
    assert "firma invalida" in str(exc.value.detail).lower()

    row = store.get_crypto_challenge(challenge_id)
    assert row is not None
    assert int(row["attempts"]) == 1