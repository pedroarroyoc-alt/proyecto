from __future__ import annotations

import base64
import os
import secrets
import time
import uuid
from datetime import datetime
from urllib.parse import quote

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, EmailStr, field_validator

from api.users import password_hasher, user_repository
from services.audit_service import get_audit_service
from services.email_service import EmailDeliveryError, send_otp_email
from services.security_service import (
    otp_service,
    rate_limiter,
    security_store,
    token_service,
    totp_service,
)

router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> str:
        return str(v).strip().lower()


class LoginVerify(BaseModel):
    email: EmailStr
    otp: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> str:
        return str(v).strip().lower()


class RefreshTokenRequest(BaseModel):
    refreshToken: str


class LogoutRequest(BaseModel):
    refreshToken: str


class CryptoChallengeRequest(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> str:
        return str(v).strip().lower()


class CryptoVerifyRequest(BaseModel):
    email: EmailStr
    challengeId: str
    signature: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> str:
        return str(v).strip().lower()

    @field_validator("challengeId")
    @classmethod
    def normalize_challenge_id(cls, v: str) -> str:
        return (v or "").strip()

    @field_validator("signature")
    @classmethod
    def normalize_signature(cls, v: str) -> str:
        return (v or "").strip()


class CryptoExchangeRequest(BaseModel):
    challengeId: str
    loginGrant: str

    @field_validator("challengeId")
    @classmethod
    def normalize_challenge_id(cls, v: str) -> str:
        return (v or "").strip()

    @field_validator("loginGrant")
    @classmethod
    def normalize_grant(cls, v: str) -> str:
        return (v or "").strip()


class AuthService:
    def __init__(self) -> None:
        self._users_repo = user_repository
        self._pwd_hasher = password_hasher
        self._audit = get_audit_service()
        self._crypto_challenge_ttl = int(os.getenv("CRYPTO_CHALLENGE_TTL_SECONDS", "180"))
        self._crypto_login_grant_ttl = int(os.getenv("CRYPTO_LOGIN_GRANT_TTL_SECONDS", "120"))
        self._crypto_max_attempts = int(os.getenv("CRYPTO_CHALLENGE_MAX_ATTEMPTS", "5"))

    @staticmethod
    def _normalize_otp(otp: str) -> str:
        return (otp or "").strip()

    @staticmethod
    def _expose_debug_otp() -> bool:
        return os.getenv("EXPOSE_OTP_IN_RESPONSE", "false").lower() == "true"

    @staticmethod
    def _now_ts() -> int:
        return int(time.time())

    @staticmethod
    def _build_totp_enrollment(email: str, secret: str) -> dict:
        otpauth_uri = totp_service.provisioning_uri(email=email, secret=secret)
        qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=220x220&data={quote(otpauth_uri, safe='')}"
        return {
            "secret": secret,
            "otpauthUri": otpauth_uri,
            "qrUrl": qr_url,
        }

    def _validate_active_user_for_login(self, email: str):
        user = self._users_repo.get_by_email(email)
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")

        if not user.autenticar():
            if not bool(getattr(user, "emailVerificado", False)):
                raise HTTPException(status_code=403, detail="Cuenta pendiente de verificacion de correo")
            raise HTTPException(status_code=403, detail="Usuario no activo")
        return user

    def _assert_crypto_method_enabled(self, user) -> None:
        if not bool(getattr(user, "cryptoAuthEnabled", False)):
            raise HTTPException(status_code=400, detail="Firma criptografica deshabilitada para este usuario")
        if not str(getattr(user, "cryptoPublicKeyPem", "") or "").strip():
            raise HTTPException(status_code=400, detail="No hay llave publica registrada")

    # ======== Login por correo+password+TOTP ========
    def request_login_otp(self, payload: LoginRequest):
        email = str(payload.email).strip().lower()
        password = (payload.password or "").strip()

        allowed, retry_after = rate_limiter.check(
            action="login_request",
            key=email,
            window_seconds=60,
            max_attempts=5,
            block_seconds=180,
        )
        if not allowed:
            raise HTTPException(status_code=429, detail=f"Demasiados intentos. Reintenta en {retry_after}s")

        user = self._users_repo.get_by_email(email)
        if not user:
            raise HTTPException(status_code=401, detail="Credenciales invalidas")

        if not user.autenticar():
            if not bool(getattr(user, "emailVerificado", False)):
                otp = otp_service.create(email=email, purpose="email_verification", ttl_seconds=300)
                email_sent = True
                response = {
                    "message": "Tu cuenta existe pero falta verificar el correo. Te enviamos un OTP de verificacion.",
                    "mfaRequired": False,
                    "mfaMethod": getattr(user, "mfaMetodo", "none"),
                    "emailSecondFactorRequired": False,
                    "requiresEmailVerification": True,
                }
                try:
                    send_otp_email(email, otp)
                except EmailDeliveryError as exc:
                    email_sent = False
                    response["message"] = "Tu cuenta no esta verificada y no se pudo enviar el OTP por correo"
                    print(f"[WARN] No se pudo enviar OTP de verificacion a {email}: {exc}")

                response["emailSent"] = email_sent
                if not email_sent and self._expose_debug_otp():
                    response["otpDebug"] = otp

                self._audit.registrar_evento(
                    usuario_id=email,
                    accion="LOGIN_EMAIL_VERIFICATION_OTP_REQUESTED",
                    recurso="/auth/login/request-otp",
                    metadatos={"emailSent": email_sent},
                )
                return response

            raise HTTPException(status_code=403, detail="Usuario no activo")

        if not self._pwd_hasher.verify_password(password, user.passwordHash):
            raise HTTPException(status_code=401, detail="Credenciales invalidas")

        has_totp_configured = bool(user.totpSecret)
        if not has_totp_configured:
            secret = totp_service.generate_secret()
            user.totpSecret = secret
            user.mfaMetodo = "totp_pending"
            user.mfaHabilitado = False
            self._users_repo.save(user)
            enrollment = self._build_totp_enrollment(email=email, secret=secret)
            response = {
                "message": "Configura tu app autenticadora y luego ingresa el codigo TOTP.",
                "mfaRequired": True,
                "mfaMethod": "totp",
                "totpEnrollment": enrollment,
                "emailSecondFactorRequired": False,
            }
            self._audit.registrar_evento(
                usuario_id=email,
                accion="LOGIN_TOTP_ENROLLMENT_CREATED",
                recurso="/auth/login/request-otp",
                metadatos={"mfaMethod": "totp"},
            )
            return response

        response = {
            "message": "Credenciales validas",
            "mfaRequired": True,
            "mfaMethod": "totp",
            "emailSecondFactorRequired": False,
        }
        self._audit.registrar_evento(
            usuario_id=email,
            accion="LOGIN_CHALLENGE_TOTP_REQUESTED",
            recurso="/auth/login/request-otp",
            metadatos={"mfaMethod": "totp"},
        )
        return response

    def verify_login_otp(self, payload: LoginVerify):
        email = str(payload.email).strip().lower()
        code = self._normalize_otp(payload.otp)

        allowed, retry_after = rate_limiter.check(
            action="login_verify",
            key=email,
            window_seconds=300,
            max_attempts=10,
            block_seconds=300,
        )
        if not allowed:
            raise HTTPException(status_code=429, detail=f"Demasiados intentos. Reintenta en {retry_after}s")

        user = self._users_repo.get_by_email(email)
        if not user:
            raise HTTPException(status_code=401, detail="Usuario no encontrado")
        if not user.totpSecret:
            raise HTTPException(status_code=400, detail="Debes configurar TOTP antes de ingresar")

        if totp_service.verify(secret=user.totpSecret, code=code):
            if not bool(user.mfaHabilitado) or getattr(user, "mfaMetodo", "none") != "totp":
                user.mfaHabilitado = True
                user.mfaMetodo = "totp"
                if hasattr(user, "actualizar_nivel_confianza"):
                    user.actualizar_nivel_confianza()
                self._users_repo.save(user)
            tokens = token_service.issue_tokens(email)
            self._audit.registrar_evento(
                usuario_id=email,
                accion="LOGIN_VERIFIED_TOTP",
                recurso="/auth/login/verify-otp",
                metadatos={"mfaMethod": "totp", "at": datetime.utcnow().isoformat()},
            )
            return {"message": "Acceso verificado por TOTP", "user": {"email": email}, **tokens}

        for hashed in list(getattr(user, "recoveryCodesHash", [])):
            if self._pwd_hasher.verify_password(code, hashed):
                user.recoveryCodesHash.remove(hashed)
                self._users_repo.save(user)
                tokens = token_service.issue_tokens(email)
                self._audit.registrar_evento(
                    usuario_id=email,
                    accion="LOGIN_VERIFIED_RECOVERY",
                    recurso="/auth/login/verify-otp",
                    metadatos={"remainingCodes": len(user.recoveryCodesHash)},
                )
                return {"message": "Acceso verificado por recovery code", "user": {"email": email}, **tokens}

        raise HTTPException(status_code=400, detail="Codigo TOTP/Recovery invalido")

    # ======== Login challenge + firma criptografica ========
    def request_crypto_challenge(self, payload: CryptoChallengeRequest) -> dict:
        email = str(payload.email).strip().lower()
        allowed, retry_after = rate_limiter.check(
            action="crypto_challenge_request",
            key=email,
            window_seconds=60,
            max_attempts=20,
            block_seconds=120,
        )
        if not allowed:
            raise HTTPException(status_code=429, detail=f"Demasiados intentos. Reintenta en {retry_after}s")

        user = self._validate_active_user_for_login(email)
        self._assert_crypto_method_enabled(user)

        challenge_id = str(uuid.uuid4())
        challenge_value = secrets.token_urlsafe(48)
        security_store.put_crypto_challenge(
            challenge_id=challenge_id,
            email=email,
            challenge=challenge_value,
            ttl_seconds=self._crypto_challenge_ttl,
            max_attempts=self._crypto_max_attempts,
        )

        self._audit.registrar_evento(
            usuario_id=email,
            accion="LOGIN_CRYPTO_CHALLENGE_REQUESTED",
            recurso="/auth/crypto/challenge",
            metadatos={"challengeId": challenge_id},
        )

        now = self._now_ts()
        return {
            "message": "Challenge criptografico generado",
            "challengeId": challenge_id,
            "challenge": challenge_value,
            "algorithm": "RSA-PSS-SHA256",
            "expiresIn": self._crypto_challenge_ttl,
            "expiresAt": now + self._crypto_challenge_ttl,
        }

    def verify_crypto_signature(self, payload: CryptoVerifyRequest) -> dict:
        email = str(payload.email).strip().lower()
        challenge_id = payload.challengeId
        signature_raw = payload.signature.strip()

        allowed, retry_after = rate_limiter.check(
            action="crypto_challenge_verify",
            key=f"{email}:{challenge_id}",
            window_seconds=300,
            max_attempts=25,
            block_seconds=120,
        )
        if not allowed:
            raise HTTPException(status_code=429, detail=f"Demasiados intentos. Reintenta en {retry_after}s")

        user = self._validate_active_user_for_login(email)
        self._assert_crypto_method_enabled(user)

        row = security_store.get_crypto_challenge(challenge_id)
        if not row:
            raise HTTPException(status_code=404, detail="Challenge no encontrado")
        if row["email"] != email:
            raise HTTPException(status_code=403, detail="Challenge no pertenece a este usuario")
        if row["status"] not in ("pending",):
            raise HTTPException(status_code=409, detail=f"Challenge en estado {row['status']}")

        now = self._now_ts()
        if int(row["expires_at"]) < now:
            security_store.mark_crypto_challenge_failed(challenge_id)
            raise HTTPException(status_code=400, detail="Challenge expirado")

        if int(row["attempts"]) >= int(row["max_attempts"]):
            security_store.mark_crypto_challenge_failed(challenge_id)
            raise HTTPException(status_code=429, detail="Challenge bloqueado por demasiados intentos")

        try:
            signature_bytes = base64.b64decode(signature_raw, validate=True)
        except Exception:
            security_store.increment_crypto_challenge_attempt(challenge_id)
            raise HTTPException(status_code=400, detail="Firma en base64 invalida")

        try:
            public_key = serialization.load_pem_public_key(user.cryptoPublicKeyPem.encode("utf-8"))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"Llave publica invalida: {exc}") from exc
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise HTTPException(status_code=400, detail="La llave publica registrada no es RSA")

        try:
            public_key.verify(
                signature_bytes,
                row["challenge"].encode("utf-8"),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                hashes.SHA256(),
            )
        except InvalidSignature:
            security_store.increment_crypto_challenge_attempt(challenge_id)
            current = security_store.get_crypto_challenge(challenge_id) or {}
            attempts = int(current.get("attempts", 0))
            max_attempts = int(current.get("max_attempts", self._crypto_max_attempts))
            if attempts >= max_attempts:
                security_store.mark_crypto_challenge_failed(challenge_id)

            self._audit.registrar_evento(
                usuario_id=email,
                accion="LOGIN_CRYPTO_SIGNATURE_INVALID",
                recurso="/auth/crypto/verify",
                metadatos={"challengeId": challenge_id, "attempts": attempts},
            )
            raise HTTPException(status_code=401, detail="Firma invalida")

        login_grant = secrets.token_urlsafe(32)
        security_store.mark_crypto_challenge_verified(
            challenge_id=challenge_id,
            login_grant=login_grant,
            grant_ttl_seconds=self._crypto_login_grant_ttl,
        )

        self._audit.registrar_evento(
            usuario_id=email,
            accion="LOGIN_CRYPTO_SIGNATURE_VERIFIED",
            recurso="/auth/crypto/verify",
            metadatos={"challengeId": challenge_id},
        )
        return {
            "message": "Firma valida. Puedes completar el login.",
            "approved": True,
            "challengeId": challenge_id,
            "loginGrant": login_grant,
            "grantExpiresIn": self._crypto_login_grant_ttl,
        }

    def crypto_challenge_status(self, challenge_id: str) -> dict:
        row = security_store.get_crypto_challenge(challenge_id)
        if not row:
            raise HTTPException(status_code=404, detail="Challenge no encontrado")

        now = self._now_ts()
        status = row["status"]
        if status == "pending" and int(row["expires_at"]) < now:
            security_store.mark_crypto_challenge_failed(challenge_id)
            status = "expired"

        login_grant = ""
        if status == "verified" and int(row.get("grant_expires_at", 0)) >= now:
            login_grant = row.get("login_grant", "") or ""

        return {
            "challengeId": challenge_id,
            "email": row["email"],
            "status": status,
            "approved": status == "verified",
            "expiresAt": int(row["expires_at"]),
            "expiresIn": max(0, int(row["expires_at"]) - now),
            "verifiedAt": int(row.get("verified_at", 0)) or None,
            "loginGrant": login_grant,
        }

    def exchange_crypto_login(self, payload: CryptoExchangeRequest) -> dict:
        challenge_id = payload.challengeId
        grant = payload.loginGrant
        if not challenge_id or not grant:
            raise HTTPException(status_code=400, detail="challengeId y loginGrant son obligatorios")

        consumed = security_store.consume_crypto_login_grant(challenge_id=challenge_id, login_grant=grant)
        if not consumed:
            raise HTTPException(status_code=401, detail="Grant invalido o expirado")

        email = consumed["email"]
        user = self._validate_active_user_for_login(email)
        self._assert_crypto_method_enabled(user)

        tokens = token_service.issue_tokens(email)
        self._audit.registrar_evento(
            usuario_id=email,
            accion="LOGIN_CRYPTO_GRANTED",
            recurso="/auth/crypto/exchange",
            metadatos={"challengeId": challenge_id},
        )
        return {"message": "Acceso verificado por firma criptografica", "user": {"email": email}, **tokens}

    # ======== Tokens ========
    def refresh_token(self, payload: RefreshTokenRequest):
        try:
            tokens = token_service.refresh(payload.refreshToken)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return {"message": "Token renovado", **tokens}

    def logout(self, payload: LogoutRequest):
        token_service.revoke_refresh(payload.refreshToken)
        return {"message": "Sesion revocada"}


class AuthController:
    def __init__(self, auth_service: AuthService):
        self._auth_service = auth_service

    def request_login_otp(self, payload: LoginRequest):
        return self._auth_service.request_login_otp(payload)

    def verify_login_otp(self, payload: LoginVerify):
        return self._auth_service.verify_login_otp(payload)

    def request_crypto_challenge(self, payload: CryptoChallengeRequest):
        return self._auth_service.request_crypto_challenge(payload)

    def verify_crypto_signature(self, payload: CryptoVerifyRequest):
        return self._auth_service.verify_crypto_signature(payload)

    def crypto_challenge_status(self, challenge_id: str):
        return self._auth_service.crypto_challenge_status(challenge_id)

    def exchange_crypto_login(self, payload: CryptoExchangeRequest):
        return self._auth_service.exchange_crypto_login(payload)

    def refresh_token(self, payload: RefreshTokenRequest):
        return self._auth_service.refresh_token(payload)

    def logout(self, payload: LogoutRequest):
        return self._auth_service.logout(payload)


auth_service = AuthService()
auth_controller = AuthController(auth_service)


def crypto_challenge_status_endpoint(challengeId: str = Query(...)) -> dict:
    return auth_controller.crypto_challenge_status(challengeId)

router.add_api_route("/login/request-otp", auth_controller.request_login_otp, methods=["POST"])
router.add_api_route("/login/verify-otp", auth_controller.verify_login_otp, methods=["POST"])
router.add_api_route("/crypto/challenge", auth_controller.request_crypto_challenge, methods=["POST"])
router.add_api_route("/crypto/verify", auth_controller.verify_crypto_signature, methods=["POST"])
router.add_api_route("/crypto/challenge-status", crypto_challenge_status_endpoint, methods=["GET"])
router.add_api_route("/crypto/exchange", auth_controller.exchange_crypto_login, methods=["POST"])
router.add_api_route("/token/refresh", auth_controller.refresh_token, methods=["POST"])
router.add_api_route("/logout", auth_controller.logout, methods=["POST"])
