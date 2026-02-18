from __future__ import annotations

import json
import os
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, HTTPException, Query 
from pydantic import BaseModel, EmailStr, field_validator

from domain.usuarios import EstadoUsuario, UsuarioHumano
from services.audit_service import get_audit_service
from services.email_service import send_otp_email
from services.security_service import PasswordHasher, otp_service, totp_service


# =========================
# Schemas (request bodies)
# =========================
class CreateHumanUser(BaseModel):
    email: EmailStr
    nombre: str
    password: str
    telefono: Optional[str] = ""
    mfaHabilitado: bool = False

    @field_validator("email")
    @classmethod
    def only_uni_pe(cls, v: EmailStr) -> str:
        email = str(v).strip().lower()
        if not email.endswith("@gmail.com"):
            raise ValueError("El correo debe ser @gmail.com")
        return email

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        pwd = (v or "").strip()
        if len(pwd) < 8:
            raise ValueError("La contraseña debe tener al menos 8 caracteres")
        return pwd


class VerifyEmailRequest(BaseModel):
    email: EmailStr
    otp: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> str:
        return str(v).strip().lower()


class ResendVerificationOtpRequest(BaseModel):
    email: EmailStr

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> str:
        return str(v).strip().lower()


class EnableMfaRequest(BaseModel):
    mfaHabilitado: bool = True


class UpdateCryptoSignatureMethodRequest(BaseModel):
    habilitado: bool = False
    publicKeyPem: str = ""

    @field_validator("publicKeyPem")
    @classmethod
    def normalize_public_key(cls, v: str) -> str:
        return (v or "").strip()


class ConfirmTotpEnrollmentRequest(BaseModel):
    codigo: str


class VerifyRecoveryCodeRequest(BaseModel):
    codigo: str


# =========================
# Errores de dominio/servicio
# =========================
@dataclass
class UserError(Exception):
    message: str
    status_code: int


# =========================
# Repository (memoria)
# =========================
class UserRepository:
    """Equivalente a USERS: Dict[str, UsuarioHumano]"""

    def __init__(self, file_path: Optional[str] = None) -> None:
        default_path = Path(__file__).resolve().parents[1] / "users_store.json"
        configured = file_path or os.getenv("USERS_STORE_PATH", str(default_path))
        self._file_path = Path(configured)
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        self._users: Dict[str, UsuarioHumano] = {}
        self._load()

    @staticmethod
    def _serialize_user(user: UsuarioHumano) -> dict:
        return {
            "id": str(user.id),
            "email": user.email,
            "nombre": user.nombre,
            "telefono": user.telefono,
            "estado": user.estado.value if isinstance(user.estado, EstadoUsuario) else str(user.estado),
            "emailVerificado": bool(user.emailVerificado),
            "mfaHabilitado": bool(user.mfaHabilitado),
            "mfaMetodo": user.mfaMetodo,
            "totpSecret": user.totpSecret,
            "cryptoAuthEnabled": bool(getattr(user, "cryptoAuthEnabled", False)),
            "cryptoPublicKeyPem": str(getattr(user, "cryptoPublicKeyPem", "") or ""),
            "recoveryCodesHash": list(getattr(user, "recoveryCodesHash", [])),
            "passwordHash": user.passwordHash,
            "fechaCreacion": user.fechaCreacion.isoformat(),
            "nivelConfianza": int(getattr(user, "nivelConfianza", 0)),
        }

    @staticmethod
    def _deserialize_user(raw: dict) -> UsuarioHumano:
        created_raw = raw.get("fechaCreacion")
        try:
            created_at = datetime.fromisoformat(created_raw) if created_raw else datetime.now(timezone.utc)
        except ValueError:
            created_at = datetime.now(timezone.utc)

        user = UsuarioHumano(
            email=str(raw.get("email", "")).strip().lower(),
            nombre=str(raw.get("nombre", "")).strip(),
            telefono=str(raw.get("telefono", "")).strip(),
            mfaHabilitado=bool(raw.get("mfaHabilitado", False)),
            mfaMetodo=str(raw.get("mfaMetodo", "none") or "none"),
            totpSecret=str(raw.get("totpSecret", "") or ""),
            cryptoAuthEnabled=bool(raw.get("cryptoAuthEnabled", False)),
            cryptoPublicKeyPem=str(raw.get("cryptoPublicKeyPem", "") or ""),
            recoveryCodesHash=[str(x) for x in (raw.get("recoveryCodesHash") or [])],
            passwordHash=str(raw.get("passwordHash", "") or ""),
            emailVerificado=bool(raw.get("emailVerificado", False)),
            estado=EstadoUsuario(str(raw.get("estado", EstadoUsuario.PENDIENTE.value))),
            fechaCreacion=created_at,
            id=uuid.UUID(str(raw.get("id"))) if raw.get("id") else uuid.uuid4(),
        )
        user.actualizar_nivel_confianza()
        return user

    def _load(self) -> None:
        if not self._file_path.exists():
            return

        try:
            payload = json.loads(self._file_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(f"[WARN] users store corrupto: {self._file_path}")
            return

        users: Dict[str, UsuarioHumano] = {}
        for raw in payload.get("users", []):
            try:
                user = self._deserialize_user(raw)
            except Exception as exc:
                print(f"[WARN] usuario inválido en store: {exc}")
                continue
            users[str(user.id)] = user

        self._users = users

    def _persist(self) -> None:
        payload = {"users": [self._serialize_user(u) for u in self._users.values()]}
        self._file_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def save(self, user: UsuarioHumano) -> UsuarioHumano:
        self._users[str(user.id)] = user
        self._persist()
        return user

    def list_all(self) -> List[UsuarioHumano]:
        return list(self._users.values())

    def get_by_id(self, user_id: str) -> Optional[UsuarioHumano]:
        return self._users.get(user_id)

    def get_by_email(self, email: str) -> Optional[UsuarioHumano]:
        normalized = email.strip().lower()
        for u in self._users.values():
            if u.email.lower() == normalized:
                return u
        return None


# =========================
# OTP Manager (memoria)
# =========================
class OtpManager:
    def generate_for_email(self, email: str) -> str:
        return otp_service.create(email=email.strip().lower(), purpose="email_verification", ttl_seconds=300)

    def get_expected(self, email: str) -> Optional[str]:
        # El OTP ya no se guarda en claro para producción.
        return None       

    def verify(self, email: str, otp: str) -> bool:
        ok, _ = otp_service.verify(email=email.strip().lower(), purpose="email_verification", otp=otp)
        return ok

    def clear(self, email: str) -> None:
        otp_service.clear(email=email.strip().lower(), purpose="email_verification")

# =========================
# Service (lógica negocio)
# =========================
class UserService:
    def __init__(self, repository: UserRepository, otp_manager: OtpManager, password_hasher: PasswordHasher) -> None:
        self._repository = repository
        self._otp_manager = otp_manager
        self._password_hasher = password_hasher
        self._audit = get_audit_service()

    @staticmethod
    def _validate_crypto_public_key_pem(public_key_pem: str) -> str:
        normalized = (public_key_pem or "").strip()
        if not normalized:
            raise UserError(message="La llave publica es obligatoria para habilitar firma criptografica", status_code=400)

        if "BEGIN PUBLIC KEY" not in normalized:
            raise UserError(message="Formato invalido de llave publica (PEM)", status_code=400)

        try:
            loaded_key = serialization.load_pem_public_key(normalized.encode("utf-8"))
        except Exception as exc:
            raise UserError(message=f"No se pudo leer la llave publica: {exc}", status_code=400) from exc

        if not isinstance(loaded_key, rsa.RSAPublicKey):
            raise UserError(message="Solo se soportan llaves RSA para firma", status_code=400)

        return normalized

    def create_human_user(self, payload: CreateHumanUser) -> dict:
        email = str(payload.email).strip().lower()

        # Evitar duplicados por email (igual que tu for en USERS.values())
        existing_user = self._repository.get_by_email(email)
        if existing_user:
            if existing_user.emailVerificado:
                raise UserError(message="Ya existe un usuario con ese email", status_code=409)

            otp = self._otp_manager.generate_for_email(email)
            email_sent = True
            message = "Esta cuenta ya existe, pero aún no está verificada. Te reenviamos un OTP."
            try:
                send_otp_email(email, otp)
            except Exception as exc:
                email_sent = False
                message = (
                    "La cuenta existe y sigue pendiente de verificación, "
                    "pero no se pudo enviar el OTP por correo."
                )
                print(f"[WARN] No se pudo reenviar OTP a {email}: {exc}")

            response = {
                "user": self.to_public(existing_user),
                "message": message,
                "emailSent": email_sent,
                "alreadyExists": True,
                "requiresEmailVerification": True,
            }
            if not email_sent and os.getenv("EXPOSE_OTP_IN_RESPONSE", "false").lower() == "true":
                response["otpDebug"] = otp
            return response

        user = UsuarioHumano(
            email=email,
            nombre=payload.nombre,
            telefono=payload.telefono or "",
            mfaHabilitado=payload.mfaHabilitado,
            passwordHash=self._password_hasher.hash_password(payload.password),
        )

        self._repository.save(user)
        self._audit.registrar_evento(
            usuario_id=str(user.id),
            accion="USER_CREATED",
            recurso="/users/human",
            metadatos={"email": email, "mfa": payload.mfaHabilitado},
        )

        otp = self._otp_manager.generate_for_email(email)
        email_sent = True
        message = "Usuario creado. Revisa tu correo para el código de verificación."

        try:
            send_otp_email(email, otp)
        except Exception as exc:
            email_sent = False
            message = (
                "Usuario creado, pero no se pudo enviar el OTP por correo. "
                "Verifica la configuración SMTP del backend."
            )
            print(f"[WARN] No se pudo enviar OTP a {email}: {exc}")
        response = {
            "user": self.to_public(user),
            "message": message,
            "emailSent": email_sent,
            "requiresEmailVerification": True,
        }

        if not email_sent and os.getenv("EXPOSE_OTP_IN_RESPONSE", "false").lower() == "true":
            response["otpDebug"] = otp

        return response



    def verify_email(self, payload: VerifyEmailRequest) -> dict:
        email = str(payload.email).strip().lower()
        otp = (payload.otp or "").strip()

        if not otp:
            raise UserError(message="OTP requerido", status_code=400)

        if not self._otp_manager.verify(email, otp):
            raise UserError(message="OTP inválido", status_code=401)

        user = self._repository.get_by_email(email)
        if not user:
            raise UserError(message="Usuario no encontrado", status_code=404)

        user.marcar_email_verificado()
        self._otp_manager.clear(email)
        self._repository.save(user)
        self._audit.registrar_evento(
            usuario_id=str(user.id),
            accion="EMAIL_VERIFIED",
            recurso="/users/verify-email",
            metadatos={"email": email},
        )

        return {
            "user": self.to_public(user),
            "message": "Correo verificado. Usuario ACTIVADO.",
        }

    def resend_verification_otp(self, payload: ResendVerificationOtpRequest) -> dict:
        email = str(payload.email).strip().lower()
        user = self._repository.get_by_email(email)
        if not user:
            raise UserError(message="Usuario no encontrado", status_code=404)
        if bool(user.emailVerificado):
            raise UserError(message="La cuenta ya está verificada", status_code=409)

        otp = self._otp_manager.generate_for_email(email)
        email_sent = True
        message = "Te reenviamos el OTP de verificación."

        try:
            send_otp_email(email, otp)
        except Exception as exc:
            email_sent = False
            message = "No se pudo enviar el OTP por correo. Verifica la configuración SMTP."
            print(f"[WARN] No se pudo reenviar OTP a {email}: {exc}")

        response = {
            "user": self.to_public(user),
            "message": message,
            "emailSent": email_sent,
            "requiresEmailVerification": True,
        }
        if not email_sent and os.getenv("EXPOSE_OTP_IN_RESPONSE", "false").lower() == "true":
            response["otpDebug"] = otp
        return response
    
    def update_user_mfa(self, user_id: str, payload: EnableMfaRequest) -> dict:
        user = self._repository.get_by_id(user_id)
        if not user:
            raise UserError(message="Usuario no encontrado", status_code=404)

        user.mfaHabilitado = bool(payload.mfaHabilitado)
        user.actualizar_nivel_confianza()
        self._repository.save(user)

        self._audit.registrar_evento(
            usuario_id=str(user.id),
            accion="USER_MFA_UPDATED",
            recurso=f"/users/{user_id}/mfa",
            metadatos={"mfaHabilitado": user.mfaHabilitado},
        )

        return {
            "user": self.to_public(user),
            "message": "Configuración MFA actualizada.",
        }

    def update_crypto_signature_method(self, user_id: str, payload: UpdateCryptoSignatureMethodRequest) -> dict:
        user = self._repository.get_by_id(user_id)
        if not user:
            raise UserError(message="Usuario no encontrado", status_code=404)

        enable = bool(payload.habilitado)
        if enable:
            user.cryptoPublicKeyPem = self._validate_crypto_public_key_pem(payload.publicKeyPem)
            user.cryptoAuthEnabled = True
        else:
            user.cryptoAuthEnabled = False
            if payload.publicKeyPem:
                user.cryptoPublicKeyPem = self._validate_crypto_public_key_pem(payload.publicKeyPem)

        user.actualizar_nivel_confianza()
        self._repository.save(user)

        self._audit.registrar_evento(
            usuario_id=str(user.id),
            accion="USER_CRYPTO_SIGNATURE_METHOD_UPDATED",
            recurso=f"/users/{user_id}/methods/crypto-signature",
            metadatos={
                "habilitado": user.cryptoAuthEnabled,
                "publicKeyConfigured": bool(user.cryptoPublicKeyPem),
            },
        )

        return {
            "user": self.to_public(user),
            "message": "Metodo de firma criptografica actualizado.",
        }

    def start_totp_enrollment(self, user_id: str) -> dict:
        user = self._repository.get_by_id(user_id)
        if not user:
            raise UserError(message="Usuario no encontrado", status_code=404)

        secret = totp_service.generate_secret()
        user.totpSecret = secret
        user.mfaMetodo = "totp_pending"
        recovery_codes = [secrets.token_hex(4) for _ in range(8)]
        user.recoveryCodesHash = [self._password_hasher.hash_password(code) for code in recovery_codes]
        self._repository.save(user)

        self._audit.registrar_evento(
            usuario_id=str(user.id),
            accion="MFA_TOTP_ENROLLMENT_STARTED",
            recurso=f"/users/{user_id}/mfa/totp/enroll",
            metadatos={"method": "totp"},
        )

        return {
            "message": "Escanea el QR/URI y confirma con un código TOTP.",
            "otpauthUri": totp_service.provisioning_uri(email=user.email, secret=secret),
            "secret": secret,
            "recoveryCodes": recovery_codes,
        }

    def confirm_totp_enrollment(self, user_id: str, payload: ConfirmTotpEnrollmentRequest) -> dict:
        user = self._repository.get_by_id(user_id)
        if not user:
            raise UserError(message="Usuario no encontrado", status_code=404)
        if not user.totpSecret:
            raise UserError(message="No hay enrolamiento TOTP pendiente", status_code=400)
        if not totp_service.verify(secret=user.totpSecret, code=payload.codigo):
            raise UserError(message="Código TOTP inválido", status_code=401)

        user.mfaHabilitado = True
        user.mfaMetodo = "totp"
        user.actualizar_nivel_confianza()
        self._repository.save(user)
        self._audit.registrar_evento(
            usuario_id=str(user.id),
            accion="MFA_TOTP_ENABLED",
            recurso=f"/users/{user_id}/mfa/totp/confirm",
            metadatos={"method": "totp"},
        )
        return {"message": "MFA TOTP habilitado", "user": self.to_public(user)}

    def verify_recovery_code(self, user_id: str, payload: VerifyRecoveryCodeRequest) -> dict:
        user = self._repository.get_by_id(user_id)
        if not user:
            raise UserError(message="Usuario no encontrado", status_code=404)
        incoming = (payload.codigo or "").strip()
        for hashed in list(getattr(user, "recoveryCodesHash", [])):
            if self._password_hasher.verify_password(incoming, hashed):
                user.recoveryCodesHash.remove(hashed)
                self._repository.save(user)
                self._audit.registrar_evento(
                    usuario_id=str(user.id),
                    accion="MFA_RECOVERY_CODE_USED",
                    recurso=f"/users/{user_id}/mfa/recovery/verify",
                    metadatos={"remainingCodes": len(user.recoveryCodesHash)},
                )
                return {"message": "Recovery code válido"}
        raise UserError(message="Recovery code inválido", status_code=401)

    def list_users(self) -> List[dict]:
        return [self.to_public(u) for u in self._repository.list_all()]

    def get_user(self, user_id: str) -> dict:
        user = self._repository.get_by_id(user_id)
        if not user:
            raise UserError(message="Usuario no encontrado", status_code=404)
        return self.to_public(user)

    @staticmethod
    def to_public(u: UsuarioHumano) -> dict:
        # Recalcula el nivel para reflejar correctamente el estado actual
        # incluso para usuarios creados antes de introducir esta regla.
        u.actualizar_nivel_confianza()
        return u.obtenerPerfil()


# =========================
# Controller (FastAPI Router)
# =========================
class UserController:
    def __init__(self, service: UserService) -> None:
        self._service = service
        self.router = APIRouter(prefix="/users", tags=["Users"])
        self._register_routes()

    def _register_routes(self) -> None:
        self.router.post("/human")(self.create_human_user)
        self.router.post("/verify-email")(self.verify_email)
        self.router.post("/resend-verification-otp")(self.resend_verification_otp)
        self.router.get("")(self.list_users)            # GET /users
        self.router.get("/by-email")(self.get_user_by_email)  # GET /users/by-email?email=
        self.router.get("/{user_id}")(self.get_user)    # GET /users/{id}
        self.router.patch("/{user_id}/mfa")(self.update_user_mfa)  # PATCH /users/{id}/mfa
        self.router.patch("/{user_id}/methods/crypto-signature")(self.update_crypto_signature_method)
        self.router.post("/{user_id}/mfa/totp/enroll")(self.start_totp_enrollment)
        self.router.post("/{user_id}/mfa/totp/confirm")(self.confirm_totp_enrollment)
        self.router.post("/{user_id}/mfa/recovery/verify")(self.verify_recovery_code)

    def create_human_user(self, payload: CreateHumanUser) -> dict:
        try:
            return self._service.create_human_user(payload)
        except UserError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    def verify_email(self, payload: VerifyEmailRequest) -> dict:
        try:
            return self._service.verify_email(payload)
        except UserError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    def resend_verification_otp(self, payload: ResendVerificationOtpRequest) -> dict:
        try:
            return self._service.resend_verification_otp(payload)
        except UserError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
    
    def update_user_mfa(self, user_id: str, payload: EnableMfaRequest) -> dict:
        try:
            return self._service.update_user_mfa(user_id, payload)
        except UserError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    def update_crypto_signature_method(self, user_id: str, payload: UpdateCryptoSignatureMethodRequest) -> dict:
        try:
            return self._service.update_crypto_signature_method(user_id, payload)
        except UserError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    def start_totp_enrollment(self, user_id: str) -> dict:
        try:
            return self._service.start_totp_enrollment(user_id)
        except UserError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    def confirm_totp_enrollment(self, user_id: str, payload: ConfirmTotpEnrollmentRequest) -> dict:
        try:
            return self._service.confirm_totp_enrollment(user_id, payload)
        except UserError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    def verify_recovery_code(self, user_id: str, payload: VerifyRecoveryCodeRequest) -> dict:
        try:
            return self._service.verify_recovery_code(user_id, payload)
        except UserError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc
     
    def list_users(self) -> List[dict]:
        return self._service.list_users()

    def get_user(self, user_id: str) -> dict:
        try:
            return self._service.get_user(user_id)
        except UserError as exc:
            raise HTTPException(status_code=exc.status_code, detail=exc.message) from exc

    def get_user_by_email(self, email: EmailStr = Query(...)) -> dict:
        user = self._service._repository.get_by_email(str(email).strip().lower())
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado")
        return self._service.to_public(user)

# =========================
# Wiring (instancias)
# =========================
user_repository = UserRepository()
otp_manager = OtpManager()
password_hasher = PasswordHasher()
user_service = UserService(repository=user_repository, otp_manager=otp_manager, password_hasher=password_hasher)
user_controller = UserController(service=user_service)

router = user_controller.router
