from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, field_validator

from domain.usuarios import UsuarioHumano
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
            raise ValueError("El correo debe ser @@gmail.com")
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


class EnableMfaRequest(BaseModel):
    mfaHabilitado: bool = True


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

    def __init__(self) -> None:
        self._users: Dict[str, UsuarioHumano] = {}

    def save(self, user: UsuarioHumano) -> UsuarioHumano:
        self._users[str(user.id)] = user
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
        }

        if not email_sent and os.getenv("EXPOSE_OTP_IN_RESPONSE", "false").lower() == "true":
            response["otpDebug"] = otp

        return response



    def verify_email(self, payload: VerifyEmailRequest) -> dict:
        email = str(payload.email).strip().lower()
        otp = (payload.otp or "").strip()

        if not self._otp_manager.verify(email, otp):
            raise UserError(message="OTP inválido", status_code=401)

        user = self._repository.get_by_email(email)
        if not user:
            raise UserError(message="Usuario no encontrado", status_code=404)

        user.marcar_email_verificado()
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

    def update_user_mfa(self, user_id: str, payload: EnableMfaRequest) -> dict:
        user = self._repository.get_by_id(user_id)
        if not user:
            raise UserError(message="Usuario no encontrado", status_code=404)

        user.mfaHabilitado = bool(payload.mfaHabilitado)
        user.actualizar_nivel_confianza()

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

    def start_totp_enrollment(self, user_id: str) -> dict:
        user = self._repository.get_by_id(user_id)
        if not user:
            raise UserError(message="Usuario no encontrado", status_code=404)

        secret = totp_service.generate_secret()
        user.totpSecret = secret
        user.mfaMetodo = "totp_pending"
        recovery_codes = [secrets.token_hex(4) for _ in range(8)]
        user.recoveryCodesHash = [self._password_hasher.hash_password(code) for code in recovery_codes]

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
        self.router.get("")(self.list_users)            # GET /users
        self.router.get("/{user_id}")(self.get_user)    # GET /users/{id}
        self.router.patch("/{user_id}/mfa")(self.update_user_mfa)  # PATCH /users/{id}/mfa
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

    def update_user_mfa(self, user_id: str, payload: EnableMfaRequest) -> dict:
        try:
            return self._service.update_user_mfa(user_id, payload)
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


# =========================
# Wiring (instancias)
# =========================
user_repository = UserRepository()
otp_manager = OtpManager()
password_hasher = PasswordHasher()
user_service = UserService(repository=user_repository, otp_manager=otp_manager, password_hasher=password_hasher)
user_controller = UserController(service=user_service)

router = user_controller.router
