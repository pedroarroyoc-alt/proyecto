from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, field_validator

from domain.usuarios import UsuarioHumano
from services.email_service import send_otp_email


# =========================
# Schemas (request bodies)
# =========================
class CreateHumanUser(BaseModel):
    email: EmailStr
    nombre: str
    telefono: Optional[str] = ""
    mfaHabilitado: bool = False

    @field_validator("email")
    @classmethod
    def only_uni_pe(cls, v: EmailStr) -> str:
        email = str(v).strip().lower()
        if not email.endswith("@gmail.com"):
            raise ValueError("El correo debe ser @@gmail.com")
        return email


class VerifyEmailRequest(BaseModel):
    email: EmailStr
    otp: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr) -> str:
        return str(v).strip().lower()


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
from datetime import datetime, timedelta

class OtpManager:
    def __init__(self):
        self._pending_email_otp: Dict[str, tuple[str, datetime]] = {}

    def generate_for_email(self, email: str) -> str:
        otp = f"{secrets.randbelow(1_000_000):06d}"
        expiry = datetime.utcnow() + timedelta(minutes=5)
        self._pending_email_otp[email.strip().lower()] = (otp, expiry)
        return otp

    def get_expected(self, email: str) -> Optional[str]:
        record = self._pending_email_otp.get(email.strip().lower())
        if not record:
            return None

        otp, expiry = record
        if datetime.utcnow() > expiry:
            self._pending_email_otp.pop(email.strip().lower(), None)
            return None

        return otp

    def clear(self, email: str) -> None:
        self._pending_email_otp.pop(email.strip().lower(), None)

# =========================
# Service (lógica negocio)
# =========================
class UserService:
    def __init__(self, repository: UserRepository, otp_manager: OtpManager) -> None:
        self._repository = repository
        self._otp_manager = otp_manager

    def create_human_user(self, payload: CreateHumanUser) -> dict:
        email = str(payload.email).strip().lower()

        # Evitar duplicados por email (igual que tu for en USERS.values())
        if self._repository.get_by_email(email):
            raise UserError(message="Ya existe un usuario con ese email", status_code=409)

        user = UsuarioHumano(
            email=email,
            nombre=payload.nombre,
            telefono=payload.telefono or "",
            mfaHabilitado=payload.mfaHabilitado,
        )

        self._repository.save(user)

        otp = self._otp_manager.generate_for_email(email)

        try:
            send_otp_email(email, otp)
        except Exception as exc:
            # No bloqueamos el registro si falla el SMTP en entorno local.
            print(f"[WARN] No se pudo enviar OTP a {email}: {exc}")
        return {
             "user": self.to_public(user),
            "message": "Usuario creado. Revisa tu correo para el código de verificación.",
        }


    def verify_email(self, payload: VerifyEmailRequest) -> dict:
        email = str(payload.email).strip().lower()
        otp = (payload.otp or "").strip()

        expected = self._otp_manager.get_expected(email)
        if not expected:
            raise UserError(
                message="No hay verificación pendiente para este email",
                status_code=404,
            )

        if otp != expected:
            raise UserError(message="OTP inválido", status_code=401)

        user = self._repository.get_by_email(email)
        if not user:
            raise UserError(message="Usuario no encontrado", status_code=404)

        user.marcar_email_verificado()
        self._otp_manager.clear(email)

        return {
            "user": self.to_public(user),
            "message": "Correo verificado. Usuario ACTIVADO.",
        }

    def list_users(self) -> List[dict]:
        return [self.to_public(u) for u in self._repository.list_all()]

    def get_user(self, user_id: str) -> dict:
        user = self._repository.get_by_id(user_id)
        if not user:
            raise UserError(message="Usuario no encontrado", status_code=404)
        return self.to_public(user)

    @staticmethod
    def to_public(u: UsuarioHumano) -> dict:
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
user_service = UserService(repository=user_repository, otp_manager=otp_manager)
user_controller = UserController(service=user_service)

router = user_controller.router
