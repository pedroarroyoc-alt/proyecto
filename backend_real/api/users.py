from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, field_validator
from typing import Dict, Optional, List
import uuid
import secrets

from domain.usuarios import UsuarioHumano

router = APIRouter(prefix="/users", tags=["Users"])

# "DB" en memoria (luego lo cambiamos a SQLite/Postgres)
USERS: Dict[str, UsuarioHumano] = {}

# OTP en memoria: email -> otp
PENDING_EMAIL_OTP: Dict[str, str] = {}


# =========================
# Schemas (lo que llega del frontend)
# =========================
class CreateHumanUser(BaseModel):
    email: EmailStr
    nombre: str
    telefono: Optional[str] = ""
    mfaHabilitado: bool = False

    # ✅ valida dominio @uni.pe
    @field_validator("email")
    @classmethod
    def only_uni_pe(cls, v: EmailStr):
        email = str(v).strip().lower()
        if not email.endswith("@uni.pe"):
            raise ValueError("El correo debe ser @uni.pe")
        return email


class VerifyEmailRequest(BaseModel):
    email: EmailStr
    otp: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v: EmailStr):
        return str(v).strip().lower()


# =========================
# Helpers
# =========================
def to_public(u: UsuarioHumano) -> dict:
    # usa tu método del dominio
    return u.obtenerPerfil()


# =========================
# Endpoints
# =========================
@router.post("/human")
def create_human_user(payload: CreateHumanUser):
    email = payload.email.strip().lower()

    # Evitar duplicados por email
    for u in USERS.values():
        if u.email.lower() == email:
            raise HTTPException(status_code=409, detail="Ya existe un usuario con ese email")

    # Crear usuario en estado PENDIENTE (según domain/usuarios.py recomendado)
    user = UsuarioHumano(
        email=email,
        nombre=payload.nombre,
        telefono=payload.telefono or "",
        mfaHabilitado=payload.mfaHabilitado,
    )

    user_id = str(user.id)
    USERS[user_id] = user

    # OTP simulado (6 dígitos)
    otp = f"{secrets.randbelow(1_000_000):06d}"
    PENDING_EMAIL_OTP[email] = otp

    return {
        "user": to_public(user),
        "message": "Usuario creado. Verifica tu correo para activarlo.",
        "otp_simulado": otp,  # ⚠️ SOLO DEMO
    }


@router.post("/verify-email")
def verify_email(payload: VerifyEmailRequest):
    email = str(payload.email).strip().lower()
    otp = (payload.otp or "").strip()

    expected = PENDING_EMAIL_OTP.get(email)
    if not expected:
        raise HTTPException(status_code=404, detail="No hay verificación pendiente para este email")

    if otp != expected:
        raise HTTPException(status_code=401, detail="OTP inválido")

    # Buscar usuario por email
    user_found: Optional[UsuarioHumano] = None
    for u in USERS.values():
        if u.email.lower() == email:
            user_found = u
            break

    if not user_found:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    # Activar
    user_found.marcar_email_verificado()

    # limpiar OTP
    PENDING_EMAIL_OTP.pop(email, None)

    return {"user": to_public(user_found), "message": "Correo verificado. Usuario ACTIVADO."}


@router.get("")
def list_users() -> List[dict]:
    return [to_public(u) for u in USERS.values()]


@router.get("/{user_id}")
def get_user(user_id: str):
    u = USERS.get(user_id)
    if not u:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")
    return to_public(u)
