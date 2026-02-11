from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr

# reutiliza tu lógica actual (ajusta imports según tu proyecto)
from services.email_service import send_otp_email
# si ya tienes un servicio OTP (guardar/validar), úsalo.
# aquí te dejo una versión simple en memoria para demo:
import secrets
from datetime import datetime, timedelta

router = APIRouter(prefix="/auth", tags=["auth"])

# ===== demo store en memoria (solo para local) =====
_otp_store = {}  # email -> {"otp": "...", "exp": datetime}

class LoginRequest(BaseModel):
    email: EmailStr

class LoginVerify(BaseModel):
    email: EmailStr
    otp: str

@router.post("/login/request-otp")
def request_login_otp(payload: LoginRequest):
    email = payload.email.lower().strip()

    otp = f"{secrets.randbelow(10**6):06d}"
    _otp_store[email] = {"otp": otp, "exp": datetime.utcnow() + timedelta(minutes=10)}

    try:
        send_otp_email(email, otp)
    except Exception as e:
        # si falla smtp, devuelve error real
        raise HTTPException(status_code=500, detail=f"No se pudo enviar OTP: {e}")

    return {"message": "OTP enviado", "emailSent": True}

@router.post("/login/verify-otp")
def verify_login_otp(payload: LoginVerify):
    email = payload.email.lower().strip()
    otp = payload.otp.strip()

    rec = _otp_store.get(email)
    if not rec:
        raise HTTPException(status_code=400, detail="No hay OTP pendiente para este correo")

    if datetime.utcnow() > rec["exp"]:
        _otp_store.pop(email, None)
        raise HTTPException(status_code=400, detail="OTP expirado")

    if otp != rec["otp"]:
        raise HTTPException(status_code=400, detail="OTP inválido")

    _otp_store.pop(email, None)

    # demo: “sesión” simple (luego reemplazas por JWT)
    return {"message": "Acceso verificado", "token": "demo-token", "user": {"email": email}}
