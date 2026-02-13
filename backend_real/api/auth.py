import os
import secrets
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr

# reutiliza tu lógica actual (ajusta imports según tu proyecto)
from services.audit_service import get_audit_service
from services.email_service import EmailDeliveryError, send_otp_email
from api.users import password_hasher, user_repository

router = APIRouter(prefix="/auth", tags=["auth"])

# ===== demo store en memoria (solo para local) =====
_otp_store = {}  # email -> {"otp": "...", "exp": datetime}


class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class LoginVerify(BaseModel):
    email: EmailStr
    otp: str


class OTPStoreService:
    def __init__(self, otp_store):
        self._otp_store = otp_store

    def create_for_email(self, email):
        otp = f"{secrets.randbelow(10**6):06d}"
        self._otp_store[email] = {
            "otp": otp,
            "exp": datetime.utcnow() + timedelta(minutes=10),
        }
        return otp

    def get_for_email(self, email):
        return self._otp_store.get(email)

    def remove_for_email(self, email):
        self._otp_store.pop(email, None)



class AuthService:
    def __init__(self, otp_store_service, users_repo, pwd_hasher):
        self._otp_store_service = otp_store_service
        self._users_repo = users_repo
        self._pwd_hasher = pwd_hasher
        self._audit = get_audit_service()

    def normalize_email(self, email):
        return email.lower().strip()

    def normalize_otp(self, otp):
        return otp.strip()

    def build_request_otp_response(self, message, email_sent, otp):
        response = {"message": message, "emailSent": email_sent}
        if not email_sent and os.getenv("EXPOSE_OTP_IN_RESPONSE", "false").lower() == "true":
            response["otpDebug"] = otp
        return response

    def send_otp(self, email, otp):
        send_otp_email(email, otp)

    def request_login_otp(self, payload):
        email = self.normalize_email(payload.email)
        password = (payload.password or "").strip()

        user = self._users_repo.get_by_email(email)
        if not user:
            raise HTTPException(status_code=401, detail="Credenciales inválidas")

        if not user.autenticar():
            raise HTTPException(status_code=403, detail="Usuario no activo o correo no verificado")

        if not self._pwd_hasher.verify_password(password, user.passwordHash):
            raise HTTPException(status_code=401, detail="Credenciales inválidas")
        
        otp = self._otp_store_service.create_for_email(email)

        email_sent = True
        message = "OTP enviado"

        try:
            self.send_otp(email, otp)
        except EmailDeliveryError as exc:
            email_sent = False
            message = "No se pudo enviar el OTP por correo. Revisa la configuración SMTP."
            print(f"[WARN] No se pudo enviar OTP de login a {email}: {exc}")

        self._audit.registrar_evento(
            usuario_id=email,
            accion="LOGIN_OTP_REQUESTED",
            recurso="/auth/login/request-otp",
            metadatos={"emailSent": email_sent},
        )

        return self.build_request_otp_response(message, email_sent, otp)

    def verify_login_otp(self, payload):
        email = self.normalize_email(payload.email)
        otp = self.normalize_otp(payload.otp)

        rec = self._otp_store_service.get_for_email(email)
        if not rec:
            raise HTTPException(status_code=400, detail="No hay OTP pendiente para este correo")

        if datetime.utcnow() > rec["exp"]:
            self._otp_store_service.remove_for_email(email)
            raise HTTPException(status_code=400, detail="OTP expirado")

        if otp != rec["otp"]:
            raise HTTPException(status_code=400, detail="OTP inválido")

        self._otp_store_service.remove_for_email(email)
        self._audit.registrar_evento(
            usuario_id=email,
            accion="LOGIN_VERIFIED",
            recurso="/auth/login/verify-otp",
            metadatos={"auth": "otp"},
        )

        # demo: “sesión” simple (luego reemplazas por JWT)
        return {"message": "Acceso verificado", "token": "demo-token", "user": {"email": email}}


class AuthController:
    def __init__(self, auth_service):
        self._auth_service = auth_service

    def request_login_otp(self, payload: LoginRequest):
        return self._auth_service.request_login_otp(payload)

    def verify_login_otp(self, payload: LoginVerify):
        return self._auth_service.verify_login_otp(payload)


otp_store_service = OTPStoreService(_otp_store)
auth_service = AuthService(otp_store_service, user_repository, password_hasher)
auth_controller = AuthController(auth_service)

router.add_api_route(
    "/login/request-otp",
    auth_controller.request_login_otp,
    methods=["POST"],
)
router.add_api_route(
    "/login/verify-otp",
    auth_controller.verify_login_otp,
    methods=["POST"],
)
