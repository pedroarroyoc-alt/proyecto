import os
from datetime import datetime

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, EmailStr, field_validator

# reutiliza tu lógica actual (ajusta imports según tu proyecto)
from services.audit_service import get_audit_service
from services.email_service import EmailDeliveryError, send_otp_email
from services.security_service import otp_service, rate_limiter, token_service, totp_service

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


class AuthService:
    def __init__(self):
        self._users_repo = user_repository
        self._pwd_hasher = password_hasher
        self._audit = get_audit_service()

    @staticmethod
    def _normalize_otp(otp: str) -> str:
        return (otp or "").strip()

    @staticmethod
    def _expose_debug_otp() -> bool:
        return os.getenv("EXPOSE_OTP_IN_RESPONSE", "false").lower() == "true"

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
            raise HTTPException(status_code=401, detail="Credenciales inválidas")

        if not user.autenticar():
            raise HTTPException(status_code=403, detail="Usuario no activo o correo no verificado")

        if not self._pwd_hasher.verify_password(password, user.passwordHash):
            raise HTTPException(status_code=401, detail="Credenciales inválidas")

        mfa_required = bool(user.mfaHabilitado) and getattr(user, "mfaMetodo", "none") == "totp"

        response = {
            "message": "Credenciales válidas",
            "mfaRequired": mfa_required,
            "mfaMethod": getattr(user, "mfaMetodo", "none"),
            "emailSecondFactorRequired": not mfa_required,
        }

        if mfa_required:
            self._audit.registrar_evento(
                usuario_id=email,
                accion="LOGIN_CHALLENGE_TOTP_REQUESTED",
                recurso="/auth/login/request-otp",
                metadatos={"mfaMethod": "totp"},
            )
            return response

        otp = otp_service.create(email=email, purpose="login_email", ttl_seconds=300)
        email_sent = True
        try:
            send_otp_email(email, otp)
        except EmailDeliveryError as exc:
            email_sent = False
            response["message"] = "No se pudo enviar OTP por correo"
            print(f"[WARN] No se pudo enviar OTP de login a {email}: {exc}")

        response["emailSent"] = email_sent
        if not email_sent and self._expose_debug_otp():
            response["otpDebug"] = otp
        
        self._audit.registrar_evento(
            usuario_id=email,
            accion="LOGIN_OTP_REQUESTED",
            recurso="/auth/login/request-otp",
            metadatos={"emailSent": email_sent, "mfaRequired": mfa_required},
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

        if bool(user.mfaHabilitado) and getattr(user, "mfaMetodo", "none") == "totp":
            if totp_service.verify(secret=user.totpSecret, code=code):
                tokens = token_service.issue_tokens(email)
                self._audit.registrar_evento(
                    usuario_id=email,
                    accion="LOGIN_VERIFIED_TOTP",
                    recurso="/auth/login/verify-otp",
                    metadatos={"mfaMethod": "totp", "at": datetime.utcnow().isoformat()},
                )
                return {"message": "Acceso verificado por TOTP", "user": {"email": email}, **tokens}

            # fallback recovery code
            for hashed in list(getattr(user, "recoveryCodesHash", [])):
                if password_hasher.verify_password(code, hashed):
                    user.recoveryCodesHash.remove(hashed)
                    tokens = token_service.issue_tokens(email)
                    self._audit.registrar_evento(
                        usuario_id=email,
                        accion="LOGIN_VERIFIED_RECOVERY",
                        recurso="/auth/login/verify-otp",
                        metadatos={"remainingCodes": len(user.recoveryCodesHash)},
                    )
                    return {"message": "Acceso verificado por recovery code", "user": {"email": email}, **tokens}
            raise HTTPException(status_code=400, detail="Código TOTP/Recovery inválido")

        ok, reason = otp_service.verify(email=email, purpose="login_email", otp=code)
        if not ok:
            raise HTTPException(status_code=400, detail=reason)

        tokens = token_service.issue_tokens(email)
        self._audit.registrar_evento(
            usuario_id=email,
            accion="LOGIN_VERIFIED_EMAIL_OTP",
            recurso="/auth/login/verify-otp",
            metadatos={"auth": "otp"},
        )
        return {"message": "Acceso verificado", "user": {"email": email}, **tokens}
    
    def refresh_token(self, payload: RefreshTokenRequest):
        try:
            tokens = token_service.refresh(payload.refreshToken)
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        return {"message": "Token renovado", **tokens}

    def logout(self, payload: LogoutRequest):
        token_service.revoke_refresh(payload.refreshToken)
        return {"message": "Sesión revocada"}


class AuthController:
    def __init__(self, auth_service: AuthService):
        self._auth_service = auth_service

    def request_login_otp(self, payload: LoginRequest):
        return self._auth_service.request_login_otp(payload)

    def verify_login_otp(self, payload: LoginVerify):
        return self._auth_service.verify_login_otp(payload)

    def refresh_token(self, payload: RefreshTokenRequest):
        return self._auth_service.refresh_token(payload)

    def logout(self, payload: LogoutRequest):
        return self._auth_service.logout(payload)


auth_service = AuthService()
auth_controller = AuthController(auth_service)

router.add_api_route("/login/request-otp", auth_controller.request_login_otp, methods=["POST"])
router.add_api_route("/login/verify-otp", auth_controller.verify_login_otp, methods=["POST"])
router.add_api_route("/token/refresh", auth_controller.refresh_token, methods=["POST"])
router.add_api_route("/logout", auth_controller.logout, methods=["POST"])