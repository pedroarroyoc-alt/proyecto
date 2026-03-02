from __future__ import annotations

import os

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware

from api.audit import AuditController
from api.auth import AuthController, AuthService
from api.users import OtpManager, UserController, UserRepository, UserService
from services.audit_service import AuditService
from services.email_service import EmailService
from services.faceid_service import FaceIdService
from services.request_context import RequestContextStore
from services.security_service import SecurityServices


class EnvironmentConfig:
    @staticmethod
    def load() -> None:
        load_dotenv(".env")


class HealthController:
    @staticmethod
    def health() -> dict[str, bool | str]:
        return {"ok": True, "service": "cryptolock-api"}


class ApplicationContainer:
    def __init__(self) -> None:
        self.request_context_store = RequestContextStore()
        self.security_services = SecurityServices()
        self.user_repository = UserRepository()
        self.otp_manager = OtpManager(self.security_services.otp_service)
        self.email_service = EmailService()
        self.faceid_service = FaceIdService()
        self.audit_service = AuditService(request_context_store=self.request_context_store)

        self.user_service = UserService(
            repository=self.user_repository,
            otp_manager=self.otp_manager,
            password_hasher=self.security_services.password_hasher,
            audit_service=self.audit_service,
            faceid_service=self.faceid_service,
            email_service=self.email_service,
            totp_service=self.security_services.totp_service,
        )

        self.auth_service = AuthService(
            users_repo=self.user_repository,
            password_hasher=self.security_services.password_hasher,
            audit_service=self.audit_service,
            email_service=self.email_service,
            faceid_service=self.faceid_service,
            otp_service=self.security_services.otp_service,
            rate_limiter=self.security_services.rate_limiter,
            security_store=self.security_services.store,
            token_service=self.security_services.token_service,
            totp_service=self.security_services.totp_service,
        )

        self.user_controller = UserController(service=self.user_service)
        self.auth_controller = AuthController(self.auth_service)
        self.audit_controller = AuditController(self.audit_service)


class CryptoLockAppFactory:
    def __init__(self, container: ApplicationContainer) -> None:
        self._container = container
        self._app = FastAPI(title="CryptoLock Backend", version="0.1.0")

    @staticmethod
    def _extract_client_ip(request: Request) -> str:
        x_forwarded_for = request.headers.get("x-forwarded-for", "").strip()
        if x_forwarded_for:
            candidate = x_forwarded_for.split(",")[0].strip()
            if candidate:
                return candidate

        x_real_ip = request.headers.get("x-real-ip", "").strip()
        if x_real_ip:
            return x_real_ip

        if request.client and request.client.host:
            return request.client.host

        return "0.0.0.0"

    def configure_middleware(self) -> "CryptoLockAppFactory":
        raw_origins = os.getenv(
            "CORS_ALLOW_ORIGINS",
            (
                "http://localhost:3000,"
                "http://127.0.0.1:3000,"
                "http://localhost:5500,"
                "http://127.0.0.1:5500"
            ),
        ).strip()
        allow_origins = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]

        allow_origin_regex = os.getenv(
            "CORS_ALLOW_ORIGIN_REGEX",
            (
                r"^https?://("
                r"localhost|127\.0\.0\.1|"
                r"192\.168\.\d{1,3}\.\d{1,3}|"
                r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
                r"172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}"
                r")(:\d+)?$|^null$"
            ),
        )
        self._app.add_middleware(
            CORSMiddleware,
            allow_origins=allow_origins,
            allow_origin_regex=allow_origin_regex,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["*"],
        )

        @self._app.middleware("http")
        async def attach_request_context(request: Request, call_next):
            self._container.request_context_store.set_context(
                client_ip=self._extract_client_ip(request),
                headers={k.lower(): v for k, v in request.headers.items()},
            )
            try:
                response = await call_next(request)
            finally:
                self._container.request_context_store.clear_context()
            return response

        return self

    def configure_routes(self) -> "CryptoLockAppFactory":
        self._app.get("/health")(HealthController.health)
        self._app.include_router(self._container.user_controller.router)
        self._app.include_router(self._container.auth_controller.router)
        self._app.include_router(self._container.audit_controller.router)
        return self

    def build(self) -> FastAPI:
        return self._app


class ApplicationBootstrap:
    @staticmethod
    def create() -> FastAPI:
        EnvironmentConfig.load()
        container = ApplicationContainer()
        return CryptoLockAppFactory(container).configure_middleware().configure_routes().build()


app = ApplicationBootstrap.create()

