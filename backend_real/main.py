import os

from dotenv import load_dotenv

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.auth import router as auth_router
from api.audit import router as audit_router
from api.users import router as users_router


class EnvironmentConfig:
    @staticmethod
    def load() -> None:
        load_dotenv(".env")


class HealthController:
    @staticmethod
    def health() -> dict[str, bool | str]:
        return {"ok": True, "service": "cryptolock-api"}


class CryptoLockAppFactory:
    def __init__(self) -> None:
        self._app = FastAPI(title="CryptoLock Backend", version="0.1.0")

    def configure_middleware(self) -> "CryptoLockAppFactory":
        raw_origins = os.getenv("CORS_ALLOW_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").strip()
        allow_origins = [origin.strip() for origin in raw_origins.split(",") if origin.strip()]
        self._app.add_middleware(
            CORSMiddleware,
            allow_origins=allow_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
            allow_headers=["Authorization", "Content-Type"],
        )
        return self

    def configure_routes(self) -> "CryptoLockAppFactory":
        self._app.get("/health")(HealthController.health)
        self._app.include_router(users_router)
        self._app.include_router(auth_router)
        self._app.include_router(audit_router)
        return self

    def build(self) -> FastAPI:
        return self._app


class ApplicationBootstrap:
    @staticmethod
    def create() -> FastAPI:
        EnvironmentConfig.load()
        return CryptoLockAppFactory().configure_middleware().configure_routes().build()


app = ApplicationBootstrap.create()
