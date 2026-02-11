from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import List
import uuid


class EstadoUsuario(str, Enum):
    ACTIVO = "ACTIVO"
    INACTIVO = "INACTIVO"
    BLOQUEADO = "BLOQUEADO"
    PENDIENTE = "PENDIENTE"


@dataclass
class Usuario:
    email: str
    nombre: str

    # 🔐 Flujo crear cuenta → verificar → activar
    estado: EstadoUsuario = EstadoUsuario.PENDIENTE
    emailVerificado: bool = False

    nivelConfianza: int = 0
    id: uuid.UUID = field(default_factory=uuid.uuid4)
    fechaCreacion: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def autenticar(self) -> bool:
        # Solo puede autenticarse si está activo y con email verificado
        return self.estado == EstadoUsuario.ACTIVO and self.emailVerificado is True

    def marcar_email_verificado(self) -> None:
        self.emailVerificado = True
        self.estado = EstadoUsuario.ACTIVO

    def obtenerPerfil(self) -> dict:
        return {
            "id": str(self.id),
            "email": self.email,
            "nombre": self.nombre,
            "estado": self.estado.value,
            "emailVerificado": self.emailVerificado,
            "fechaCreacion": self.fechaCreacion.isoformat(),
            "nivelConfianza": self.nivelConfianza,
            "tipo": self.__class__.__name__,
        }


@dataclass
class UsuarioHumano(Usuario):
    telefono: str = ""
    mfaHabilitado: bool = False

    def verificarMFA(self) -> bool:
        return bool(self.mfaHabilitado)


@dataclass
class UsuarioServicio(Usuario):
    apiKey: str = ""
    ipPermitidas: List[str] = field(default_factory=list)

    def validarIP(self, ip: str) -> bool:
        if not self.ipPermitidas:
            return True
        return ip in self.ipPermitidas


@dataclass
class UsuarioAgente(Usuario):
    permisos: List[str] = field(default_factory=list)
    contexto: str = ""

    def ejecutarTarea(self, tarea: str) -> str:
        return f"Agente ejecutó: {tarea}"
