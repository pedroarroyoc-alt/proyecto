from __future__ import annotations

import json
from threading import Lock
from typing import Any, Dict, List

from domain.audit_blockchain import Blockchain, RegistroAcceso


class AuditService:
    """Servicio de auditoría basado en blockchain en memoria."""

    def __init__(self, dificultad: int = 2) -> None:
        self._blockchain = Blockchain(dificultad=dificultad)
        self._lock = Lock()

    def registrar_evento(
        self,
        *,
        usuario_id: str,
        accion: str,
        recurso: str,
        ip: str = "0.0.0.0",
        metadatos: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        registro = RegistroAcceso(
            usuarioId=usuario_id,
            accion=accion,
            recurso=recurso,
            ip=ip,
            metadatos=metadatos or {},
        )

        with self._lock:
            bloque = self._blockchain.agregar_registro(registro)

        return bloque.to_dict()

    def estado_cadena(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "valida": self._blockchain.validar_cadena(),
                "dificultad": self._blockchain.dificultad,
                "longitud": self._blockchain.longitud,
            }

    def listar_resumen(self) -> List[str]:
        with self._lock:
            return self._blockchain.exportar_resumen()

    def exportar_cadena(self) -> Dict[str, Any]:
        with self._lock:
            # reaprovechamos exportar_json para no duplicar estructura
            return json.loads(self._blockchain.exportar_json())


# Singleton para uso transversal en todo el backend
_audit_service_singleton = AuditService()


def get_audit_service() -> AuditService:
    return _audit_service_singleton