from fastapi import APIRouter

from services.audit_service import get_audit_service


class AuditController:
    def __init__(self) -> None:
        self._audit = get_audit_service()
        self.router = APIRouter(prefix="/audit", tags=["audit"])
        self._register_routes()

    def _register_routes(self) -> None:
        self.router.get("/status")(self.status)
        self.router.get("/summary")(self.summary)
        self.router.get("/chain")(self.chain)

    def status(self) -> dict:
        return self._audit.estado_cadena()

    def summary(self) -> list[str]:
        return self._audit.listar_resumen()

    def chain(self) -> dict:
        return self._audit.exportar_cadena()


audit_controller = AuditController()
router = audit_controller.router