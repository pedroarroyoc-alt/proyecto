from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys


def _load_module(module_name: str, relative_path: str):
    base = Path(__file__).resolve().parents[1]
    module_path = base / relative_path
    spec = spec_from_file_location(module_name, module_path)
    module = module_from_spec(spec)
    assert spec and spec.loader
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


usuarios_module = _load_module("usuarios_module", "domain/usuarios.py")
audit_module = _load_module("audit_module", "domain/audit_blockchain.py")

EstadoUsuario = usuarios_module.EstadoUsuario
UsuarioAgente = usuarios_module.UsuarioAgente
UsuarioHumano = usuarios_module.UsuarioHumano
UsuarioServicio = usuarios_module.UsuarioServicio

Blockchain = audit_module.Blockchain
RegistroAcceso = audit_module.RegistroAcceso


def test_usuario_humano_auth_and_confidence_flow() -> None:
    user = UsuarioHumano(email="user@example.com", nombre="User")

    assert user.autenticar() is False
    assert user.nivelConfianza == 0

    user.marcar_email_verificado()
    assert user.estado == EstadoUsuario.ACTIVO
    assert user.emailVerificado is True
    assert user.nivelConfianza == 1

    user.mfaHabilitado = True
    user.actualizar_nivel_confianza()
    assert user.nivelConfianza == 2

    user.faceIdEnabled = True
    user.faceIdEnrolled = True
    user.actualizar_nivel_confianza()
    assert user.nivelConfianza == 3


def test_usuario_servicio_validar_ip() -> None:
    svc = UsuarioServicio(email="svc@example.com", nombre="svc", ipPermitidas=["10.0.0.1"])

    assert svc.validarIP("10.0.0.1") is True
    assert svc.validarIP("10.0.0.2") is False


def test_usuario_agente_ejecutar_tarea() -> None:
    agent = UsuarioAgente(email="agent@example.com", nombre="bot")
    result = agent.ejecutarTarea("reindexar")
    assert "reindexar" in result


def test_blockchain_add_record_and_validate_chain() -> None:
    bc = Blockchain(dificultad=1)
    registro = RegistroAcceso(
        usuarioId="u-1",
        accion="LOGIN",
        recurso="/auth/login",
        ip="127.0.0.1",
        metadatos={"ok": True},
    )

    bloque = bc.agregar_registro(registro)

    assert bloque.indice == 1
    assert bc.longitud == 2
    assert bc.validar_cadena() is True
    assert len(bc.buscar_por_usuario("u-1")) == 1


def test_blockchain_detects_tampering() -> None:
    bc = Blockchain(dificultad=1)
    registro = RegistroAcceso(
        usuarioId="u-2",
        accion="READ",
        recurso="/vault",
        ip="127.0.0.1",
        metadatos={},
    )
    bc.agregar_registro(registro)

    bc._Blockchain__cadena[1]._Bloque__datos["accion"] = "TAMPERED"  # type: ignore[attr-defined]

    assert bc.validar_cadena() is False