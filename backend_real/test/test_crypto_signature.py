import pytest

cryptography = pytest.importorskip("cryptography")

from backend_real.domain.boveda_llaves import BovedaLlaves


def test_boveda_firmar_y_verificar_firma_valida() -> None:
    boveda = BovedaLlaves()
    mensaje = "transaccion:usuario=alice;accion=login"

    firma_hex = boveda.firmar(mensaje)

    assert isinstance(firma_hex, str)
    assert len(firma_hex) > 0
    assert boveda.verificar_firma(mensaje, firma_hex) is True


def test_boveda_verificar_firma_invalida_retorna_false() -> None:
    boveda = BovedaLlaves()
    mensaje = "mensaje-original"
    firma_hex = boveda.firmar(mensaje)

    # Alteramos la firma para simular manipulación
    firma_alterada = ("00" if not firma_hex.startswith("00") else "ff") + firma_hex[2:]

    assert boveda.verificar_firma(mensaje, firma_alterada) is False


def test_boveda_verificar_firma_falla_si_mensaje_cambia() -> None:
    boveda = BovedaLlaves()
    firma_hex = boveda.firmar("mensaje-original")

    assert boveda.verificar_firma("mensaje-modificado", firma_hex) is False