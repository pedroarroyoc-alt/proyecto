from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


@dataclass(frozen=True)
class MetadatosLlave:
    fecha_creacion: datetime
    fecha_expiracion: datetime


class ParLlaves:
    """Par de llaves RSA con metadatos de vigencia."""

    def __init__(self, dias_validez: int = 365) -> None:
        self._private_key_obj = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._public_key_obj = self._private_key_obj.public_key()
        fecha_creacion = datetime.now()
        self._metadatos = MetadatosLlave(
            fecha_creacion=fecha_creacion,
            fecha_expiracion=fecha_creacion + timedelta(days=dias_validez),
        )

    @property
    def metadatos(self) -> MetadatosLlave:
        return self._metadatos

    def obtener_publica_pem(self) -> str:
        return self._public_key_obj.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

    def obtener_privada_pem(self) -> str:
        return self._private_key_obj.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")


class BovedaLlaves:
    """Bóveda en memoria para gestionar pares RSA y firma/verificación."""

    def __init__(self) -> None:
        self._llaves: List[ParLlaves] = []
        self.generar_par_llaves()

    def generar_par_llaves(self, dias_validez: int = 365) -> ParLlaves:
        par = ParLlaves(dias_validez=dias_validez)
        self._llaves.append(par)
        return par

    def obtener_llave_activa(self) -> Optional[ParLlaves]:
        return self._llaves[-1] if self._llaves else None

    def firmar(self, mensaje: str) -> str:
        llave = self.obtener_llave_activa()
        if not llave:
            raise RuntimeError("No hay llaves disponibles en la bóveda")

        firma_bytes = llave._private_key_obj.sign(
            mensaje.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return firma_bytes.hex()

    def verificar_firma(self, mensaje: str, firma_hex: str) -> bool:
        llave = self.obtener_llave_activa()
        if not llave:
            return False

        try:
            firma_bytes = bytes.fromhex(firma_hex)
            llave._public_key_obj.verify(
                firma_bytes,
                mensaje.encode("utf-8"),
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except (ValueError, InvalidSignature):
            return False