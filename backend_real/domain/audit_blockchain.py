from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# ==========================================================
# 1) REGISTRO DE ACCESO (Entidad de dominio / POO)
# ==========================================================
@dataclass(frozen=True)
class RegistroAcceso:
    usuarioId: str
    accion: str
    recurso: str
    ip: str
    metadatos: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        # sort_keys=True asegura consistencia en el hash
        return json.dumps(self.to_dict(), ensure_ascii=False, sort_keys=True)


# ==========================================================
# 2) BLOQUE (Inmutabilidad + Hash + Proof-of-Work)
# ==========================================================
class Bloque:
    def __init__(self, indice: int, datos: Dict[str, Any], hash_anterior: str, dificultad: int):
        self.__indice = indice
        self.__timestamp = datetime.now(timezone.utc).isoformat()
        self.__datos = datos  # dict (no string), para búsquedas limpias
        self.__hash_anterior = hash_anterior
        self.__dificultad = dificultad

        self.__nonce = 0
        self.__hash = ""
        self.__minar()  # genera nonce y hash cumpliendo PoW

    # ---------- Hash / PoW ----------
    def __contenido_hash(self, nonce: int) -> str:
        # JSON estable para que el hash sea reproducible
        datos_json = json.dumps(self.__datos, ensure_ascii=False, sort_keys=True)
        return f"{self.__indice}|{self.__timestamp}|{datos_json}|{self.__hash_anterior}|{nonce}"

    def calcular_hash(self, nonce: Optional[int] = None) -> str:
        n = self.__nonce if nonce is None else nonce
        contenido = self.__contenido_hash(n)
        return hashlib.sha256(contenido.encode("utf-8")).hexdigest()

    def __minar(self) -> None:
        objetivo = "0" * self.__dificultad
        while True:
            h = self.calcular_hash(self.__nonce)
            if h.startswith(objetivo):
                self.__hash = h
                break
            self.__nonce += 1

    # ---------- Validación ----------
    def validar(self) -> bool:
        # 1) hash coincide con su contenido actual
        if self.__hash != self.calcular_hash():
            return False

        # 2) cumple el Proof-of-Work
        if not self.__hash.startswith("0" * self.__dificultad):
            return False

        return True

    # ---------- Getters (solo lectura) ----------
    @property
    def indice(self) -> int:
        return self.__indice

    @property
    def timestamp(self) -> str:
        return self.__timestamp

    @property
    def datos(self) -> Dict[str, Any]:
        # devolvemos copia para evitar cambios accidentales desde fuera
        return dict(self.__datos)

    @property
    def hash(self) -> str:
        return self.__hash

    @property
    def hash_anterior(self) -> str:
        return self.__hash_anterior

    @property
    def nonce(self) -> int:
        return self.__nonce

    @property
    def dificultad(self) -> int:
        return self.__dificultad

    def resumen(self) -> str:
        return f"Bloque #{self.__indice} [hash={self.__hash[:12]}..., prev={self.__hash_anterior[:12]}..., nonce={self.__nonce}]"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indice": self.__indice,
            "timestamp": self.__timestamp,
            "datos": self.__datos,
            "hash_anterior": self.__hash_anterior,
            "nonce": self.__nonce,
            "dificultad": self.__dificultad,
            "hash": self.__hash,
        }


# ==========================================================
# 3) BLOCKCHAIN (Composición + Auditoría + Trazabilidad)
# ==========================================================
class Blockchain:
    def __init__(self, dificultad: int = 3):
        if dificultad < 1:
            raise ValueError("La dificultad debe ser >= 1")

        self.__dificultad = dificultad
        self.__cadena: List[Bloque] = []
        self.__crear_bloque_genesis()

    def __crear_bloque_genesis(self) -> None:
        genesis = Bloque(
            indice=0,
            datos={"mensaje": "Bloque Génesis - CryptoLock"},
            hash_anterior="0",
            dificultad=self.__dificultad,
        )
        self.__cadena.append(genesis)

    def obtener_ultimo_bloque(self) -> Bloque:
        return self.__cadena[-1]

    def agregar_registro(self, registro: RegistroAcceso) -> Bloque:
        ultimo = self.obtener_ultimo_bloque()
        nuevo = Bloque(
            indice=len(self.__cadena),
            datos=registro.to_dict(),
            hash_anterior=ultimo.hash,
            dificultad=self.__dificultad,
        )
        self.__cadena.append(nuevo)
        return nuevo

    def validar_cadena(self) -> bool:
        # valida bloque por bloque + enlace con anterior
        for i in range(1, len(self.__cadena)):
            actual = self.__cadena[i]
            anterior = self.__cadena[i - 1]

            if not actual.validar():
                return False
            if actual.hash_anterior != anterior.hash:
                return False

        # valida genesis también
        return self.__cadena[0].validar() and self.__cadena[0].hash_anterior == "0"

    def buscar_por_usuario(self, usuario_id: str) -> List[Bloque]:
        encontrados: List[Bloque] = []
        for b in self.__cadena:
            datos = b.datos
            if datos.get("usuarioId") == usuario_id:
                encontrados.append(b)
        return encontrados

    def exportar_resumen(self) -> List[str]:
        return [b.resumen() for b in self.__cadena]

    def exportar_json(self) -> str:
        payload = {
            "dificultad": self.__dificultad,
            "longitud": len(self.__cadena),
            "cadena": [b.to_dict() for b in self.__cadena],
        }
        return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True)

    # Solo lectura: evita modificar cadena desde fuera
    @property
    def dificultad(self) -> int:
        return self.__dificultad

    @property
    def longitud(self) -> int:
        return len(self.__cadena)


# ==========================================================
# DEMO (si lo ejecutas directo)
# ==========================================================
if __name__ == "__main__":
    print("--- INICIANDO AUDITORÍA TIPO BLOCKCHAIN (CryptoLock) ---")
    bc = Blockchain(dificultad=3)

    r1 = RegistroAcceso(
        usuarioId="20240535K",
        accion="ACCESO_BOVEDA",
        recurso="Servidor_UNI",
        ip="192.168.1.10",
        metadatos={"factor": "OTP", "resultado": "OK"},
    )

    bloque = bc.agregar_registro(r1)
    print("Registrado:", bloque.resumen())

    encontrados = bc.buscar_por_usuario("20240535K")
    print("Bloques del usuario:", [b.resumen() for b in encontrados])

    print("¿Cadena íntegra?:", bc.validar_cadena())

    print("\n--- SIMULACIÓN DE ATAQUE (manipulación interna) ---")
    # Nota: En Python se puede “romper” el encapsulamiento a propósito (como demo).
    # Esto simula que alguien alteró datos ya registrados.
    bc._Blockchain__cadena[1]._Bloque__datos["accion"] = "ACCESO_CONCEDIDO_INTRUSO"  # type: ignore

    print("¿Cadena íntegra tras hackeo?:", bc.validar_cadena())
    print("ALERTA: la cadena detectó manipulación (hash no coincide).")
