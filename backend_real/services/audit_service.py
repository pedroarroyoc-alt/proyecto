from __future__ import annotations

import ipaddress
import json
import os
from threading import Lock
import time
from typing import Any, Dict, List
from urllib.parse import quote
from urllib.request import Request, urlopen

from domain.audit_blockchain import Blockchain, RegistroAcceso
from services.request_context import RequestContextStore


class GeoIpResolver:
    def __init__(self) -> None:
        self._enabled = self._read_bool_env("AUDIT_GEOIP_ENABLED", True)
        self._provider_url = os.getenv("AUDIT_GEOIP_URL", "https://ipapi.co/{ip}/json/").strip()
        self._timeout_seconds = max(0.2, self._read_float_env("AUDIT_GEOIP_TIMEOUT_SECONDS", 2.0))
        self._cache_ttl_seconds = max(60, self._read_int_env("AUDIT_GEOIP_CACHE_TTL_SECONDS", 21600))
        self._local_city = os.getenv("AUDIT_LOCAL_CITY", "").strip()
        self._local_country = os.getenv("AUDIT_LOCAL_COUNTRY", "").strip()
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = Lock()

    @staticmethod
    def _read_bool_env(name: str, default: bool) -> bool:
        raw = os.getenv(name, "").strip().lower()
        if not raw:
            return bool(default)
        return raw not in {"0", "false", "no", "off"}

    @staticmethod
    def _read_int_env(name: str, default: int) -> int:
        raw = os.getenv(name, "").strip()
        if not raw:
            return int(default)
        try:
            return int(raw)
        except ValueError:
            return int(default)

    @staticmethod
    def _read_float_env(name: str, default: float) -> float:
        raw = os.getenv(name, "").strip()
        if not raw:
            return float(default)
        try:
            return float(raw)
        except ValueError:
            return float(default)

    @staticmethod
    def _normalize_ip(value: str) -> str:
        ip_raw = str(value or "").strip()
        if not ip_raw:
            return "0.0.0.0"
        if ip_raw.startswith("::ffff:"):
            ip_raw = ip_raw.replace("::ffff:", "", 1)
        try:
            return str(ipaddress.ip_address(ip_raw))
        except ValueError:
            return "0.0.0.0"

    @staticmethod
    def _is_public_ip(ip_value: str) -> bool:
        try:
            parsed = ipaddress.ip_address(ip_value)
        except ValueError:
            return False

        return not (
            parsed.is_private
            or parsed.is_loopback
            or parsed.is_link_local
            or parsed.is_reserved
            or parsed.is_multicast
            or parsed.is_unspecified
        )

    def _get_cache(self, ip_value: str) -> Dict[str, str] | None:
        now = time.time()
        with self._cache_lock:
            row = self._cache.get(ip_value)
            if not row:
                return None
            if float(row.get("expires_at", 0)) < now:
                self._cache.pop(ip_value, None)
                return None
            return {
                "city": str(row.get("city", "Desconocida")),
                "country": str(row.get("country", "Desconocido")),
                "source": str(row.get("source", "cache")),
            }

    def _set_cache(self, ip_value: str, payload: Dict[str, str]) -> None:
        with self._cache_lock:
            self._cache[ip_value] = {
                "city": str(payload.get("city", "Desconocida")),
                "country": str(payload.get("country", "Desconocido")),
                "source": str(payload.get("source", "cache")),
                "expires_at": time.time() + self._cache_ttl_seconds,
            }

    @staticmethod
    def _sanitize_location_text(value: str, fallback: str) -> str:
        text = str(value or "").strip()
        return text if text else fallback

    def _from_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        city = (
            headers.get("x-vercel-ip-city")
            or headers.get("x-appengine-city")
            or headers.get("x-city")
            or ""
        ).strip()
        country = (
            headers.get("x-vercel-ip-country")
            or headers.get("x-appengine-country")
            or headers.get("cf-ipcountry")
            or headers.get("x-country")
            or ""
        ).strip()
        if not city and not country:
            return {}
        return {
            "city": self._sanitize_location_text(city, self._local_city or "Desconocida"),
            "country": self._sanitize_location_text(country, self._local_country or "Desconocido"),
            "source": "proxy_header",
        }

    def _resolve_private_or_local(self, headers: Dict[str, str]) -> Dict[str, str]:
        header_location = self._from_headers(headers)
        if header_location:
            return header_location
        return {
            "city": self._local_city or "Red local",
            "country": self._local_country or "Local",
            "source": "private_ip",
        }

    def _resolve_public_ip(self, ip_value: str) -> Dict[str, str]:
        if not self._enabled:
            return {"city": "Desconocida", "country": "Desconocido", "source": "disabled"}
        if "{ip}" not in self._provider_url:
            return {"city": "Desconocida", "country": "Desconocido", "source": "invalid_provider_url"}

        url = self._provider_url.replace("{ip}", quote(ip_value, safe=""))
        req = Request(
            url=url,
            headers={
                "Accept": "application/json",
                "User-Agent": "CryptoLock-Audit/1.0",
            },
        )
        try:
            with urlopen(req, timeout=self._timeout_seconds) as resp:
                payload_raw = resp.read().decode("utf-8", errors="replace")
            payload = json.loads(payload_raw)
        except Exception:
            return {"city": "Desconocida", "country": "Desconocido", "source": "provider_error"}

        city = self._sanitize_location_text(
            payload.get("city")
            or payload.get("city_name")
            or payload.get("region")
            or "",
            "Desconocida",
        )
        country = self._sanitize_location_text(
            payload.get("country_name")
            or payload.get("country")
            or payload.get("countryCode")
            or payload.get("country_code")
            or "",
            "Desconocido",
        )
        return {"city": city, "country": country, "source": "geoip_provider"}

    def resolve(self, ip_value: str, headers: Dict[str, str] | None = None) -> Dict[str, str]:
        normalized = self._normalize_ip(ip_value)
        if normalized == "0.0.0.0":
            return {"city": "Desconocida", "country": "Desconocido", "source": "missing_ip"}

        cached = self._get_cache(normalized)
        if cached is not None:
            return cached

        header_map = dict(headers or {})
        if self._is_public_ip(normalized):
            resolved = self._resolve_public_ip(normalized)
        else:
            resolved = self._resolve_private_or_local(header_map)

        self._set_cache(normalized, resolved)
        return resolved


class AuditService:
    """Servicio de auditoria basado en blockchain en memoria."""

    def __init__(
        self,
        request_context_store: RequestContextStore,
        *,
        dificultad: int = 2,
        geoip_resolver: GeoIpResolver | None = None,
    ) -> None:
        self._blockchain = Blockchain(dificultad=dificultad)
        self._request_context_store = request_context_store
        self._lock = Lock()
        self._geoip = geoip_resolver or GeoIpResolver()

    @staticmethod
    def _normalize_ip(value: str) -> str:
        raw = str(value or "").strip()
        if raw.startswith("::ffff:"):
            raw = raw.replace("::ffff:", "", 1)
        return raw or "0.0.0.0"

    @staticmethod
    def _enrich_metadata(
        metadatos: Dict[str, Any] | None,
        *,
        geo_city: str,
        geo_country: str,
        geo_source: str,
    ) -> Dict[str, Any]:
        payload = dict(metadatos or {})
        payload["geo"] = {
            "city": geo_city,
            "country": geo_country,
            "source": geo_source,
        }
        return payload

    def registrar_evento(
        self,
        *,
        usuario_id: str,
        accion: str,
        recurso: str,
        ip: str = "0.0.0.0",
        metadatos: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        ctx = self._request_context_store.get_context()
        normalized_input_ip = self._normalize_ip(ip)
        effective_ip = normalized_input_ip
        if effective_ip in {"0.0.0.0", ""}:
            effective_ip = self._normalize_ip(ctx.client_ip)

        geo = self._geoip.resolve(effective_ip, headers=ctx.headers)
        city = geo.get("city", "Desconocida")
        country = geo.get("country", "Desconocido")
        source = geo.get("source", "unknown")

        registro = RegistroAcceso(
            usuarioId=usuario_id,
            accion=accion,
            recurso=recurso,
            ip=effective_ip,
            metadatos=self._enrich_metadata(
                metadatos,
                geo_city=city,
                geo_country=country,
                geo_source=source,
            ),
            ciudad=city,
            pais=country,
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
            return json.loads(self._blockchain.exportar_json())
