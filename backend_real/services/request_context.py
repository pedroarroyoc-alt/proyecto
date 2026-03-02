from __future__ import annotations

import contextvars
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class RequestContext:
    client_ip: str = "0.0.0.0"
    headers: Dict[str, str] = field(default_factory=dict)


class RequestContextStore:
    def __init__(self) -> None:
        self._request_context_var: contextvars.ContextVar[RequestContext] = contextvars.ContextVar(
            "cryptolock_request_context",
            default=RequestContext(),
        )

    def set_context(self, *, client_ip: str, headers: Dict[str, str] | None = None) -> None:
        self._request_context_var.set(
            RequestContext(
                client_ip=str(client_ip or "0.0.0.0").strip() or "0.0.0.0",
                headers=dict(headers or {}),
            )
        )

    def clear_context(self) -> None:
        self._request_context_var.set(RequestContext())

    def get_context(self) -> RequestContext:
        return self._request_context_var.get()
