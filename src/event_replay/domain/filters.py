"""Domain event filters: Self-Replay Storm Quarantine (INV-1) and PII Masking."""

from __future__ import annotations

import json
from typing import Dict, Optional
from event_replay.domain.models import RecordedEvent

REPLAY_HEADER_KEY = "x-event-replay"


class SelfReplayFilter:
    """Invariant 1: Anti-Self-Replay Storm Filter.
    
    Drops any event bearing the 'X-Event-Replay: true' header to mechanically
    prevent infinite recursive event amplification loops during live recording.
    """

    @staticmethod
    def is_replayed_event(event: RecordedEvent) -> bool:
        """Inspect headers (case-insensitive) for replay markers."""
        for k, v in event.headers.items():
            if k.lower() == REPLAY_HEADER_KEY and str(v).lower() in ("true", "1", "yes"):
                return True
        return False

    @classmethod
    def filter(cls, event: RecordedEvent) -> Optional[RecordedEvent]:
        """Return None if event was produced by a replay session, otherwise return event."""
        if cls.is_replayed_event(event):
            return None
        return event


class PIIMaskingFilter:
    """Masks credentials, tokens, and PII from headers and JSON payloads (F-03)."""

    SENSITIVE_KEYS = {
        "password", "secret", "token", "authorization", "auth",
        "api_key", "apikey", "credit_card", "card_number", "ssn", "private_key"
    }

    @classmethod
    def is_sensitive_key(cls, key: str) -> bool:
        norm = str(key).lower().replace("-", "_")
        return any(s in norm for s in cls.SENSITIVE_KEYS)

    @classmethod
    def mask_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        """Mask sensitive keys in headers dictionary."""
        masked = {}
        for k, v in headers.items():
            if cls.is_sensitive_key(k):
                masked[k] = "[REDACTED]"
            else:
                masked[k] = v
        return masked

    @classmethod
    def mask_payload_if_json(cls, payload: bytes) -> bytes:
        """If payload is UTF-8 JSON, recursively mask sensitive fields in dicts and lists (F-03)."""
        try:
            text = payload.decode("utf-8")
            data = json.loads(text)
            if isinstance(data, dict):
                cls._mask_dict(data)
                return json.dumps(data, ensure_ascii=False).encode("utf-8")
            elif isinstance(data, list):
                cls._mask_list(data)
                return json.dumps(data, ensure_ascii=False).encode("utf-8")
        except Exception:
            pass
        return payload

    @classmethod
    def _mask_dict(cls, d: dict) -> None:
        for k, v in list(d.items()):
            if cls.is_sensitive_key(str(k)):
                d[k] = "[REDACTED]"
            elif isinstance(v, dict):
                cls._mask_dict(v)
            elif isinstance(v, list):
                cls._mask_list(v)

    @classmethod
    def _mask_list(cls, lst: list) -> None:
        for item in lst:
            if isinstance(item, dict):
                cls._mask_dict(item)
            elif isinstance(item, list):
                cls._mask_list(item)
