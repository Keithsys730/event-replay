"""DryRunSink for quarantined replay execution with automatic header injection."""

from __future__ import annotations

from typing import Dict, List, Optional
from event_replay.domain.models import RecordedEvent
from event_replay.ports.sink import EventSinkPort


class DryRunSink(EventSinkPort):
    """In-memory event sink ensuring zero external network side-effects during replay.
    
    Automatically injects mandatory quarantine headers:
    - X-Event-Replay: true
    - X-Replay-Session-Id: <session_id>
    - X-Original-Timestamp: <iso_utc>
    """

    def __init__(
        self,
        session_id: str,
        header_overrides: Optional[Dict[str, str]] = None,
    ) -> None:
        self.session_id = session_id
        self.header_overrides = header_overrides or {}
        self.emitted_events: List[RecordedEvent] = []
        self._is_closed: bool = False

    def emit(self, event: RecordedEvent, dry_run: bool = True) -> bool:
        """Inject quarantine headers and capture replayed event in memory."""
        if self._is_closed:
            raise RuntimeError("DryRunSink is closed")

        # Copy and inject quarantine headers
        new_headers = dict(event.headers)
        new_headers["X-Event-Replay"] = "true"
        new_headers["X-Replay-Session-Id"] = self.session_id
        if "X-Original-Timestamp" not in new_headers:
            new_headers["X-Original-Timestamp"] = event.timestamp_utc

        # Apply user header overrides (e.g. fresh auth token)
        for k, v in self.header_overrides.items():
            new_headers[k] = v

        quarantined_event = RecordedEvent.create(
            seq_id=event.seq_id,
            event_id=event.event_id,
            stream_topic=event.stream_topic,
            timestamp_utc=event.timestamp_utc,
            payload=event.payload,
            partition_key=event.partition_key,
            headers=new_headers,
        )

        self.emitted_events.append(quarantined_event)
        return True

    def flush(self) -> None:
        pass

    def close(self) -> None:
        self._is_closed = True

    @property
    def count(self) -> int:
        return len(self.emitted_events)
