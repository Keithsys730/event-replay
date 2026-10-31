"""Port definition for event ingestion from external brokers or logs."""

from __future__ import annotations

from typing import List, Protocol
from event_replay.domain.models import RecordedEvent


class EventIngestionPort(Protocol):
    """Hexagonal Ingestion Port: pulls events from messaging broker or file source."""

    def poll_events(self, max_count: int = 100, timeout_seconds: float = 1.0) -> List[RecordedEvent]:
        """Poll a batch of events from subscribed topics."""
        ...

    def ack(self, event: RecordedEvent) -> None:
        """Acknowledge successful event processing / commit offset."""
        ...

    def close(self) -> None:
        """Release underlying broker connections."""
        ...
