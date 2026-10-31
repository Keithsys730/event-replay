"""Port definition for event sinks (dry-run inspectors or live broker producers)."""

from __future__ import annotations

from typing import Protocol
from event_replay.domain.models import RecordedEvent


class EventSinkPort(Protocol):
    """Hexagonal Sink Port: emits replayed events downstream."""

    def emit(self, event: RecordedEvent, dry_run: bool = True) -> bool:
        """Emit a replayed event to destination. Returns True if successfully handled."""
        ...

    def flush(self) -> None:
        """Flush any pending buffered events."""
        ...

    def close(self) -> None:
        """Release underlying connections."""
        ...
