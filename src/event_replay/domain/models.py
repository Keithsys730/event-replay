"""Domain data models and contracts for event-replay."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
from typing import Any, Dict, List, Optional


class ReplayClockMode(str, Enum):
    """Replay time pacing strategy."""
    PRESERVE_INTERVAL = "preserve_interval"  # Replay with original relative delays (scaled by speed_multiplier)
    SHIFT_TO_CURRENT = "shift_to_current"    # Shift event timestamps to now while preserving relative intervals
    IMMEDIATE_STEP = "immediate_step"        # No artificial delays; fast-forward or step-by-step


@dataclass(frozen=True)
class RecordedEvent:
    """An immutable recorded messaging event with cryptographic checksum."""
    seq_id: int                          # Monotonically increasing sequence number across all topics
    event_id: str                        # Original unique ID (UUID, message-id, or correlation-id)
    stream_topic: str                    # Target topic, channel, or queue name
    partition_key: Optional[str]        # Partition or routing key
    timestamp_utc: str                   # Original ISO-8601 UTC timestamp
    headers: Dict[str, str] = field(default_factory=dict)
    payload: bytes = b""                 # Bit-exact binary payload (Protobuf, Avro, JSON, MsgPack)
    checksum_sha256: str = ""            # SHA-256 integrity hash over (topic + payload)

    def verify_integrity(self) -> bool:
        """Verify that payload and topic match the recorded checksum."""
        if not self.checksum_sha256:
            return True
        computed = hashlib.sha256(self.stream_topic.encode("utf-8") + self.payload).hexdigest()
        return computed == self.checksum_sha256

    @classmethod
    def create(
        cls,
        seq_id: int,
        event_id: str,
        stream_topic: str,
        timestamp_utc: str,
        payload: bytes,
        partition_key: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> RecordedEvent:
        """Factory creating RecordedEvent with deterministic checksum computation."""
        hdrs = headers or {}
        checksum = hashlib.sha256(stream_topic.encode("utf-8") + payload).hexdigest()
        return cls(
            seq_id=seq_id,
            event_id=event_id,
            stream_topic=stream_topic,
            partition_key=partition_key,
            timestamp_utc=timestamp_utc,
            headers=hdrs,
            payload=payload,
            checksum_sha256=checksum,
        )


@dataclass
class ReplayConfig:
    """Configuration options for a replay run."""
    session_id: str
    clock_mode: ReplayClockMode = ReplayClockMode.PRESERVE_INTERVAL
    speed_multiplier: float = 1.0        # E.g. 2.0 = 2x speed, 0.5 = half speed
    dry_run: bool = True                 # Default to safe dry-run (no physical outbound mutation)
    time_window_start: Optional[str] = None
    time_window_end: Optional[str] = None
    topic_filters: List[str] = field(default_factory=list)
    header_overrides: Dict[str, str] = field(default_factory=dict)
    mask_pii: bool = True


@dataclass
class ReplayResult:
    """Summary metrics of an executed replay session."""
    session_id: str
    events_replayed: int
    events_skipped: int
    start_time_utc: str
    end_time_utc: str
    success: bool
    quarantine_verified: bool = True
    error_message: Optional[str] = None


@dataclass
class EventDiff:
    """Differences between expected and observed events."""
    seq_id: int
    event_id: str
    stream_topic: str
    diff_type: str                       # 'MISSING', 'UNEXPECTED', 'PAYLOAD_MISMATCH', 'HEADER_MISMATCH'
    details: str


@dataclass
class DiffResult:
    """Composite difference report between two event streams."""
    identical: bool
    total_a: int
    total_b: int
    mismatches: List[EventDiff] = field(default_factory=list)
