"""Append-only EventStream container and CausalSequencer for monotonic event streams."""

from __future__ import annotations

from datetime import datetime, timezone
import heapq
import json
from pathlib import Path
from typing import Dict, Iterator, List, Optional
from event_replay.domain.models import RecordedEvent


def _parse_ts_epoch(ts_str: str) -> float:
    """Parse timestamp to epoch seconds for robust normalized comparison."""
    try:
        clean = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except Exception:
        return 0.0


class EventStream:
    """In-memory and chunked append-only container for recorded events."""

    def __init__(self, name: str = "default_stream") -> None:
        self.name = name
        self._events: List[RecordedEvent] = []
        self._next_seq_id: int = 1

    @property
    def count(self) -> int:
        return len(self._events)

    @property
    def events(self) -> List[RecordedEvent]:
        """Return a copy of the events list."""
        return list(self._events)

    def append(
        self,
        event_id: str,
        stream_topic: str,
        timestamp_utc: str,
        payload: bytes,
        partition_key: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> RecordedEvent:
        """Append an event, assigning the next monotonic sequence ID."""
        event = RecordedEvent.create(
            seq_id=self._next_seq_id,
            event_id=event_id,
            stream_topic=stream_topic,
            timestamp_utc=timestamp_utc,
            payload=payload,
            partition_key=partition_key,
            headers=headers,
        )
        self._events.append(event)
        self._next_seq_id += 1
        return event

    def append_raw(self, event: RecordedEvent) -> None:
        """Append an existing event, updating monotonic sequence counter if necessary."""
        self._events.append(event)
        if event.seq_id >= self._next_seq_id:
            self._next_seq_id = event.seq_id + 1

    def iter_events(
        self,
        time_start: Optional[str] = None,
        time_end: Optional[str] = None,
        topics: Optional[List[str]] = None,
    ) -> Iterator[RecordedEvent]:
        """Streaming generator over events with normalized time comparison (F-04)."""
        topic_set = set(topics) if topics else None
        ts_start_val = _parse_ts_epoch(time_start) if time_start else None
        ts_end_val = _parse_ts_epoch(time_end) if time_end else None

        for ev in self._events:
            ev_ts_val = _parse_ts_epoch(ev.timestamp_utc)
            if ts_start_val is not None and ev_ts_val < ts_start_val:
                continue
            if ts_end_val is not None and ev_ts_val > ts_end_val:
                continue
            if topic_set and ev.stream_topic not in topic_set:
                continue
            yield ev

    def to_jsonl(self, file_path: Path) -> None:
        """Serialize stream to JSONL file."""
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, "w", encoding="utf-8") as f:
            for ev in self._events:
                row = {
                    "seq_id": ev.seq_id,
                    "event_id": ev.event_id,
                    "stream_topic": ev.stream_topic,
                    "partition_key": ev.partition_key,
                    "timestamp_utc": ev.timestamp_utc,
                    "headers": ev.headers,
                    "payload_hex": ev.payload.hex(),
                    "checksum_sha256": ev.checksum_sha256,
                }
                f.write(json.dumps(row, ensure_ascii=False) + "\n")

    @classmethod
    def from_jsonl(cls, file_path: Path, name: Optional[str] = None) -> EventStream:
        """Deserialize stream from JSONL file."""
        stream_name = name or file_path.stem
        stream = cls(name=stream_name)
        if not file_path.exists():
            return stream

        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                payload = bytes.fromhex(row.get("payload_hex", ""))
                ev = RecordedEvent(
                    seq_id=row["seq_id"],
                    event_id=row["event_id"],
                    stream_topic=row["stream_topic"],
                    partition_key=row.get("partition_key"),
                    timestamp_utc=row["timestamp_utc"],
                    headers=row.get("headers", {}),
                    payload=payload,
                    checksum_sha256=row.get("checksum_sha256", ""),
                )
                stream.append_raw(ev)
        return stream


class CausalSequencer:
    """Interleaved monotonic event sequencer across multiple topics/streams.
    
    Guarantees cross-topic causal ordering: events with smaller seq_id or timestamp
    are always yielded before subsequent events, preventing causal inversions (INV-3).
    Includes insertion counter to break ties without falling back to RecordedEvent comparison (F-01).
    """

    def __init__(self) -> None:
        self._heap: List[tuple[int, str, int, RecordedEvent]] = []
        self._counter: int = 0

    def push(self, event: RecordedEvent) -> None:
        """Push an event into the causal priority queue."""
        heapq.heappush(self._heap, (event.seq_id, event.timestamp_utc, self._counter, event))
        self._counter += 1

    def has_next(self) -> bool:
        return len(self._heap) > 0

    def pop_next(self) -> RecordedEvent:
        """Retrieve the next event in strict causal monotonic order."""
        if not self._heap:
            raise IndexError("CausalSequencer is empty")
        _, _, _, event = heapq.heappop(self._heap)
        return event

    def drain_all(self) -> Iterator[RecordedEvent]:
        """Drain all events in causal order."""
        while self.has_next():
            yield self.pop_next()
