"""Regression tests for ORD-0157 cold review findings (F-01 through F-05)."""

import json
from event_replay.domain.models import RecordedEvent, ReplayConfig, ReplayClockMode
from event_replay.domain.stream import EventStream, CausalSequencer
from event_replay.domain.differ import StreamDiffer
from event_replay.domain.filters import PIIMaskingFilter
from event_replay.domain.engine import ReplayEngine
from event_replay.ports.sink import EventSinkPort


class DummySink(EventSinkPort):
    def __init__(self):
        self.emitted = []

    def emit(self, event: RecordedEvent, dry_run: bool = True) -> bool:
        self.emitted.append(event)
        return True

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


def test_f01_causal_sequencer_duplicate_seq_id_and_timestamp_tie_breaker():
    """F-01 [P0]: CausalSequencer handles duplicate (seq_id, timestamp) without TypeError."""
    sequencer = CausalSequencer()
    ev1 = RecordedEvent.create(
        seq_id=1,
        event_id="ev-1",
        stream_topic="orders",
        timestamp_utc="2026-10-31T12:00:00Z",
        payload=b'{"order_id": 1}',
    )
    ev2 = RecordedEvent.create(
        seq_id=1,
        event_id="ev-2",
        stream_topic="payments",
        timestamp_utc="2026-10-31T12:00:00Z",
        payload=b'{"payment_id": 2}',
    )

    # Prior to fix, heappush/heappop crashed with TypeError: '<' not supported between instances of 'RecordedEvent'
    sequencer.push(ev1)
    sequencer.push(ev2)

    popped = list(sequencer.drain_all())
    assert len(popped) == 2
    assert {p.event_id for p in popped} == {"ev-1", "ev-2"}


def test_f02_stream_differ_handles_duplicate_event_ids_at_least_once():
    """F-02 [P1]: StreamDiffer detects occurrence count mismatches for duplicate event IDs."""
    ev_a1 = RecordedEvent.create(
        seq_id=1,
        event_id="dup-1",
        stream_topic="events",
        timestamp_utc="2026-10-31T12:00:00Z",
        payload=b"payload_1",
    )
    ev_a2 = RecordedEvent.create(
        seq_id=2,
        event_id="dup-1",
        stream_topic="events",
        timestamp_utc="2026-10-31T12:00:01Z",
        payload=b"payload_1",
    )

    ev_b1 = RecordedEvent.create(
        seq_id=1,
        event_id="dup-1",
        stream_topic="events",
        timestamp_utc="2026-10-31T12:00:00Z",
        payload=b"payload_1",
    )

    # Stream A has 2 instances of dup-1, Stream B has only 1 instance
    result = StreamDiffer.diff([ev_a1, ev_a2], [ev_b1])
    assert not result.identical
    assert any(m.diff_type == "OCCURRENCE_MISMATCH" for m in result.mismatches)


def test_f03_pii_masking_filter_handles_root_json_array():
    """F-03 [P1]: PIIMaskingFilter recursively masks sensitive fields in root JSON arrays."""
    payload = json.dumps([
        {"id": 1, "api_key": "secret_abc"},
        {"id": 2, "nested": [{"token": "jwt_123"}]},
    ]).encode("utf-8")

    masked = PIIMaskingFilter.mask_payload_if_json(payload)
    parsed = json.loads(masked.decode("utf-8"))

    assert parsed[0]["api_key"] == "[REDACTED]"
    assert parsed[1]["nested"][0]["token"] == "[REDACTED]"
    assert parsed[0]["id"] == 1


def test_f04_event_stream_iter_events_iso_z_and_offset_comparison():
    """F-04 [P2]: EventStream.iter_events correctly filters across Z and +00:00 ISO timestamps."""
    stream = EventStream()
    stream.append(
        event_id="ev-1",
        stream_topic="test",
        timestamp_utc="2026-10-31T12:00:00+00:00",
        payload=b"test",
    )
    stream.append(
        event_id="ev-2",
        stream_topic="test",
        timestamp_utc="2026-10-31T14:00:00Z",
        payload=b"test",
    )

    # Filter with Z start time against +00:00 stored event
    filtered = list(stream.iter_events(time_start="2026-10-31T11:59:59Z", time_end="2026-10-31T13:00:00+00:00"))
    assert len(filtered) == 1
    assert filtered[0].event_id == "ev-1"


def test_f05_replay_engine_universal_quarantine_header_injection():
    """F-05 [P2]: ReplayEngine injects quarantine headers regardless of the sink."""
    sink = DummySink()
    config = ReplayConfig(
        session_id="session-f05",
        clock_mode=ReplayClockMode.IMMEDIATE_STEP,
    )
    engine = ReplayEngine(config=config, sink=sink)

    ev = RecordedEvent.create(
        seq_id=1,
        event_id="ev-unmarked",
        stream_topic="test",
        timestamp_utc="2026-10-31T12:00:00Z",
        payload=b"raw",
        headers={"custom": "val"},
    )

    result = engine.run([ev])
    assert result.success
    assert len(sink.emitted) == 1

    emitted_ev = sink.emitted[0]
    assert emitted_ev.headers["X-Event-Replay"] == "true"
    assert emitted_ev.headers["X-Replay-Session-Id"] == "session-f05"
    assert emitted_ev.headers["X-Original-Timestamp"] == "2026-10-31T12:00:00Z"
    assert emitted_ev.headers["custom"] == "val"
