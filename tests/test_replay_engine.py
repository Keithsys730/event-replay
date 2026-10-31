"""Unit tests for TB-3: ReplayEngine, Time Projection (INV-2), StreamDiffer, and Bisect."""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
import pytest

from event_replay.adapters.dry_run_sink import DryRunSink
from event_replay.domain.bisect import bisect_failing_event
from event_replay.domain.differ import StreamDiffer
from event_replay.domain.engine import ReplayEngine
from event_replay.domain.models import (
    RecordedEvent,
    ReplayClockMode,
    ReplayConfig,
)


def test_replay_engine_shift_to_current_timestamp_projection():
    """INV-2: Shift-to-current mode projects historical events into current time window
    while maintaining relative delta between events, preventing expired TTL/Token rejections."""
    # Historical events recorded 30 days ago
    e1 = RecordedEvent.create(
        seq_id=1,
        event_id="ev_old_1",
        stream_topic="billing",
        timestamp_utc="2026-09-01T10:00:00Z",
        payload=b"charge_start",
    )
    e2 = RecordedEvent.create(
        seq_id=2,
        event_id="ev_old_2",
        stream_topic="billing",
        timestamp_utc="2026-09-01T10:00:15Z",  # exactly 15 seconds later
        payload=b"charge_done",
    )

    sink = DryRunSink(session_id="sess_proj")
    fixed_now = datetime(2026, 10, 31, 15, 0, 0, tzinfo=timezone.utc)
    sleep_calls = []

    config = ReplayConfig(
        session_id="sess_proj",
        clock_mode=ReplayClockMode.SHIFT_TO_CURRENT,
        dry_run=True,
    )
    engine = ReplayEngine(
        config=config,
        sink=sink,
        sleeper=lambda s: sleep_calls.append(s),
        now_fn=lambda: fixed_now,
    )

    result = engine.run([e1, e2])
    assert result.success is True
    assert result.events_replayed == 2
    assert len(sink.emitted_events) == 2

    emitted_1 = sink.emitted_events[0]
    emitted_2 = sink.emitted_events[1]

    # First event projected to fixed_now
    dt1 = datetime.fromisoformat(emitted_1.timestamp_utc)
    assert dt1.year == 2026
    assert dt1.month == 10
    assert dt1.day == 31
    assert dt1.hour == 15
    assert dt1.minute == 0
    assert dt1.second == 0

    # Second event projected to fixed_now + 15s
    dt2 = datetime.fromisoformat(emitted_2.timestamp_utc)
    delta = (dt2 - dt1).total_seconds()
    assert delta == 15.0

    # Quarantine headers verified
    assert emitted_1.headers["X-Event-Replay"] == "true"
    assert emitted_1.headers["X-Original-Timestamp"] == "2026-09-01T10:00:00Z"


def test_replay_engine_preserve_interval_pacing():
    """PRESERVE_INTERVAL scales delays by speed_multiplier."""
    e1 = RecordedEvent.create(seq_id=1, event_id="1", stream_topic="t", timestamp_utc="2026-10-31T12:00:00Z", payload=b"a")
    e2 = RecordedEvent.create(seq_id=2, event_id="2", stream_topic="t", timestamp_utc="2026-10-31T12:00:04Z", payload=b"b")

    sink = DryRunSink("ses_speed")
    sleep_calls = []
    config = ReplayConfig(
        session_id="ses_speed",
        clock_mode=ReplayClockMode.PRESERVE_INTERVAL,
        speed_multiplier=2.0,  # 2x speed -> 4s gap should sleep 2s
        dry_run=True,
    )
    engine = ReplayEngine(config=config, sink=sink, sleeper=lambda s: sleep_calls.append(s))
    res = engine.run([e1, e2])

    assert res.success is True
    assert len(sleep_calls) == 1
    assert sleep_calls[0] == 2.0


def test_stream_differ_detects_all_divergence_types():
    """StreamDiffer pinpoints missing, payload-mismatched, and header-mutated events."""
    stream_expected = [
        RecordedEvent.create(seq_id=1, event_id="e1", stream_topic="auth", timestamp_utc="2026-10-31T10:00:00Z", payload=b"login_ok", headers={"role": "admin"}),
        RecordedEvent.create(seq_id=2, event_id="e2", stream_topic="billing", timestamp_utc="2026-10-31T10:01:00Z", payload=b"price_50"),
        RecordedEvent.create(seq_id=3, event_id="e3", stream_topic="audit", timestamp_utc="2026-10-31T10:02:00Z", payload=b"log_saved"),
    ]

    stream_observed = [
        # e1 has altered payload
        RecordedEvent.create(seq_id=1, event_id="e1", stream_topic="auth", timestamp_utc="2026-10-31T10:00:00Z", payload=b"login_FAILED", headers={"role": "admin"}),
        # e2 has altered header
        RecordedEvent.create(seq_id=2, event_id="e2", stream_topic="billing", timestamp_utc="2026-10-31T10:01:00Z", payload=b"price_50", headers={"status": "corrupt"}),
        # e3 is missing, replaced by unexpected e4
        RecordedEvent.create(seq_id=4, event_id="e4", stream_topic="ghost", timestamp_utc="2026-10-31T10:03:00Z", payload=b"unknown"),
    ]

    diff_res = StreamDiffer.diff(stream_expected, stream_observed)
    assert diff_res.identical is False
    assert len(diff_res.mismatches) == 4

    types = {m.diff_type for m in diff_res.mismatches}
    assert "PAYLOAD_MISMATCH" in types
    assert "HEADER_MISMATCH" in types
    assert "MISSING" in types
    assert "UNEXPECTED" in types


def test_bisect_failing_event_isolates_poison_pill():
    """bisect_failing_event discovers the exact earliest poison pill event causing failure."""
    # Create 10 events where event #7 contains a poison pill payload
    events = [
        RecordedEvent.create(
            seq_id=i,
            event_id=f"ev_{i}",
            stream_topic="pipeline",
            timestamp_utc=f"2026-10-31T12:00:{i:02d}Z",
            payload=b"poison_pill" if i == 7 else b"healthy_payload",
        )
        for i in range(1, 11)
    ]

    # Evaluator predicate simulating downstream consumer crashing on "poison_pill"
    def downstream_evaluator(batch: list[RecordedEvent]) -> bool:
        return not any(b"poison_pill" in ev.payload for ev in batch)

    poison_ev = bisect_failing_event(events, downstream_evaluator)
    assert poison_ev is not None
    assert poison_ev.seq_id == 7
    assert poison_ev.event_id == "ev_7"
    assert poison_ev.payload == b"poison_pill"
