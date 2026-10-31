"""Unit tests for TB-1: Core RecordedEvent, EventStream, and CausalSequencer."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from event_replay.domain.models import RecordedEvent
from event_replay.domain.stream import CausalSequencer, EventStream


def test_recorded_event_integrity_verification():
    """Event computes SHA-256 over topic and payload; tampering triggers integrity failure."""
    ev = RecordedEvent.create(
        seq_id=1,
        event_id="ev_001",
        stream_topic="orders.checkout",
        timestamp_utc="2026-10-31T12:00:00Z",
        payload=b'{"order_id": "ORD-99", "amount": 1200}',
        headers={"Trace-Id": "trc_123"},
    )

    assert ev.verify_integrity() is True
    assert len(ev.checksum_sha256) == 64

    # Tamper payload
    tampered = RecordedEvent(
        seq_id=ev.seq_id,
        event_id=ev.event_id,
        stream_topic=ev.stream_topic,
        partition_key=ev.partition_key,
        timestamp_utc=ev.timestamp_utc,
        headers=ev.headers,
        payload=b'{"order_id": "ORD-99", "amount": 0}',  # altered
        checksum_sha256=ev.checksum_sha256,
    )
    assert tampered.verify_integrity() is False


def test_event_stream_monotonicity_and_filtering(tmp_path: Path):
    """EventStream enforces monotonically increasing sequence IDs and zero-copy streaming filters."""
    stream = EventStream("test_stream")
    e1 = stream.append("id_1", "topic.a", "2026-10-31T10:00:00Z", b"data1")
    e2 = stream.append("id_2", "topic.b", "2026-10-31T10:05:00Z", b"data2")
    e3 = stream.append("id_3", "topic.a", "2026-10-31T10:10:00Z", b"data3")

    assert e1.seq_id == 1
    assert e2.seq_id == 2
    assert e3.seq_id == 3
    assert stream.count == 3

    # Filter by topic
    topic_a_events = list(stream.iter_events(topics=["topic.a"]))
    assert len(topic_a_events) == 2
    assert [e.seq_id for e in topic_a_events] == [1, 3]

    # Filter by time window
    window_events = list(stream.iter_events(time_start="2026-10-31T10:02:00Z", time_end="2026-10-31T10:08:00Z"))
    assert len(window_events) == 1
    assert window_events[0].seq_id == 2


def test_event_stream_jsonl_roundtrip_bit_exact(tmp_path: Path):
    """INV-4: Binary payload is preserved bit-exact without deserialization corruption."""
    stream = EventStream("binary_stream")
    # Binary payload with non-UTF8 raw bytes (e.g. simulated Protobuf / Gzip)
    binary_data = b"\x00\x01\xfe\xff\x1b\x99\xde\xad\xbe\xef\xca\xfe"
    stream.append(
        event_id="bin_01",
        stream_topic="telemetry.sensor",
        timestamp_utc="2026-10-31T12:00:00Z",
        payload=binary_data,
        headers={"Content-Type": "application/octet-stream"},
    )

    out_file = tmp_path / "stream_dump.jsonl"
    stream.to_jsonl(out_file)

    loaded = EventStream.from_jsonl(out_file)
    assert loaded.count == 1
    loaded_ev = list(loaded.iter_events())[0]

    assert loaded_ev.payload == binary_data
    assert loaded_ev.verify_integrity() is True
    assert loaded_ev.headers["Content-Type"] == "application/octet-stream"


def test_causal_sequencer_interleaved_ordering():
    """INV-3: Out-of-order events pushed from different topics are yielded in strict causal sequence order."""
    sequencer = CausalSequencer()

    ev_3 = RecordedEvent.create(seq_id=3, event_id="3", stream_topic="invoice", timestamp_utc="2026-10-31T12:02:00Z", payload=b"c")
    ev_1 = RecordedEvent.create(seq_id=1, event_id="1", stream_topic="orders", timestamp_utc="2026-10-31T12:00:00Z", payload=b"a")
    ev_2 = RecordedEvent.create(seq_id=2, event_id="2", stream_topic="payment", timestamp_utc="2026-10-31T12:01:00Z", payload=b"b")

    # Push out of order: 3, 1, 2
    sequencer.push(ev_3)
    sequencer.push(ev_1)
    sequencer.push(ev_2)

    ordered = list(sequencer.drain_all())
    assert [ev.seq_id for ev in ordered] == [1, 2, 3]
    assert [ev.stream_topic for ev in ordered] == ["orders", "payment", "invoice"]
