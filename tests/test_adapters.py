"""Unit tests for TB-2: Hexagonal Adapters, DryRunSink, and SelfReplayFilter."""

from __future__ import annotations

import json
import pytest

from event_replay.adapters.dry_run_sink import DryRunSink
from event_replay.adapters.mock_broker_adapter import MockBroker, MockBrokerIngestionAdapter
from event_replay.domain.filters import PIIMaskingFilter, SelfReplayFilter
from event_replay.domain.models import RecordedEvent


def test_self_replay_filter_drops_quarantined_events():
    """INV-1: Events with 'X-Event-Replay: true' must be dropped to break feedback loops."""
    normal_event = RecordedEvent.create(
        seq_id=1,
        event_id="e1",
        stream_topic="orders",
        timestamp_utc="2026-10-31T12:00:00Z",
        payload=b"user_action",
        headers={"Content-Type": "application/json"},
    )
    replayed_event = RecordedEvent.create(
        seq_id=2,
        event_id="e2",
        stream_topic="orders",
        timestamp_utc="2026-10-31T12:00:00Z",
        payload=b"user_action",
        headers={"X-Event-Replay": "true", "X-Replay-Session-Id": "ses_99"},
    )

    assert SelfReplayFilter.is_replayed_event(normal_event) is False
    assert SelfReplayFilter.is_replayed_event(replayed_event) is True

    assert SelfReplayFilter.filter(normal_event) == normal_event
    assert SelfReplayFilter.filter(replayed_event) is None


def test_dry_run_sink_quarantine_header_injection_and_overrides():
    """DryRunSink injects mandatory quarantine headers and applies header overrides."""
    sink = DryRunSink(
        session_id="session_abc_123",
        header_overrides={"Authorization": "Bearer fresh_token_999"},
    )

    original_event = RecordedEvent.create(
        seq_id=1,
        event_id="e1",
        stream_topic="billing.charge",
        timestamp_utc="2026-10-31T10:00:00Z",
        payload=b'{"charge": 500}',
        headers={"Authorization": "Bearer expired_old_token", "X-Correlation-Id": "c_1"},
    )

    success = sink.emit(original_event, dry_run=True)
    assert success is True
    assert sink.count == 1

    emitted = sink.emitted_events[0]
    # Check mandatory quarantine headers
    assert emitted.headers["X-Event-Replay"] == "true"
    assert emitted.headers["X-Replay-Session-Id"] == "session_abc_123"
    assert emitted.headers["X-Original-Timestamp"] == "2026-10-31T10:00:00Z"
    # Check header override applied
    assert emitted.headers["Authorization"] == "Bearer fresh_token_999"
    # Preserves non-conflicting original headers
    assert emitted.headers["X-Correlation-Id"] == "c_1"
    # Check payload fidelity
    assert emitted.payload == b'{"charge": 500}'


def test_mock_broker_ingestion_and_self_replay_containment():
    """MockBrokerIngestionAdapter ingests across topics and prevents self-replay ingestion."""
    broker = MockBroker()
    adapter = MockBrokerIngestionAdapter(broker, subscribed_topics=["telemetry", "events"])

    ev1 = RecordedEvent.create(seq_id=1, event_id="1", stream_topic="telemetry", timestamp_utc="2026-10-31T12:00:00Z", payload=b"t1")
    # A replayed event that was accidentally published to the broker
    ev_replay = RecordedEvent.create(
        seq_id=2,
        event_id="2",
        stream_topic="events",
        timestamp_utc="2026-10-31T12:01:00Z",
        payload=b"replayed_t2",
        headers={"x-event-replay": "TRUE"},  # case-insensitive check
    )
    ev3 = RecordedEvent.create(seq_id=3, event_id="3", stream_topic="events", timestamp_utc="2026-10-31T12:02:00Z", payload=b"t3")

    broker.publish("telemetry", ev1)
    broker.publish("events", ev_replay)
    broker.publish("events", ev3)

    polled = adapter.poll_events(max_count=10)
    assert len(polled) == 2
    assert [e.event_id for e in polled] == ["1", "3"]
    assert adapter.dropped_self_replays == 1

    # Test ACK
    adapter.ack(polled[0])
    assert len(adapter.acked_events) == 1
    assert adapter.acked_events[0].event_id == "1"


def test_pii_masking_filter():
    """Sensitive credential and PII keys are redacted from headers and JSON payloads."""
    headers = {
        "Content-Type": "application/json",
        "Authorization": "Bearer super_secret_token",
        "X-Api-Key": "key_12345",
    }
    masked_headers = PIIMaskingFilter.mask_headers(headers)
    assert masked_headers["Content-Type"] == "application/json"
    assert masked_headers["Authorization"] == "[REDACTED]"
    assert masked_headers["X-Api-Key"] == "[REDACTED]"

    json_payload = json.dumps({
        "user": "Alice",
        "secret_token": "abc_xyz",
        "nested": {"password": "p@ssword", "active": True}
    }).encode("utf-8")

    masked_payload = PIIMaskingFilter.mask_payload_if_json(json_payload)
    data = json.loads(masked_payload.decode("utf-8"))
    assert data["user"] == "Alice"
    assert data["secret_token"] == "[REDACTED]"
    assert data["nested"]["password"] == "[REDACTED]"
    assert data["nested"]["active"] is True
