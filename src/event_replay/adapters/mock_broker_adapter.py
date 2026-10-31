"""In-memory Mock Broker and Ingestion Adapter for 100% offline testing (INV-5)."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Optional
from event_replay.domain.filters import SelfReplayFilter
from event_replay.domain.models import RecordedEvent
from event_replay.ports.ingestion import EventIngestionPort


class MockBroker:
    """Simulates an in-memory messaging broker (e.g. Kafka, RabbitMQ, MQTT) with topic queues."""

    def __init__(self) -> None:
        self._queues: Dict[str, List[RecordedEvent]] = defaultdict(list)
        self.published_count: int = 0

    def publish(self, topic: str, event: RecordedEvent) -> None:
        """Publish an event to a topic queue."""
        self._queues[topic].append(event)
        self.published_count += 1

    def poll(self, topics: List[str], max_count: int = 100) -> List[RecordedEvent]:
        """Poll events from specified topics in FIFO order."""
        result: List[RecordedEvent] = []
        for topic in topics:
            q = self._queues[topic]
            take_count = min(len(q), max_count - len(result))
            if take_count > 0:
                result.extend(q[:take_count])
                self._queues[topic] = q[take_count:]
            if len(result) >= max_count:
                break
        return result

    def clear(self) -> None:
        self._queues.clear()
        self.published_count = 0


class MockBrokerIngestionAdapter(EventIngestionPort):
    """Ingestion Adapter polling from MockBroker with SelfReplayFilter protection."""

    def __init__(self, broker: MockBroker, subscribed_topics: List[str]) -> None:
        self.broker = broker
        self.subscribed_topics = list(subscribed_topics)
        self.acked_events: List[RecordedEvent] = []
        self.dropped_self_replays: int = 0
        self._is_closed: bool = False

    def poll_events(self, max_count: int = 100, timeout_seconds: float = 1.0) -> List[RecordedEvent]:
        if self._is_closed:
            raise RuntimeError("Adapter is closed")

        raw_events = self.broker.poll(self.subscribed_topics, max_count=max_count)
        filtered_events: List[RecordedEvent] = []

        for ev in raw_events:
            # INV-1: Anti-Self-Replay Storm protection
            if SelfReplayFilter.is_replayed_event(ev):
                self.dropped_self_replays += 1
                continue
            filtered_events.append(ev)

        return filtered_events

    def ack(self, event: RecordedEvent) -> None:
        self.acked_events.append(event)

    def close(self) -> None:
        self._is_closed = True
