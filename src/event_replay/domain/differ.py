"""Stream differ for comparing event sequences and discovering discrepancies."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Sequence
from event_replay.domain.models import DiffResult, EventDiff, RecordedEvent

REPLAY_QUARANTINE_HEADERS = {
    "x-event-replay",
    "x-replay-session-id",
    "x-original-timestamp",
}


class StreamDiffer:
    """Compares two event streams (e.g. golden recorded stream vs replay output)
    to identify missing, unexpected, payload-mismatched, or header-mutated events.
    Robust against duplicate event IDs in at-least-once retry streams (F-02).
    """

    @staticmethod
    def is_quarantine_header(header_name: str) -> bool:
        lower = header_name.lower()
        return lower in REPLAY_QUARANTINE_HEADERS or lower.startswith("x-replay")

    @classmethod
    def diff(cls, stream_a: Sequence[RecordedEvent], stream_b: Sequence[RecordedEvent]) -> DiffResult:
        """Compare Stream A (expected) against Stream B (observed)."""
        mismatches: List[EventDiff] = []

        dict_a: Dict[str, List[RecordedEvent]] = defaultdict(list)
        dict_b: Dict[str, List[RecordedEvent]] = defaultdict(list)
        for ev in stream_a:
            dict_a[ev.event_id].append(ev)
        for ev in stream_b:
            dict_b[ev.event_id].append(ev)

        all_event_ids = sorted(set(dict_a.keys()) | set(dict_b.keys()))

        for ev_id in all_event_ids:
            list_a = dict_a.get(ev_id, [])
            list_b = dict_b.get(ev_id, [])

            if not list_b:
                for ev_a in list_a:
                    mismatches.append(
                        EventDiff(
                            seq_id=ev_a.seq_id,
                            event_id=ev_id,
                            stream_topic=ev_a.stream_topic,
                            diff_type="MISSING",
                            details=f"Event {ev_id} present in expected stream but missing in observed stream",
                        )
                    )
                continue

            if not list_a:
                for ev_b in list_b:
                    mismatches.append(
                        EventDiff(
                            seq_id=ev_b.seq_id,
                            event_id=ev_id,
                            stream_topic=ev_b.stream_topic,
                            diff_type="UNEXPECTED",
                            details=f"Unexpected event {ev_id} present in observed stream but not in expected stream",
                        )
                    )
                continue

            if len(list_a) != len(list_b):
                mismatches.append(
                    EventDiff(
                        seq_id=list_a[0].seq_id,
                        event_id=ev_id,
                        stream_topic=list_a[0].stream_topic,
                        diff_type="OCCURRENCE_MISMATCH",
                        details=f"Event {ev_id} occurrence count mismatch: expected {len(list_a)}, observed {len(list_b)}",
                    )
                )

            # Compare paired occurrences
            pair_count = min(len(list_a), len(list_b))
            for idx in range(pair_count):
                ev_a = list_a[idx]
                ev_b = list_b[idx]

                if ev_a.stream_topic != ev_b.stream_topic:
                    mismatches.append(
                        EventDiff(
                            seq_id=ev_a.seq_id,
                            event_id=ev_id,
                            stream_topic=ev_a.stream_topic,
                            diff_type="TOPIC_MISMATCH",
                            details=f"Topic expected '{ev_a.stream_topic}', observed '{ev_b.stream_topic}'",
                        )
                    )
                if ev_a.payload != ev_b.payload:
                    mismatches.append(
                        EventDiff(
                            seq_id=ev_a.seq_id,
                            event_id=ev_id,
                            stream_topic=ev_a.stream_topic,
                            diff_type="PAYLOAD_MISMATCH",
                            details=f"Payload byte mismatch: expected len={len(ev_a.payload)}, observed len={len(ev_b.payload)}",
                        )
                    )

                # Check headers symmetrically excluding quarantine markers
                all_keys = set(ev_a.headers.keys()) | set(ev_b.headers.keys())
                for k in sorted(all_keys):
                    if cls.is_quarantine_header(k):
                        continue
                    val_a = ev_a.headers.get(k)
                    val_b = ev_b.headers.get(k)
                    if val_a != val_b:
                        mismatches.append(
                            EventDiff(
                                seq_id=ev_a.seq_id,
                                event_id=ev_id,
                                stream_topic=ev_a.stream_topic,
                                diff_type="HEADER_MISMATCH",
                                details=f"Header '{k}' expected '{val_a}', observed '{val_b}'",
                            )
                        )

        is_identical = (len(mismatches) == 0 and len(stream_a) == len(stream_b))
        return DiffResult(
            identical=is_identical,
            total_a=len(stream_a),
            total_b=len(stream_b),
            mismatches=mismatches,
        )
