"""Bisecting search algorithm for isolating poison pill events."""

from __future__ import annotations

from typing import Callable, List, Optional, Sequence
from event_replay.domain.models import RecordedEvent


def bisect_failing_event(
    events: Sequence[RecordedEvent],
    predicate: Callable[[Sequence[RecordedEvent]], bool],
) -> Optional[RecordedEvent]:
    """Find the single event causing downstream failure via binary search.
    
    Arguments:
        events: Sequence of recorded events in monotonic order.
        predicate: Callable taking a prefix of events and returning True if SUCCESS, False if FAILS.
    
    Returns:
        The earliest event whose inclusion triggers a failure in predicate, or None if no failure occurs.
    """
    if not events:
        return None

    # Verify that full sequence actually fails
    if predicate(events):
        return None  # Entire sequence passes, no poison pill

    # Binary search over prefix length
    low = 1
    high = len(events)
    failing_idx = -1

    while low <= high:
        mid = (low + high) // 2
        prefix = events[:mid]
        if predicate(prefix):
            # Passes with mid items, failure must be in the right half
            low = mid + 1
        else:
            # Fails with mid items, record candidate and check if smaller prefix also fails
            failing_idx = mid - 1
            high = mid - 1

    return events[failing_idx] if failing_idx >= 0 else None
