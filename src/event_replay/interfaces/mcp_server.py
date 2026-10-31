"""FastMCP / stdio tool interface for event-replay agent automation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from event_replay.adapters.dry_run_sink import DryRunSink
from event_replay.domain.bisect import bisect_failing_event
from event_replay.domain.differ import StreamDiffer
from event_replay.domain.engine import ReplayEngine
from event_replay.domain.models import ReplayClockMode, ReplayConfig
from event_replay.domain.stream import EventStream


def replay_stream_tool(
    stream_path: str,
    mode: str = "shift_to_current",
    speed: float = 1.0,
    dry_run: bool = True,
    out_path: str = "",
) -> str:
    """Execute time-travel replay over a recorded event stream.
    
    Arguments:
        stream_path: Local path to the recorded JSONL stream.
        mode: Replay clock mode ('shift_to_current', 'preserve_interval', or 'immediate_step').
        speed: Speed multiplier for preserve_interval mode.
        dry_run: Default True; ensures quarantine headers and no outward mutations.
        out_path: Optional output path to write quarantined replayed events.
    """
    p = Path(stream_path)
    if not p.exists():
        return json.dumps({"error": f"Stream file not found: {stream_path}"})

    stream = EventStream.from_jsonl(p)
    clock_mode = ReplayClockMode(mode)
    sink = DryRunSink(session_id="mcp_replay")

    config = ReplayConfig(
        session_id="mcp_replay",
        clock_mode=clock_mode,
        speed_multiplier=speed,
        dry_run=dry_run,
    )
    engine = ReplayEngine(config=config, sink=sink)
    result = engine.run(stream.iter_events())

    if out_path:
        out_stream = EventStream("mcp_output")
        for ev in sink.emitted_events:
            out_stream.append_raw(ev)
        out_stream.to_jsonl(Path(out_path))

    return json.dumps({
        "status": "SUCCESS" if result.success else "FAILED",
        "events_replayed": result.events_replayed,
        "dry_run": dry_run,
        "clock_mode": mode,
        "quarantine_verified": result.quarantine_verified,
    }, indent=2)


def diff_streams_tool(stream_a_path: str, stream_b_path: str) -> str:
    """Compare two event streams (expected vs observed) and report discrepancies."""
    p_a = Path(stream_a_path)
    p_b = Path(stream_b_path)
    if not p_a.exists() or not p_b.exists():
        return json.dumps({"error": "One or both stream files do not exist"})

    stream_a = EventStream.from_jsonl(p_a)
    stream_b = EventStream.from_jsonl(p_b)

    diff_res = StreamDiffer.diff(list(stream_a.iter_events()), list(stream_b.iter_events()))
    return json.dumps({
        "identical": diff_res.identical,
        "total_a": diff_res.total_a,
        "total_b": diff_res.total_b,
        "mismatches": [
            {
                "event_id": m.event_id,
                "topic": m.stream_topic,
                "type": m.diff_type,
                "details": m.details,
            }
            for m in diff_res.mismatches
        ],
    }, indent=2, ensure_ascii=False)


def inspect_stream_tool(stream_path: str, limit: int = 20, topic: str = "", grep: str = "") -> str:
    """Inspect and filter recorded events inside a stream."""
    p = Path(stream_path)
    if not p.exists():
        return json.dumps({"error": f"Stream file not found: {stream_path}"})

    stream = EventStream.from_jsonl(p)
    topics = [topic] if topic else None
    matches = []

    for ev in stream.iter_events(topics=topics):
        if grep:
            text = ev.payload.decode("utf-8", errors="replace")
            if grep not in text:
                continue
        matches.append({
            "seq_id": ev.seq_id,
            "event_id": ev.event_id,
            "topic": ev.stream_topic,
            "timestamp": ev.timestamp_utc,
            "payload_snippet": ev.payload.decode("utf-8", errors="replace")[:100],
            "headers": ev.headers,
        })
        if len(matches) >= limit:
            break

    return json.dumps({"total_matches": len(matches), "events": matches}, indent=2, ensure_ascii=False)


def bisect_stream_tool(stream_path: str, failing_keyword: str) -> str:
    """Bisect a stream to isolate the earliest poison pill event containing the failing keyword."""
    p = Path(stream_path)
    if not p.exists():
        return json.dumps({"error": f"Stream file not found: {stream_path}"})

    stream = EventStream.from_jsonl(p)
    kw_bytes = failing_keyword.encode("utf-8")

    def predicate(batch) -> bool:
        return not any(kw_bytes in ev.payload for ev in batch)

    poison_ev = bisect_failing_event(list(stream.iter_events()), predicate)
    if poison_ev:
        return json.dumps({
            "poison_pill_found": True,
            "seq_id": poison_ev.seq_id,
            "event_id": poison_ev.event_id,
            "topic": poison_ev.stream_topic,
            "timestamp": poison_ev.timestamp_utc,
            "payload_snippet": poison_ev.payload.decode("utf-8", errors="replace")[:150],
        }, indent=2)
    return json.dumps({"poison_pill_found": False}, indent=2)
