"""Command Line Interface (CLI) for event-replay."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional

from event_replay.adapters.dry_run_sink import DryRunSink
from event_replay.domain.bisect import bisect_failing_event
from event_replay.domain.differ import StreamDiffer
from event_replay.domain.engine import ReplayEngine
from event_replay.domain.models import (
    ReplayClockMode,
    ReplayConfig,
)
from event_replay.domain.stream import EventStream


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="event-replay",
        description="Dual-track time-travel event stream replay & data version control CLI",
    )
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # Subcommand: inspect
    p_inspect = subparsers.add_parser("inspect", help="Inspect events inside a recorded stream")
    p_inspect.add_argument("stream_path", type=Path, help="Path to JSONL stream file")
    p_inspect.add_argument("--limit", type=int, default=20, help="Max events to display")
    p_inspect.add_argument("--topic", type=str, default="", help="Filter by topic")
    p_inspect.add_argument("--grep", type=str, default="", help="Substring filter on payload")

    # Subcommand: replay
    p_replay = subparsers.add_parser("replay", help="Replay events from a recorded stream")
    p_replay.add_argument("stream_path", type=Path, help="Path to JSONL stream file")
    p_replay.add_argument(
        "--mode",
        choices=["preserve_interval", "shift_to_current", "immediate_step"],
        default="shift_to_current",
        help="Replay clock mode (default: shift_to_current)",
    )
    p_replay.add_argument("--speed", type=float, default=1.0, help="Replay speed multiplier")
    p_replay.add_argument("--dry-run", action="store_true", default=True, help="Quarantined dry-run (default: True)")
    p_replay.add_argument("--out", type=Path, default=None, help="Output JSONL path for replayed events")

    # Subcommand: diff
    p_diff = subparsers.add_parser("diff", help="Compare two event streams for discrepancies")
    p_diff.add_argument("stream_a", type=Path, help="Expected stream path")
    p_diff.add_argument("stream_b", type=Path, help="Observed stream path")

    # Subcommand: bisect
    p_bisect = subparsers.add_parser("bisect", help="Bisect a stream to isolate a poison pill event")
    p_bisect.add_argument("stream_path", type=Path, help="Path to JSONL stream file")
    p_bisect.add_argument("--failing-keyword", required=True, type=str, help="Substring triggering failure")

    return parser


def cmd_inspect(args: argparse.Namespace) -> int:
    stream = EventStream.from_jsonl(args.stream_path)
    topics = [args.topic] if args.topic else None

    matches = []
    for ev in stream.iter_events(topics=topics):
        if args.grep:
            text = ev.payload.decode("utf-8", errors="replace")
            if args.grep not in text:
                continue
        matches.append({
            "seq_id": ev.seq_id,
            "event_id": ev.event_id,
            "topic": ev.stream_topic,
            "timestamp": ev.timestamp_utc,
            "payload_len": len(ev.payload),
            "headers": ev.headers,
        })
        if len(matches) >= args.limit:
            break

    print(json.dumps({"total_matches": len(matches), "events": matches}, indent=2, ensure_ascii=False))
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    stream = EventStream.from_jsonl(args.stream_path)
    clock_mode = ReplayClockMode(args.mode)
    sink = DryRunSink(session_id="cli_replay")

    config = ReplayConfig(
        session_id="cli_replay",
        clock_mode=clock_mode,
        speed_multiplier=args.speed,
        dry_run=args.dry_run,
    )
    engine = ReplayEngine(config=config, sink=sink)
    result = engine.run(stream.iter_events())

    if args.out:
        out_stream = EventStream("replayed_output")
        for ev in sink.emitted_events:
            out_stream.append_raw(ev)
        out_stream.to_jsonl(args.out)

    output = {
        "session_id": result.session_id,
        "events_replayed": result.events_replayed,
        "success": result.success,
        "dry_run": args.dry_run,
        "clock_mode": args.mode,
    }
    print(json.dumps(output, indent=2))
    return 0 if result.success else 1


def cmd_diff(args: argparse.Namespace) -> int:
    stream_a = EventStream.from_jsonl(args.stream_a)
    stream_b = EventStream.from_jsonl(args.stream_b)

    diff_res = StreamDiffer.diff(list(stream_a.iter_events()), list(stream_b.iter_events()))
    report = {
        "identical": diff_res.identical,
        "total_a": diff_res.total_a,
        "total_b": diff_res.total_b,
        "mismatch_count": len(diff_res.mismatches),
        "mismatches": [
            {
                "seq_id": m.seq_id,
                "event_id": m.event_id,
                "topic": m.stream_topic,
                "type": m.diff_type,
                "details": m.details,
            }
            for m in diff_res.mismatches
        ],
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if diff_res.identical else 1


def cmd_bisect(args: argparse.Namespace) -> int:
    stream = EventStream.from_jsonl(args.stream_path)
    keyword_bytes = args.failing_keyword.encode("utf-8")

    def predicate(batch) -> bool:
        return not any(keyword_bytes in ev.payload for ev in batch)

    poison_ev = bisect_failing_event(list(stream.iter_events()), predicate)
    if poison_ev:
        res = {
            "poison_pill_found": True,
            "seq_id": poison_ev.seq_id,
            "event_id": poison_ev.event_id,
            "topic": poison_ev.stream_topic,
            "timestamp": poison_ev.timestamp_utc,
            "payload_snippet": poison_ev.payload.decode("utf-8", errors="replace")[:100],
        }
    else:
        res = {"poison_pill_found": False}

    print(json.dumps(res, indent=2, ensure_ascii=False))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.subcommand == "inspect":
        return cmd_inspect(args)
    elif args.subcommand == "replay":
        return cmd_replay(args)
    elif args.subcommand == "diff":
        return cmd_diff(args)
    elif args.subcommand == "bisect":
        return cmd_bisect(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
