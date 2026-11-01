"""Command Line Interface (CLI) for event-replay."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional

from event_replay.adapters.dry_run_sink import DryRunSink
from event_replay.adapters.can_adapter import CanLogAdapter
from event_replay.domain.bisect import bisect_failing_event
from event_replay.domain.dbc import DbcDatabase
from event_replay.domain.differ import StreamDiffer
from event_replay.domain.diagnostics import (
    PGN_DM1_ACTIVE_DTC,
    PGN_DM2_PREV_ACTIVE_DTC,
    J1939DiagnosticMessage,
    UdsMessage,
    format_j1939_diagnostics,
    format_uds_diagnostics,
)
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

    # Subcommand: decode-can
    p_decode = subparsers.add_parser("decode-can", help="Decode CAN/CAN-FD/J1939 frames against a DBC database and diagnostics")
    p_decode.add_argument("--dbc", default=None, type=Path, help="Path to .dbc database file (optional)")
    p_decode.add_argument("--log", type=Path, default=None, help="Path to candump/CAN log file to decode")
    p_decode.add_argument("--can-id", type=str, default="", help="Single CAN arbitration ID in hex (e.g. 0x18F00400)")
    p_decode.add_argument("--payload", type=str, default="", help="Single CAN hex payload (e.g. 0102030405060708)")
    p_decode.add_argument("--no-tp", action="store_true", help="Disable SAE J1939 Transport Protocol multi-packet reassembly")
    p_decode.add_argument("--no-diag", action="store_true", help="Disable automotive diagnostic decoding (DM1/DM2, UDS)")
    p_decode.add_argument("--out", type=Path, default=None, help="Output JSON file path")

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


def cmd_decode_can(args: argparse.Namespace) -> int:
    dbc: Optional[DbcDatabase] = None
    if args.dbc is not None:
        if not args.dbc.exists():
            print(f"[ERROR] DBC file not found: {args.dbc}", file=sys.stderr)
            return 1
        dbc = DbcDatabase.from_file(args.dbc)

    output_data: Any = None

    if args.can_id is not None and args.can_id != "" and args.payload is not None:
        clean_id_str = args.can_id.strip()
        try:
            arb_id = int(clean_id_str, 0)
        except ValueError:
            arb_id = int(clean_id_str, 16)
        payload = bytes.fromhex(args.payload)
        hex_digits = clean_id_str.lower().replace("0x", "")
        is_ext = len(hex_digits) > 3 or arb_id > 0x7FF

        decoded_dict: Dict[str, Any] = {
            "can_id": f"0x{arb_id:X}",
            "raw_hex": args.payload.upper(),
            "message_name": "UNKNOWN",
        }

        if dbc is not None:
            decoded = dbc.decode_frame(arb_id, payload, is_extended_id=is_ext)
            if decoded is not None:
                decoded_dict["message_name"] = decoded["message_name"]
                decoded_dict["signals"] = decoded["signals"]

        if not args.no_diag:
            # Check J1939 DM1/DM2
            if is_ext or arb_id > 0x7FF:
                dp_edp = (arb_id >> 24) & 0x03
                pf = (arb_id >> 16) & 0xFF
                ps = (arb_id >> 8) & 0xFF
                pgn = (dp_edp << 16) | (pf << 8) | (ps if pf >= 240 else 0)
                if pgn in (PGN_DM1_ACTIVE_DTC, PGN_DM2_PREV_ACTIVE_DTC):
                    diag_msg = J1939DiagnosticMessage.decode_payload(pgn, payload)
                    decoded_dict["diagnostics"] = format_j1939_diagnostics(diag_msg)
                    if decoded_dict["message_name"] == "UNKNOWN":
                        decoded_dict["message_name"] = "DM1_ActiveDTC" if diag_msg.is_dm1 else "DM2_PrevActiveDTC"

            # Check UDS (11-bit standard diagnostic IDs or 29-bit PF=0xDA)
            is_uds = (
                (not is_ext and (arb_id == 0x7DF or arb_id in range(0x7E0, 0x7F0)))
                or (is_ext and ((arb_id >> 16) & 0xFF) == 0xDA)
            )
            if is_uds and len(payload) > 0:
                try:
                    uds_msg = UdsMessage.decode(payload, has_pci=True)
                    decoded_dict["uds"] = format_uds_diagnostics(uds_msg)
                    if decoded_dict["message_name"] == "UNKNOWN":
                        decoded_dict["message_name"] = f"UDS_{uds_msg.service_name}"
                except Exception:
                    pass

        if dbc is not None and decoded_dict["message_name"] == "UNKNOWN" and "diagnostics" not in decoded_dict and "uds" not in decoded_dict:
            print(f"[WARN] No matching DBC message found for ID 0x{arb_id:X}", file=sys.stderr)
            return 1

        output_data = decoded_dict
    elif args.log:
        if not args.log.exists():
            print(f"[ERROR] Log file not found: {args.log}", file=sys.stderr)
            return 1
        stream = CanLogAdapter.parse_log_file(args.log)
        output_data = CanLogAdapter.decode_stream(
            stream,
            dbc=dbc,
            reassemble_tp=not args.no_tp,
            decode_diagnostics=not args.no_diag,
        )
    else:
        print("[ERROR] Must provide either --log <file> or both --can-id <id> and --payload <hex>", file=sys.stderr)
        return 1

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)
        print(f"Decoded results written to {args.out}")
    else:
        print(json.dumps(output_data, indent=2, ensure_ascii=False))

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
    elif args.subcommand == "decode-can":
        return cmd_decode_can(args)
    return 1


if __name__ == "__main__":
    sys.exit(main())
