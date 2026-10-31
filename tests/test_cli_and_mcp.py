"""Unit tests for TB-4: CLI runner and FastMCP stdio tool interface."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from event_replay.domain.stream import EventStream
from event_replay.interfaces.cli import main as cli_main
from event_replay.interfaces.mcp_server import (
    bisect_stream_tool,
    diff_streams_tool,
    inspect_stream_tool,
    replay_stream_tool,
)


def create_sample_stream(file_path: Path) -> None:
    stream = EventStream("sample")
    stream.append("ev_1", "orders.created", "2026-10-31T10:00:00Z", b'{"order": "1", "val": 100}', headers={"trace": "t1"})
    stream.append("ev_2", "payment.charged", "2026-10-31T10:01:00Z", b'{"order": "1", "status": "paid"}', headers={"trace": "t1"})
    stream.append("ev_3", "orders.failed", "2026-10-31T10:02:00Z", b'{"error": "poison_bomb"}', headers={"trace": "t2"})
    stream.to_jsonl(file_path)


def test_cli_inspect_and_grep(tmp_path: Path, capsys):
    """CLI inspect filters events by topic and payload substring."""
    stream_path = tmp_path / "test.jsonl"
    create_sample_stream(stream_path)

    # Inspect with topic filter
    code = cli_main(["inspect", str(stream_path), "--topic", "payment.charged"])
    assert code == 0
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert res["total_matches"] == 1
    assert res["events"][0]["event_id"] == "ev_2"

    # Inspect with grep filter
    code = cli_main(["inspect", str(stream_path), "--grep", "poison_bomb"])
    assert code == 0
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert res["total_matches"] == 1
    assert res["events"][0]["event_id"] == "ev_3"


def test_cli_replay_and_diff(tmp_path: Path, capsys):
    """CLI replay executes quarantined replay and diff confirms identical output."""
    in_path = tmp_path / "in.jsonl"
    out_path = tmp_path / "out.jsonl"
    create_sample_stream(in_path)

    code_rep = cli_main(["replay", str(in_path), "--mode", "immediate_step", "--out", str(out_path)])
    assert code_rep == 0
    capsys.readouterr()

    # Replayed output must exist and be loadable
    assert out_path.exists()
    replayed_stream = EventStream.from_jsonl(out_path)
    assert replayed_stream.count == 3

    # Diff in vs out: should show identical payloads (quarantine headers are ignored in semantic payload diff)
    code_diff = cli_main(["diff", str(in_path), str(out_path)])
    assert code_diff == 0
    captured = capsys.readouterr()
    diff_report = json.loads(captured.out)
    assert diff_report["identical"] is True


def test_cli_bisect(tmp_path: Path, capsys):
    """CLI bisect isolates poison pill event."""
    stream_path = tmp_path / "bisect.jsonl"
    create_sample_stream(stream_path)

    code = cli_main(["bisect", str(stream_path), "--failing-keyword", "poison_bomb"])
    assert code == 0
    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert res["poison_pill_found"] is True
    assert res["event_id"] == "ev_3"


def test_mcp_tools(tmp_path: Path):
    """FastMCP tools interface delivers structured results."""
    stream_path = tmp_path / "mcp_test.jsonl"
    out_path = tmp_path / "mcp_out.jsonl"
    create_sample_stream(stream_path)

    # 1. inspect_stream_tool
    inspect_json = inspect_stream_tool(str(stream_path), topic="orders.created")
    inspect_data = json.loads(inspect_json)
    assert inspect_data["total_matches"] == 1

    # 2. replay_stream_tool
    replay_json = replay_stream_tool(str(stream_path), mode="shift_to_current", out_path=str(out_path))
    replay_data = json.loads(replay_json)
    assert replay_data["status"] == "SUCCESS"
    assert replay_data["events_replayed"] == 3
    assert replay_data["quarantine_verified"] is True

    # 3. diff_streams_tool
    diff_json = diff_streams_tool(str(stream_path), str(out_path))
    diff_data = json.loads(diff_json)
    assert diff_data["identical"] is True

    # 4. bisect_stream_tool
    bisect_json = bisect_stream_tool(str(stream_path), failing_keyword="poison_bomb")
    bisect_data = json.loads(bisect_json)
    assert bisect_data["poison_pill_found"] is True
    assert bisect_data["event_id"] == "ev_3"
