"""Tests for OBC Vehicle CAN/CAN-FD Stress Stream Generator and Cross-Repo Fault Bisection."""

import json
from pathlib import Path
import sys
import pytest

from event_replay.domain.can import CanFdFrame
from event_replay.domain.diagnostics import (
    PGN_DM1_ACTIVE_DTC,
    J1939DTC,
    J1939DiagnosticMessage,
    LampStatus,
)
from event_replay.domain.stress_generator import (
    ObcStressScenarioConfig,
    generate_obc_stress_stream,
    export_stress_stream_to_candump,
    export_stress_stream_to_event_replay_jsonl,
    synthesize_j1939_dm1_fault_frame,
    synthesize_obc_telemetry_payload,
    synthesize_obc_status_payload,
    synthesize_iso15118_evcc_payload,
    SPN_OBC_DCLINK_OVP,
    SPN_OBC_BATT_OVP,
    SPN_OBC_PFC_OCP,
    SPN_OBC_THERMAL_SHUTDOWN,
    SPN_OBC_EMERGENCY_STOP,
    SPN_OBC_GRID_ISLANDING,
)
from event_replay.interfaces.cli import main


def test_obc_stress_config_validation():
    """Verify scenario configuration invariants and bounds checking."""
    cfg = ObcStressScenarioConfig(duration_ms=50.0)
    assert cfg.duration_ms == 50.0
    assert cfg.enable_can_fd is True

    with pytest.raises(ValueError, match="strictly positive"):
        ObcStressScenarioConfig(duration_ms=0.0)

    with pytest.raises(ValueError, match="strictly positive"):
        ObcStressScenarioConfig(telemetry_interval_ms=-1.0)

    with pytest.raises(ValueError, match="within"):
        ObcStressScenarioConfig(duration_ms=50.0, fault_injection_time_ms=60.0)


def test_payload_synthesizers():
    """Test binary encoders for fast telemetry, J1939 status, and ISO 15118 EVCC."""
    telem_32 = synthesize_obc_telemetry_payload(400.0, 390.0, 10.0, 8.0, is_64_byte=False)
    assert len(telem_32) == 32

    telem_64 = synthesize_obc_telemetry_payload(400.0, 390.0, 10.0, 8.0, is_64_byte=True)
    assert len(telem_64) == 64

    status_8 = synthesize_obc_status_payload(400.0, 390.0, 8.0, 10.0, state_code=2, zvs=True)
    assert len(status_8) == 8
    # Status byte check
    assert (status_8[7] & 0x07) == 2
    assert (status_8[7] & 0x08) != 0

    evcc_8 = synthesize_iso15118_evcc_payload(
        v_target=395.0,
        i_limit=8.0,
        soc=0.65,
        contactor_closed=True,
        charging_enable=True,
    )
    assert len(evcc_8) == 8
    assert (evcc_8[0] & 0x10) != 0  # Contactor closed
    assert (evcc_8[0] & 0x20) != 0  # Charging enable


def test_j1939_dm1_fault_frame_synthesis():
    """Test synthesis and decoding of J1939 DM1 Red Stop fault frame."""
    frame = synthesize_j1939_dm1_fault_frame(
        spn=SPN_OBC_GRID_ISLANDING,
        fmi=3,
        sa=0xE5,
        timestamp_us=25000,
        channel="can0",
    )
    assert frame.is_extended_id is True
    assert frame.is_fd is False
    assert frame.timestamp_us == 25000
    assert frame.channel == "can0"

    pgn = (frame.arbitration_id >> 8) & 0x3FFFF
    assert pgn == PGN_DM1_ACTIVE_DTC
    sa = frame.arbitration_id & 0xFF
    assert sa == 0xE5

    # Decode DM1 payload
    dm1 = J1939DiagnosticMessage.decode_payload(pgn, frame.data)
    assert dm1.is_dm1 is True
    assert dm1.lamp_state.red_stop_lamp == LampStatus.ON
    assert len(dm1.dtcs) == 1
    assert dm1.dtcs[0].spn == SPN_OBC_GRID_ISLANDING
    assert dm1.dtcs[0].fmi == 3


def test_obc_stress_stream_generation():
    """Test generation of sorted multi-protocol CAN/CAN-FD frame sequence."""
    config = ObcStressScenarioConfig(
        duration_ms=50.0,
        telemetry_interval_ms=1.0,
        status_interval_ms=10.0,
        iso15118_interval_ms=5.0,
        uds_poll_interval_ms=20.0,
        fault_injection_time_ms=25.0,
        fault_spn=SPN_OBC_THERMAL_SHUTDOWN,
    )
    frames = generate_obc_stress_stream(config)

    assert len(frames) > 50
    # Chronological sort check
    for i in range(len(frames) - 1):
        assert frames[i].timestamp_us <= frames[i + 1].timestamp_us

    # Check presence of fault frame
    dm1_frames = [
        f for f in frames if ((f.arbitration_id >> 8) & 0x3FFFF) == PGN_DM1_ACTIVE_DTC
    ]
    assert len(dm1_frames) == 1
    assert dm1_frames[0].timestamp_us == 25000


def test_candump_and_jsonl_export(tmp_path):
    """Test exporting stress frames to .candump and .jsonl files."""
    config = ObcStressScenarioConfig(
        duration_ms=20.0,
        fault_injection_time_ms=10.0,
        fault_spn=SPN_OBC_PFC_OCP,
    )
    frames = generate_obc_stress_stream(config)

    candump_path = tmp_path / "stress.candump"
    jsonl_path = tmp_path / "stress.jsonl"

    c_count = export_stress_stream_to_candump(frames, candump_path)
    j_count = export_stress_stream_to_event_replay_jsonl(frames, jsonl_path)

    assert c_count == len(frames)
    assert j_count == len(frames)
    assert candump_path.exists()
    assert jsonl_path.exists()

    candump_text = candump_path.read_text(encoding="utf-8")
    assert "can0 18FF51E5##1" in candump_text  # Fast CAN-FD
    assert "can0 18FECAE5#" in candump_text    # J1939 DM1


def test_cli_generate_obc_stress(tmp_path, capsys):
    """Test CLI subcommand generate-obc-stress."""
    candump_out = tmp_path / "cli_stress.candump"
    jsonl_out = tmp_path / "cli_stress.jsonl"

    ret = main([
        "generate-obc-stress",
        "--duration-ms", "30.0",
        "--fault-ms", "15.0",
        "--fault-spn", str(SPN_OBC_EMERGENCY_STOP),
        "--out-candump", str(candump_out),
        "--out-jsonl", str(jsonl_out),
    ])
    assert ret == 0

    captured = capsys.readouterr()
    res = json.loads(captured.out)
    assert res["status"] == "success"
    assert res["total_frames_generated"] > 30
    assert res["fault_injected"] is True
    assert candump_out.exists()
    assert jsonl_out.exists()


def test_cross_repo_obc_bisection_isolation(tmp_path):
    """Cross-repo integration: Inject fault via event-replay stress stream and isolate via PE_FW_WS."""
    # Find PE_FW_WS dynamically relative to event-replay
    workspace_root = Path(__file__).resolve().parents[2]
    pe_fw_src = workspace_root / "PE_FW_WS" / "src"

    if not pe_fw_src.exists():
        pytest.skip("PE_FW_WS repository not found in workspace")

    if str(pe_fw_src) not in sys.path:
        sys.path.insert(0, str(pe_fw_src))

    from sil_runner.simulation.cascade_harness import CascadeObcHarness
    from sil_runner.simulation.cascade_plant import CascadeObcPlant
    from sil_runner.interfaces.replay_adapter import SilEventReplayer, bisect_failing_can_event

    # 1. Synthesize 50 ms stress stream with fault injected at 30 ms
    config = ObcStressScenarioConfig(
        duration_ms=50.0,
        telemetry_interval_ms=1.0,
        status_interval_ms=10.0,
        iso15118_interval_ms=5.0,
        fault_injection_time_ms=30.0,
        fault_spn=SPN_OBC_GRID_ISLANDING,
    )
    frames = generate_obc_stress_stream(config)

    # 2. Export to candump
    candump_file = tmp_path / "cross_repo_stress.candump"
    export_stress_stream_to_candump(frames, candump_file)

    # 3. Load into SilEventReplayer
    harness = CascadeObcHarness(plant=CascadeObcPlant())
    replayer = SilEventReplayer(harness=harness)
    replayer.load_events_from_candump(candump_file, normalize_timestamps=False)
    events = replayer.scheduled_events
    assert len(events) == len(frames)

    # Locate expected fault index
    fault_idx = next(
        idx for idx, f in enumerate(frames)
        if ((f.arbitration_id >> 8) & 0x3FFFF) == PGN_DM1_ACTIVE_DTC
    )

    # 4. Run bisect_failing_can_event
    bisect_res = bisect_failing_can_event(
        events=events,
        harness_factory=lambda: CascadeObcHarness(plant=CascadeObcPlant()),
        duration_ms=50.0,
    )

    assert bisect_res is not None
    assert bisect_res["failing_index"] == fault_idx
    assert bisect_res["probes_executed"] <= 8
    assert "J1939 DM1 Red Stop: SPN 520197" in bisect_res["trip_reason"]


def test_f01_no_can_fd_classical_fallback():
    """F-01 Regression: Ensure enable_can_fd=False generates valid 8-byte Classical CAN frames."""
    cfg = ObcStressScenarioConfig(duration_ms=10.0, enable_can_fd=False)
    frames = generate_obc_stress_stream(cfg)
    assert len(frames) > 0
    for f in frames:
        assert not f.is_fd
        assert f.dlc <= 8


def test_f02_iso8601_second_overflow_beyond_60s(tmp_path):
    """F-02 Regression: Ensure durations >= 60s format valid ISO-8601 timestamps without crashing ReplayEngine."""
    from event_replay.domain.stream import EventStream
    from event_replay.domain.engine import ReplayEngine
    from event_replay.domain.models import ReplayConfig, ReplayClockMode
    from event_replay.adapters.dry_run_sink import DryRunSink

    cfg = ObcStressScenarioConfig(
        duration_ms=65000.0,
        telemetry_interval_ms=10000.0,
        status_interval_ms=10000.0,
        iso15118_interval_ms=10000.0,
        uds_poll_interval_ms=10000.0,
    )
    frames = generate_obc_stress_stream(cfg)
    jsonl_path = tmp_path / "long_scenario.jsonl"
    count = export_stress_stream_to_event_replay_jsonl(frames, jsonl_path)
    assert count == len(frames)

    stream = EventStream.from_jsonl(jsonl_path)
    sink = DryRunSink(session_id="test_sess")
    config = ReplayConfig(session_id="test_sess", clock_mode=ReplayClockMode.IMMEDIATE_STEP)
    engine = ReplayEngine(config=config, sink=sink)
    result = engine.run(stream.iter_events())
    assert result.events_replayed == len(frames)


def test_f03_phase_aliasing_harmonic_intervals():
    """F-03 Regression: Ensure fractional intervals (e.g. 1.5ms) do not experience phase aliasing frame drops."""
    cfg = ObcStressScenarioConfig(duration_ms=10.0, telemetry_interval_ms=1.5)
    frames = generate_obc_stress_stream(cfg)
    telem = [f for f in frames if ((f.arbitration_id >> 8) & 0x3FFFF) == 0x00FF51]
    assert [f.timestamp_us for f in telem] == [0, 1500, 3000, 4500, 6000, 7500, 9000]


def test_f04_microsecond_precise_fault_timestamp():
    """F-04 Regression: Ensure fractional fault injection times maintain microsecond precision."""
    cfg = ObcStressScenarioConfig(duration_ms=20.0, fault_injection_time_ms=12.345)
    frames = generate_obc_stress_stream(cfg)
    fault = next(f for f in frames if ((f.arbitration_id >> 8) & 0x3FFFF) == PGN_DM1_ACTIVE_DTC)
    assert fault.timestamp_us == 12345


def test_f05_config_bounds_validation():
    """F-05 Regression: Ensure all interval fields and FMI ranges are validated strictly."""
    with pytest.raises(ValueError, match="strictly positive"):
        ObcStressScenarioConfig(iso15118_interval_ms=0.0)

    with pytest.raises(ValueError, match="strictly positive"):
        ObcStressScenarioConfig(uds_poll_interval_ms=-5.0)

    with pytest.raises(ValueError, match="fault_fmi"):
        ObcStressScenarioConfig(fault_fmi=32)
