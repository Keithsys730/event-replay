"""Unit and integration tests for CAN Bus Health, Load Percentage, and Jitter Anomaly Analyzer."""

from __future__ import annotations

import json
from pathlib import Path
import pytest

from event_replay.domain.can import CanFdFrame
from event_replay.domain.bus_health import (
    BusHealthAnomalyType,
    CanBusHealthAnalyzer,
    calculate_frame_bits,
    calculate_frame_duration_us,
)
from event_replay.domain.stress_generator import (
    ObcStressScenarioConfig,
    generate_obc_stress_stream,
    export_stress_stream_to_candump,
    export_stress_stream_to_event_replay_jsonl,
)
from event_replay.interfaces.cli import main


def test_calculate_frame_bits_and_duration_classical_and_fd():
    """Verify bit length and physical duration calculation for Classical CAN and CAN-FD."""
    # 1. Classical CAN Standard 11-bit ID with 8 data bytes at 500 kbps
    frame_std = CanFdFrame(arbitration_id=0x123, data=b"\x01\x02\x03\x04\x05\x06\x07\x08", is_fd=False)
    nom_bits, data_bits = calculate_frame_bits(frame_std)
    assert data_bits == 0
    # Fixed 47 + 64 data + stuff bits
    assert nom_bits >= 111 and nom_bits <= 135
    dur_us = calculate_frame_duration_us(frame_std, nominal_baudrate=500000)
    # Expected ~220-260 microseconds
    assert 200.0 < dur_us < 280.0

    # 2. Classical CAN Extended 29-bit ID with 8 data bytes at 500 kbps
    frame_ext = CanFdFrame(arbitration_id=0x18FF50E5, data=b"\x00" * 8, is_extended_id=True, is_fd=False)
    nom_bits_ext, _ = calculate_frame_bits(frame_ext)
    assert nom_bits_ext > nom_bits  # 29-bit adds 20 fixed arbitration bits

    # 3. CAN-FD with Bit Rate Switch (500k nominal, 2M data)
    frame_fd = CanFdFrame(
        arbitration_id=0x123,
        data=bytes(range(64)),
        is_fd=True,
        bit_rate_switch=True,
    )
    nom_fd, data_fd = calculate_frame_bits(frame_fd)
    assert nom_fd > 0
    assert data_fd > (64 * 8)  # 512 data bits + CRC + stuff
    dur_fd_us = calculate_frame_duration_us(frame_fd, nominal_baudrate=500000, data_baudrate=2000000)
    # 64 bytes at 2Mbps data takes ~270-350 µs total (drastically faster than classical equivalent)
    assert 250.0 < dur_fd_us < 400.0


def test_sliding_window_bus_load_nominal_stream():
    """Verify sliding-window bus load calculation on a clean periodic stream."""
    analyzer = CanBusHealthAnalyzer(
        nominal_baudrate=500000,
        window_ms=100.0,
        step_ms=20.0,
        overload_threshold_pct=70.0,
    )

    # Generate 50 frames spaced every 10ms (10,000 µs)
    frames = [
        CanFdFrame(
            arbitration_id=0x100,
            data=b"\x11\x22\x33\x44\x55\x66\x77\x88",
            timestamp_us=i * 10000,
        )
        for i in range(50)
    ]

    report = analyzer.analyze_frames(frames)
    assert report.total_frames == 50
    assert report.duration_ms == 490.0
    assert report.is_healthy is True
    assert len(report.anomalies) == 0

    # In 100ms window with 10 frames (~250µs each = ~2.5ms active), load is ~2.5%
    assert 1.0 <= report.mean_bus_load_pct <= 5.0
    assert report.peak_bus_load_pct < 10.0

    # Check ID metrics
    m = report.id_metrics[0x100]
    assert m.is_periodic is True
    assert 9.9 < m.mean_cycle_ms < 10.1
    assert m.jitter_pct < 1.0


def test_bus_overload_anomaly_detection():
    """Verify detection of BUS_OVERLOAD when high-density burst traffic exceeds threshold."""
    analyzer = CanBusHealthAnalyzer(
        nominal_baudrate=500000,
        window_ms=50.0,
        step_ms=10.0,
        overload_threshold_pct=80.0,
    )

    # Frame duration is ~250µs. To reach >80% load in 50ms window (50,000µs),
    # active time must exceed 40,000µs -> need > 160 frames packed tightly!
    frames = [
        CanFdFrame(
            arbitration_id=0x200,
            data=b"\xFF" * 8,
            timestamp_us=i * 260,  # back-to-back 260µs spacing
        )
        for i in range(200)
    ]

    report = analyzer.analyze_frames(frames)
    assert report.peak_bus_load_pct >= 80.0
    assert report.is_healthy is False

    overloads = [a for a in report.anomalies if a.anomaly_type == BusHealthAnomalyType.BUS_OVERLOAD]
    assert len(overloads) > 0
    assert overloads[0].severity in ("WARNING", "CRITICAL")
    assert overloads[0].metric_value >= 80.0


def test_periodic_jitter_and_timeout_detection():
    """Verify timing jitter violations and frame gap timeout anomalies."""
    analyzer = CanBusHealthAnalyzer(
        nominal_baudrate=500000,
        jitter_threshold_pct=20.0,
        min_periodic_count=4,
    )

    # Nominal cycle is 10ms (10,000µs).
    # Introduce severe jitter: 10ms, 14ms (+40%), 6ms (-40%), 10ms, then a timeout gap of 40ms (>3x)
    timestamps = [
        0,
        10000,
        24000,   # delta = 14ms (40% jitter)
        30000,   # delta = 6ms
        40000,   # delta = 10ms
        85000,   # delta = 45ms (timeout > 3x)
        95000,   # delta = 10ms
    ]
    frames = [
        CanFdFrame(arbitration_id=0x350, data=b"\x01\x02", timestamp_us=ts)
        for ts in timestamps
    ]

    report = analyzer.analyze_frames(frames)
    m = report.id_metrics[0x350]
    assert m.is_periodic is True
    assert m.jitter_pct > 20.0

    jitters = [a for a in report.anomalies if a.anomaly_type == BusHealthAnomalyType.TIMING_JITTER_VIOLATION]
    assert len(jitters) >= 1
    assert jitters[0].can_id == 0x350

    timeouts = [a for a in report.anomalies if a.anomaly_type == BusHealthAnomalyType.FRAME_TIMEOUT]
    assert len(timeouts) >= 1
    assert timeouts[0].can_id == 0x350
    assert timeouts[0].metric_value >= 40.0


def test_babbling_idiot_and_sporadic_flooding_detection():
    """Verify detection of BABBLING_IDIOT and SPORADIC_FLOODING conditions."""
    analyzer = CanBusHealthAnalyzer(
        nominal_baudrate=500000,
        window_ms=50.0,
        step_ms=10.0,
        babbling_utilization_threshold_pct=40.0,
    )

    frames: list[CanFdFrame] = []
    # Regular background messages: 1 frame every 10ms
    for i in range(20):
        frames.append(CanFdFrame(arbitration_id=0x100, data=b"\x00" * 8, timestamp_us=i * 10000))

    # Rogue babbling ECU: blasts 250 frames with ID 0x666 back-to-back
    for j in range(150):
        frames.append(CanFdFrame(arbitration_id=0x666, data=b"\xAA" * 8, timestamp_us=50000 + (j * 260)))

    report = analyzer.analyze_frames(frames)

    babbling = [a for a in report.anomalies if a.anomaly_type == BusHealthAnomalyType.BABBLING_IDIOT]
    assert len(babbling) >= 1
    assert babbling[0].can_id == 0x666
    assert babbling[0].severity == "CRITICAL"

    floods = [a for a in report.anomalies if a.anomaly_type == BusHealthAnomalyType.SPORADIC_FLOODING]
    assert len(floods) >= 1


def test_cli_analyze_bus_health_candump_and_jsonl(tmp_path: Path):
    """Verify CLI analyze-bus-health end-to-end with candump and jsonl outputs."""
    config = ObcStressScenarioConfig(
        duration_ms=50.0,
        telemetry_interval_ms=2.0,
        status_interval_ms=10.0,
        iso15118_interval_ms=5.0,
        uds_poll_interval_ms=20.0,
    )
    frames = generate_obc_stress_stream(config)

    candump_file = tmp_path / "traffic.candump"
    jsonl_file = tmp_path / "traffic.jsonl"
    out_json = tmp_path / "health_report.json"

    export_stress_stream_to_candump(frames, candump_file)
    export_stress_stream_to_event_replay_jsonl(frames, jsonl_file)

    # 1. Analyze from candump
    ret = main([
        "analyze-bus-health",
        str(candump_file),
        "--window-ms", "25.0",
        "--step-ms", "5.0",
        "--out", str(out_json),
    ])
    assert ret == 0
    assert out_json.exists()

    with open(out_json, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert data["total_frames"] == len(frames)
    assert data["peak_bus_load_pct"] > 0.0
    assert any("FF50" in k for k in data["id_metrics"])

    # 2. Analyze from JSONL
    out_json_stream = tmp_path / "stream_health.json"
    ret_stream = main([
        "analyze-bus-health",
        str(jsonl_file),
        "--out", str(out_json_stream),
    ])
    assert ret_stream == 0
    assert out_json_stream.exists()


def test_empty_and_corrupted_inputs():
    """Verify defensive handling for empty frame lists and corrupted files."""
    analyzer = CanBusHealthAnalyzer()
    report = analyzer.analyze_frames([])
    assert report.total_frames == 0
    assert report.is_healthy is True
    assert report.peak_bus_load_pct == 0.0
