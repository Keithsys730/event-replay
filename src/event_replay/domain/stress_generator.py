"""OBC Vehicle CAN/CAN-FD Stress Stream Generator and Injected Fault Synthesizer.

Synthesizes high-frequency, multi-protocol automotive bus traffic:
1. High-rate fast CAN-FD telemetry (PGN 0x00FF51, 32 or 64 bytes).
2. J1939 OBC Status (PGN 0x00FF50, 8 bytes).
3. ISO 15118 EVCC Demand (PGN 0x00FF60) and SECC Status (PGN 0x00FF61).
4. ISO 14229 UDS Diagnostic Requests (DID 0x0100..0x0106, TesterPresent).
5. Precise microsecond fault frame injection (J1939 DM1 PGN 0x00FECA) for SIL O(log N) bisection.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import math
from pathlib import Path
import struct
from typing import Any, Dict, List, Optional, Tuple

from event_replay.domain.can import CanFdFrame
from event_replay.domain.diagnostics import (
    PGN_DM1_ACTIVE_DTC,
    J1939DTC,
    J1939DiagnosticMessage,
    J1939LampState,
    LampStatus,
)
from event_replay.domain.models import RecordedEvent
from event_replay.domain.stream import EventStream


# Well-known OBC PGNs and Addresses
PGN_OBC_STATUS = 0x00FF50
PGN_OBC_TELEMETRY = 0x00FF51
PGN_ISO15118_EVCC = 0x00FF60
PGN_ISO15118_SECC = 0x00FF61
CAN_SA_OBC = 0xE5
CAN_SA_EVCC = 0xF4
CAN_SA_TESTER = 0xF9
CAN_ID_UDS_REQ = 0x7E0
CAN_ID_UDS_FUNC = 0x7DF

# Standard OBC Diagnostic Fault SPNs
SPN_OBC_DCLINK_OVP = 520192
SPN_OBC_BATT_OVP = 520193
SPN_OBC_PFC_OCP = 520194
SPN_OBC_THERMAL_SHUTDOWN = 520195
SPN_OBC_EMERGENCY_STOP = 520196
SPN_OBC_GRID_ISLANDING = 520197


@dataclass(frozen=True)
class ObcStressScenarioConfig:
    """Configuration for synthesizing realistic OBC vehicle CAN/CAN-FD traffic."""
    duration_ms: float = 100.0
    telemetry_interval_ms: float = 1.0
    status_interval_ms: float = 10.0
    iso15118_interval_ms: float = 5.0
    uds_poll_interval_ms: float = 20.0
    channel: str = "can0"
    enable_can_fd: bool = True
    v_dclink_nominal: float = 400.0
    v_batt_nominal: float = 390.0
    i_batt_nominal: float = 8.0
    i_grid_nominal: float = 10.0
    fault_injection_time_ms: Optional[float] = None
    fault_spn: Optional[int] = None
    fault_fmi: int = 3
    seed: int = 42

    def __post_init__(self) -> None:
        if self.duration_ms <= 0.0:
            raise ValueError("duration_ms must be strictly positive")
        if (
            self.telemetry_interval_ms <= 0.0
            or self.status_interval_ms <= 0.0
            or self.iso15118_interval_ms <= 0.0
            or self.uds_poll_interval_ms <= 0.0
        ):
            raise ValueError("Intervals must be strictly positive")
        if self.fault_injection_time_ms is not None:
            if not (0.0 <= self.fault_injection_time_ms <= self.duration_ms):
                raise ValueError("fault_injection_time_ms must be within [0.0, duration_ms]")
        if not (0 <= self.fault_fmi <= 31):
            raise ValueError("fault_fmi must be within [0, 31]")


def encode_j1939_can_id(priority: int, pgn: int, sa: int) -> int:
    """Encode 29-bit J1939 CAN arbitration ID."""
    return ((priority & 0x07) << 26) | ((pgn & 0x3FFFF) << 8) | (sa & 0xFF)


def synthesize_obc_telemetry_payload(
    v_dclink: float,
    v_batt: float,
    i_grid: float,
    i_batt: float,
    pfc_duty: float = 0.18,
    llc_f_khz: float = 160.0,
    zvs: bool = True,
    tripped: bool = False,
    is_64_byte: bool = False,
) -> bytes:
    """Synthesize 32-byte or 64-byte fast CAN-FD telemetry frame payload."""
    core = struct.pack(
        ">8f",
        float(v_dclink),
        float(v_batt),
        float(i_grid),
        float(i_batt),
        float(pfc_duty),
        float(llc_f_khz),
        1.0 if zvs else 0.0,
        1.0 if tripped else 0.0,
    )
    if is_64_byte:
        # Pad with 32 bytes of thermal and auxiliary diagnostics
        aux = struct.pack(
            ">8f",
            45.0,  # T_junction (°C)
            38.0,  # T_case (°C)
            50.0,  # T_magnetics (°C)
            1.0,   # derating factor
            0.999, # True PF
            2.1,   # THD-i (%)
            230.0, # V_grid_rms (V)
            50.0,  # f_grid (Hz)
        )
        return core + aux
    return core


def synthesize_obc_status_payload(
    v_dclink: float,
    v_batt: float,
    i_batt: float,
    i_grid: float,
    state_code: int = 2,
    zvs: bool = True,
    pfc_tripped: bool = False,
    llc_tripped: bool = False,
) -> bytes:
    """Synthesize 8-byte J1939 OBC status frame payload."""
    raw_vdc = max(0, min(0xFFFF, int(round(v_dclink * 10.0))))
    raw_vbat = max(0, min(0xFFFF, int(round(v_batt * 10.0))))
    raw_ibat = max(-32768, min(32767, int(round(i_batt * 10.0))))
    raw_igrid = max(0, min(255, int(round(abs(i_grid) * 5.0))))
    status_byte = (state_code & 0x07)
    if zvs:
        status_byte |= 0x08
    if pfc_tripped:
        status_byte |= 0x10
    if llc_tripped:
        status_byte |= 0x20
    status_byte |= 0xC0
    return struct.pack(">HHhBB", raw_vdc, raw_vbat, raw_ibat, raw_igrid, status_byte)


def synthesize_iso15118_evcc_payload(
    v_target: float,
    i_limit: float,
    soc: float,
    contactor_closed: bool = True,
    charging_enable: bool = True,
    bpt_discharge: bool = False,
) -> bytes:
    """Synthesize 8-byte ISO 15118 EVCC Demand payload."""
    flags = 0x06  # CURRENT_DEMAND_CC
    if contactor_closed:
        flags |= 0x10
    if charging_enable:
        flags |= 0x20
    if bpt_discharge:
        flags |= 0x40
    raw_v = max(0, min(0xFFFF, int(round(v_target * 10.0))))
    raw_i = max(-32768, min(32767, int(round(i_limit * 10.0))))
    raw_soc = max(0, min(200, int(round(soc * 200.0))))
    return struct.pack(">BHhBBB", flags, raw_v, raw_i, raw_soc, 0xFF, 0xFF)


def synthesize_j1939_dm1_fault_frame(
    spn: int,
    fmi: int = 3,
    sa: int = CAN_SA_OBC,
    timestamp_us: int = 0,
    channel: str = "can0",
) -> CanFdFrame:
    """Synthesize an active J1939 DM1 Red Stop fault frame."""
    dtc = J1939DTC(spn=spn, fmi=fmi, cm=0, oc=1)
    lamp = J1939LampState(red_stop_lamp=LampStatus.ON)
    dm1 = J1939DiagnosticMessage(pgn=PGN_DM1_ACTIVE_DTC, lamp_state=lamp, dtcs=[dtc])
    payload = dm1.encode_payload()
    arb_id = encode_j1939_can_id(priority=6, pgn=PGN_DM1_ACTIVE_DTC, sa=sa)
    return CanFdFrame(
        arbitration_id=arb_id,
        data=payload,
        is_extended_id=True,
        is_fd=False,
        channel=channel,
        timestamp_us=timestamp_us,
    )


def generate_obc_stress_stream(config: ObcStressScenarioConfig) -> List[CanFdFrame]:
    """Generate a chronologically sorted sequence of CAN/CAN-FD frames for stress testing."""
    frames: List[CanFdFrame] = []
    total_us = int(round(config.duration_ms * 1000.0))

    telemetry_us = int(round(config.telemetry_interval_ms * 1000.0))
    status_us = int(round(config.status_interval_ms * 1000.0))
    iso15118_us = int(round(config.iso15118_interval_ms * 1000.0))
    uds_us = int(round(config.uds_poll_interval_ms * 1000.0))

    # 1. Telemetry frames (CAN-FD or 8-byte Classical fallback)
    for t in range(0, total_us + 1, telemetry_us):
        telem_id = encode_j1939_can_id(priority=6, pgn=PGN_OBC_TELEMETRY, sa=CAN_SA_OBC)
        if config.enable_can_fd:
            telem_payload = synthesize_obc_telemetry_payload(
                v_dclink=config.v_dclink_nominal,
                v_batt=config.v_batt_nominal,
                i_grid=config.i_grid_nominal,
                i_batt=config.i_batt_nominal,
                is_64_byte=True,
            )
            frames.append(
                CanFdFrame(
                    arbitration_id=telem_id,
                    data=telem_payload,
                    is_extended_id=True,
                    is_fd=True,
                    bit_rate_switch=True,
                    channel=config.channel,
                    timestamp_us=t,
                )
            )
        else:
            # Classical CAN 8-byte core fallback (e.g., 2x 32-bit float V_dc and I_batt)
            fallback_payload = struct.pack(">ff", float(config.v_dclink_nominal), float(config.i_batt_nominal))
            frames.append(
                CanFdFrame(
                    arbitration_id=telem_id,
                    data=fallback_payload,
                    is_extended_id=True,
                    is_fd=False,
                    bit_rate_switch=False,
                    channel=config.channel,
                    timestamp_us=t,
                )
            )

    # 2. Status frames (Classical CAN)
    for t in range(0, total_us + 1, status_us):
        status_id = encode_j1939_can_id(priority=3, pgn=PGN_OBC_STATUS, sa=CAN_SA_OBC)
        status_payload = synthesize_obc_status_payload(
            v_dclink=config.v_dclink_nominal,
            v_batt=config.v_batt_nominal,
            i_batt=config.i_batt_nominal,
            i_grid=config.i_grid_nominal,
        )
        frames.append(
            CanFdFrame(
                arbitration_id=status_id,
                data=status_payload,
                is_extended_id=True,
                is_fd=False,
                channel=config.channel,
                timestamp_us=t,
            )
        )

    # 3. ISO 15118 EVCC Demand frames
    for t in range(0, total_us + 1, iso15118_us):
        evcc_id = encode_j1939_can_id(priority=3, pgn=PGN_ISO15118_EVCC, sa=CAN_SA_EVCC)
        evcc_payload = synthesize_iso15118_evcc_payload(
            v_target=config.v_batt_nominal + 2.0,
            i_limit=config.i_batt_nominal,
            soc=0.55 + (t / max(1, total_us)) * 0.1,
        )
        frames.append(
            CanFdFrame(
                arbitration_id=evcc_id,
                data=evcc_payload,
                is_extended_id=True,
                is_fd=False,
                channel=config.channel,
                timestamp_us=t,
            )
        )

    # 4. Periodic UDS queries (TesterPresent 0x3E 00)
    for t in range(uds_us, total_us + 1, uds_us):
        frames.append(
            CanFdFrame(
                arbitration_id=CAN_ID_UDS_FUNC,
                data=bytes([0x02, 0x3E, 0x00, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA]),
                is_extended_id=False,
                is_fd=False,
                channel=config.channel,
                timestamp_us=t,
            )
        )

    # 5. Fault frame injection (microsecond-precise)
    if config.fault_injection_time_ms is not None:
        fault_target_us = int(round(config.fault_injection_time_ms * 1000.0))
        spn = config.fault_spn or SPN_OBC_DCLINK_OVP
        fault_frame = synthesize_j1939_dm1_fault_frame(
            spn=spn,
            fmi=config.fault_fmi,
            sa=CAN_SA_OBC,
            timestamp_us=fault_target_us,
            channel=config.channel,
        )
        frames.append(fault_frame)

    # Sort strictly by timestamp_us
    frames.sort(key=lambda f: f.timestamp_us)
    return frames


def export_stress_stream_to_candump(frames: List[CanFdFrame], out_path: Path) -> int:
    """Export frames to standard Linux SocketCAN candump log format."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    lines: List[str] = []
    for f in frames:
        ts_sec = f.timestamp_us * 1e-6
        ts_str = f"({ts_sec:017.6f})"
        id_str = f"{f.arbitration_id:08X}" if f.is_extended_id else f"{f.arbitration_id:03X}"
        if f.is_fd:
            # CAN-FD compact separator: ## + flags (1 = BRS) + hex
            flags = "1" if f.bit_rate_switch else "0"
            line = f"{ts_str} {f.channel} {id_str}##{flags}{f.hex_data}"
        else:
            line = f"{ts_str} {f.channel} {id_str}#{f.hex_data}"
        lines.append(line)

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def export_stress_stream_to_event_replay_jsonl(
    frames: List[CanFdFrame],
    out_path: Path,
    topic: str = "obc.stress",
) -> int:
    """Export frames to event-replay JSONL stream format with SHA-256 validation."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stream = EventStream(name="obc_stress_stream")
    base_dt = datetime(2026, 11, 6, 13, 0, 0, tzinfo=timezone.utc)
    for idx, f in enumerate(frames):
        event_dt = base_dt + timedelta(microseconds=f.timestamp_us)
        ev = f.to_recorded_event(
            seq_id=idx + 1,
            stream_topic=topic,
            iso_timestamp=event_dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        )
        stream.append_raw(ev)

    stream.to_jsonl(out_path)
    return stream.count
