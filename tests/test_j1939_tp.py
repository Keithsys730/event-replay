"""Comprehensive unit tests for SAE J1939 Transport Protocol (TP.CM / TP.DT) reassembly."""

import json
from pathlib import Path
import pytest

from event_replay.domain.can import CanFdFrame
from event_replay.domain.j1939 import (
    J1939Header,
    J1939Message,
    J1939_GLOBAL_ADDRESS,
)
from event_replay.domain.j1939_tp import (
    J1939TransportReassembler,
    PGN_TP_CM,
    PGN_TP_DT,
    TpAbortReason,
    TpControlByte,
    segment_j1939_message,
)
from event_replay.domain.dbc import DbcDatabase
from event_replay.adapters.can_adapter import CanLogAdapter
from event_replay.interfaces.cli import main


def test_segment_j1939_message_bam():
    # 25-byte payload across 4 packets (7 * 3 = 21, plus 4 in 4th packet)
    payload = bytes(range(1, 26))
    hdr = J1939Header.build(pgn=0xFEEC, source_address=0x35, priority=6)  # VIN PGN
    msg = J1939Message(header=hdr, data=payload)

    frames = segment_j1939_message(msg, is_bam=True)
    assert len(frames) == 5  # 1 TP.CM + 4 TP.DT

    # 1. Verify TP.CM BAM
    cm_frame = frames[0]
    cm_hdr = J1939Header.parse_can_id(cm_frame.arbitration_id)
    assert cm_hdr.pgn == PGN_TP_CM
    assert cm_hdr.destination_address == J1939_GLOBAL_ADDRESS
    assert cm_hdr.source_address == 0x35

    assert cm_frame.data[0] == TpControlByte.BAM  # 0x20
    assert cm_frame.data[1] == 25                 # total bytes LSB
    assert cm_frame.data[2] == 0                  # total bytes MSB
    assert cm_frame.data[3] == 4                  # total packets
    # PGN 0xFEEC little-endian in bytes 5..7
    assert cm_frame.data[5] == 0xEC
    assert cm_frame.data[6] == 0xFE
    assert cm_frame.data[7] == 0x00

    # 2. Verify TP.DT frames
    for i in range(1, 5):
        dt_frame = frames[i]
        dt_hdr = J1939Header.parse_can_id(dt_frame.arbitration_id)
        assert dt_hdr.pgn == PGN_TP_DT
        assert dt_hdr.destination_address == J1939_GLOBAL_ADDRESS
        assert dt_hdr.source_address == 0x35
        assert dt_frame.data[0] == i  # Sequence number 1..4

    # Check padding on final packet (4 payload bytes + 3 padding bytes of 0xFF)
    final_dt = frames[4]
    assert final_dt.data[1:5] == bytes([22, 23, 24, 25])
    assert final_dt.data[5:8] == bytes([0xFF, 0xFF, 0xFF])


def test_reassemble_j1939_bam_stream():
    payload = bytes(range(1, 26))
    hdr = J1939Header.build(pgn=0xFEEC, source_address=0x35, priority=6)
    msg = J1939Message(header=hdr, data=payload)
    frames = segment_j1939_message(msg, is_bam=True)

    reassembler = J1939TransportReassembler()

    # Feed CM frame
    res = reassembler.feed_frame(frames[0])
    assert res is None
    assert len(reassembler.active_sessions) == 1

    # Feed DT packets 1, 2, 3
    for i in range(1, 4):
        res = reassembler.feed_frame(frames[i])
        assert res is None

    # Feed final DT packet 4 -> should trigger complete reassembly!
    reassembled = reassembler.feed_frame(frames[4])
    assert reassembled is not None
    assert reassembled.pgn == 0xFEEC
    assert reassembled.source_address == 0x35
    assert reassembled.destination_address is None
    assert reassembled.data == payload
    assert len(reassembler.active_sessions) == 0
    assert reassembler.completed_count == 1


def test_reassemble_out_of_order_packets():
    payload = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ01234"  # 31 bytes
    hdr = J1939Header.build(pgn=0xFEEB, source_address=0x12, priority=3)
    msg = J1939Message(header=hdr, data=payload)
    frames = segment_j1939_message(msg, is_bam=True)

    reassembler = J1939TransportReassembler()
    # Feed CM
    assert reassembler.feed_frame(frames[0]) is None

    # Feed packets out-of-order: 3, 1, 5, 2, 4
    dt_frames = frames[1:]  # total 5 packets (31 bytes -> ceil(31/7)=5)
    order = [2, 0, 4, 1, 3]  # indices 0-based for packets 3, 1, 5, 2, 4

    for idx in order[:-1]:
        assert reassembler.feed_frame(dt_frames[idx]) is None

    # Final packet in permutation (packet 4, index 3)
    last_frame = dt_frames[order[-1]]
    reassembled = reassembler.feed_frame(last_frame)
    assert reassembled is not None
    assert reassembled.data == payload
    assert reassembled.pgn == 0xFEEB


def test_reassemble_peer_to_peer_rts_cts():
    payload = b"PEER_TO_PEER_UNICAST_PAYLOAD_12345"  # 34 bytes
    hdr = J1939Header.build(pgn=0xEF00, source_address=0x10, priority=5, destination_address=0x20)
    msg = J1939Message(header=hdr, data=payload)
    frames = segment_j1939_message(msg, is_bam=False, destination_address=0x20)

    # CM frame is RTS (0x10) with DA=0x20
    cm_frame = frames[0]
    cm_hdr = J1939Header.parse_can_id(cm_frame.arbitration_id)
    assert cm_hdr.destination_address == 0x20
    assert cm_frame.data[0] == TpControlByte.RTS

    reassembler = J1939TransportReassembler()
    for f in frames[:-1]:
        assert reassembler.feed_frame(f) is None

    reassembled = reassembler.feed_frame(frames[-1])
    assert reassembled is not None
    assert reassembled.source_address == 0x10
    assert reassembled.destination_address == 0x20
    assert reassembled.data == payload


def test_tp_abort_handling():
    payload = bytes(50)
    hdr = J1939Header.build(pgn=0xFECA, source_address=0x01)
    msg = J1939Message(header=hdr, data=payload)
    frames = segment_j1939_message(msg, is_bam=True)

    reassembler = J1939TransportReassembler()
    # Feed CM and packet 1
    reassembler.feed_frame(frames[0])
    reassembler.feed_frame(frames[1])
    assert len(reassembler.active_sessions) == 1

    # Build Abort frame
    abort_hdr = J1939Header.build(pgn=PGN_TP_CM, source_address=0x01, destination_address=J1939_GLOBAL_ADDRESS)
    abort_payload = bytearray([TpControlByte.ABORT, TpAbortReason.TIMEOUT, 0xFF, 0xFF, 0xFF, 0xCA, 0xFE, 0x00])
    abort_frame = CanFdFrame(arbitration_id=abort_hdr.to_can_id(), data=bytes(abort_payload), is_extended_id=True)

    assert reassembler.feed_frame(abort_frame) is None
    assert len(reassembler.active_sessions) == 0
    assert reassembler.aborted_count == 1

    # Subsequent DT packets should be ignored
    assert reassembler.feed_frame(frames[2]) is None


def test_concurrent_multi_node_tp_sessions():
    reassembler = J1939TransportReassembler()

    # Node A (SA=0x10) -> BAM PGN 0xFECA (20 bytes)
    payload_a = b"NODE_A_PAYLOAD_20B!!"
    msg_a = J1939Message(header=J1939Header.build(pgn=0xFECA, source_address=0x10), data=payload_a)
    frames_a = segment_j1939_message(msg_a, is_bam=True)

    # Node B (SA=0x25) -> BAM PGN 0xFEEC (18 bytes)
    payload_b = b"NODE_B_PAYLOAD_18B"
    msg_b = J1939Message(header=J1939Header.build(pgn=0xFEEC, source_address=0x25), data=payload_b)
    frames_b = segment_j1939_message(msg_b, is_bam=True)

    # Interleave frames
    assert reassembler.feed_frame(frames_a[0]) is None  # CM A
    assert reassembler.feed_frame(frames_b[0]) is None  # CM B
    assert len(reassembler.active_sessions) == 2

    assert reassembler.feed_frame(frames_a[1]) is None  # DT A1
    assert reassembler.feed_frame(frames_b[1]) is None  # DT B1
    assert reassembler.feed_frame(frames_a[2]) is None  # DT A2
    assert reassembler.feed_frame(frames_b[2]) is None  # DT B2

    # DT B3 finishes Node B session!
    re_b = reassembler.feed_frame(frames_b[3])
    assert re_b is not None
    assert re_b.source_address == 0x25
    assert re_b.data == payload_b

    # DT A3 finishes Node A session!
    re_a = reassembler.feed_frame(frames_a[3])
    assert re_a is not None
    assert re_a.source_address == 0x10
    assert re_a.data == payload_a

    assert len(reassembler.active_sessions) == 0
    assert reassembler.completed_count == 2


BMS_CELL_VOLTAGE_DBC = """
VERSION ""
NS_ :
BS_:
BU_: BMS VCU

BO_ 2566782976 BMS_CellVoltages: 32 BMS
 SG_ CellVoltage_01 : 0|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_02 : 16|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_03 : 32|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_04 : 48|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_05 : 64|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_06 : 80|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_07 : 96|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_08 : 112|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_09 : 128|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_10 : 144|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_11 : 160|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_12 : 176|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_13 : 192|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_14 : 208|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_15 : 224|16@1+ (0.001,0) [0|5] "V" VCU
 SG_ CellVoltage_16 : 240|16@1+ (0.001,0) [0|5] "V" VCU
"""

def test_end_to_end_bms_multicell_voltages_dbc_decoding(tmp_path: Path):
    # PGN 0xFE00 (decimal 65024), SA=0x00 -> CAN ID = (6 << 26) | (0xFE00 << 8) | 0x00 = 0x18FE0000 = 419299328
    # In Vector DBC, extended ID has bit 31 set: 0x80000000 | 0x18FE0000 = 2566782720
    dbc_file = tmp_path / "bms.dbc"
    dbc_file.write_text(BMS_CELL_VOLTAGE_DBC, encoding="utf-8")
    db = DbcDatabase.from_file(dbc_file)

    # 16 cell voltages: e.g. 3.750V (3750 = 0x0EA6), 3.751V (3751 = 0x0EA7)...
    payload = bytearray()
    for i in range(16):
        mv = 3750 + i
        payload.append(mv & 0xFF)
        payload.append((mv >> 8) & 0xFF)
    assert len(payload) == 32

    hdr = J1939Header.build(pgn=0xFE00, source_address=0x00)
    msg = J1939Message(header=hdr, data=bytes(payload))
    frames = segment_j1939_message(msg, is_bam=True)

    # Write frames into a candump log
    candump_lines = []
    ts = 1730456200.0
    for f in frames:
        ts += 0.010
        candump_lines.append(f"({ts:.6f}) can0 {f.arbitration_id:08X}#{f.hex_data}\n")

    log_file = tmp_path / "candump_tp.log"
    log_file.write_text("".join(candump_lines), encoding="utf-8")

    # Ingest and decode
    stream = CanLogAdapter.parse_log_file(log_file)
    assert stream.count == 6  # 1 CM + 5 DT

    decoded_records = CanLogAdapter.decode_stream(stream, db, reassemble_tp=True)
    assert len(decoded_records) == 1
    rec = decoded_records[0]
    assert rec["message_name"] == "BMS_CellVoltages"
    assert rec["tp_reassembled"] is True
    assert rec["total_bytes"] == 32

    signals = rec["signals"]
    assert signals["CellVoltage_01"] == 3.750
    assert signals["CellVoltage_02"] == 3.751
    assert signals["CellVoltage_16"] == 3.765


def test_cli_decode_can_tp_and_no_tp_flag(tmp_path: Path):
    dbc_file = tmp_path / "bms.dbc"
    dbc_file.write_text(BMS_CELL_VOLTAGE_DBC, encoding="utf-8")

    payload = bytearray()
    for i in range(16):
        mv = 3700 + i
        payload.append(mv & 0xFF)
        payload.append((mv >> 8) & 0xFF)

    hdr = J1939Header.build(pgn=0xFE00, source_address=0x00)
    msg = J1939Message(header=hdr, data=bytes(payload))
    frames = segment_j1939_message(msg, is_bam=True)

    log_file = tmp_path / "bms_tp.log"
    lines = [f"can0 {f.arbitration_id:08X}#{f.hex_data}\n" for f in frames]
    log_file.write_text("".join(lines), encoding="utf-8")

    out_tp = tmp_path / "out_tp.json"
    ret1 = main([
        "decode-can",
        "--dbc", str(dbc_file),
        "--log", str(log_file),
        "--out", str(out_tp),
    ])
    assert ret1 == 0
    with open(out_tp, "r", encoding="utf-8") as f:
        data1 = json.load(f)
    assert len(data1) == 1
    assert data1[0]["message_name"] == "BMS_CellVoltages"
    assert data1[0]["signals"]["CellVoltage_01"] == 3.700

    # With --no-tp flag
    out_no_tp = tmp_path / "out_no_tp.json"
    ret2 = main([
        "decode-can",
        "--dbc", str(dbc_file),
        "--log", str(log_file),
        "--no-tp",
        "--out", str(out_no_tp),
    ])
    assert ret2 == 0
    with open(out_no_tp, "r", encoding="utf-8") as f:
        data2 = json.load(f)
    # Without TP reassembly, raw 6 frames are emitted as UNKNOWN
    assert len(data2) == 6
    assert all(r["message_name"] == "UNKNOWN" for r in data2)


def test_receiver_abort_peer_to_peer():
    """Verify receiver Connection Abort (Conn_Abort) terminates session (Finding 1 [P1])."""
    payload = b"0123456789ABCDEF0123456789"
    hdr = J1939Header.build(pgn=0xEF00, source_address=0x10, destination_address=0x20)
    msg = J1939Message(header=hdr, data=payload)
    frames = segment_j1939_message(msg, is_bam=False, destination_address=0x20)

    reassembler = J1939TransportReassembler()
    reassembler.feed_frame(frames[0])
    assert len(reassembler.active_sessions) == 1

    # Node 0x20 (receiver) transmits Conn_Abort back to Node 0x10
    abort_hdr = J1939Header.build(pgn=0xEC00, source_address=0x20, destination_address=0x10)
    abort_data = bytes([TpControlByte.ABORT, TpAbortReason.SYSTEM_RESOURCES, 0xFF, 0xFF, 0xFF, 0x00, 0xEF, 0x00])
    abort_frame = CanFdFrame(arbitration_id=abort_hdr.to_can_id(), data=abort_data, is_extended_id=True)
    reassembler.feed_frame(abort_frame)

    assert len(reassembler.active_sessions) == 0
    assert reassembler.aborted_count == 1

    # In-flight DT packets must not resurrect aborted session
    assert reassembler.feed_frame(frames[1]) is None


def test_non_tp_dp1_extended_frame_not_dropped():
    """Verify DP=1 frame with PF=0xEC is not dropped as false-positive TP (Finding 2 [P1])."""
    from event_replay.domain.stream import EventStream
    dbc_content = """
VERSION ""
NS_ :
BS_:
BU_: ECU1 ECU2
BO_ 2582380544 DP1_CustomMessage: 8 ECU1
 SG_ TestSignal : 0|16@1+ (1,0) [0|65535] "" ECU2
"""
    db = DbcDatabase.from_text(dbc_content)

    # CAN ID 0x19EC0000: Priority 6, DP=1, PF=0xEC, DA=0x00, SA=0x00
    frame = CanFdFrame(
        arbitration_id=0x19EC0000,
        data=bytes([0x12, 0x34, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
        is_extended_id=True,
    )
    stream = EventStream(name="test_stream")
    stream.append_raw(frame.to_recorded_event(seq_id=1))

    decoded = CanLogAdapter.decode_stream(stream, db, reassemble_tp=True)
    assert len(decoded) == 1
    assert decoded[0]["message_name"] == "DP1_CustomMessage"
    assert decoded[0]["signals"]["TestSignal"] == 0x3412


def test_invalid_total_packets_mismatch_rejected():
    """Verify TP.CM with total_packets != ceil(total_bytes / 7) is rejected (Finding 3 [P1])."""
    # Malformed BAM announcement: total_bytes = 20, but total_packets = 2 (should be 3)
    cm_hdr = J1939Header.build(pgn=0xEC00, source_address=0x10, destination_address=0xFF)
    cm_data = bytes([TpControlByte.BAM, 20, 0, 2, 0xFF, 0x00, 0xFE, 0x00])
    cm_frame = CanFdFrame(arbitration_id=cm_hdr.to_can_id(), data=cm_data, is_extended_id=True)

    reassembler = J1939TransportReassembler()
    reassembler.feed_frame(cm_frame)
    # Session must be rejected immediately
    assert len(reassembler.active_sessions) == 0

    dt_hdr = J1939Header.build(pgn=0xEB00, source_address=0x10, destination_address=0xFF)
    dt1 = CanFdFrame(arbitration_id=dt_hdr.to_can_id(), data=bytes([1]) + b"1234567", is_extended_id=True)
    assert reassembler.feed_frame(dt1) is None


def test_segment_message_preserves_destination_address():
    """Verify segment_j1939_message preserves message.destination_address in unicast (Finding 4 [P2])."""
    hdr = J1939Header.build(pgn=0xEF00, source_address=0x10, destination_address=0x25)
    msg = J1939Message(header=hdr, data=bytes(20))
    frames = segment_j1939_message(msg, is_bam=False)
    cm_hdr = J1939Header.parse_can_id(frames[0].arbitration_id)
    assert cm_hdr.destination_address == 0x25


def test_multichannel_tp_session_isolation():
    """Verify separate CAN channels with identical node addresses do not collide (Finding 5 [P2])."""
    reassembler = J1939TransportReassembler()

    payload0 = b"CHANNEL_0_DATA_20B!"
    msg0 = J1939Message(header=J1939Header.build(pgn=0xFECA, source_address=0x10), data=payload0)
    frames0 = segment_j1939_message(msg0, is_bam=True, channel="can0")

    payload1 = b"CHANNEL_1_DATA_20B!"
    msg1 = J1939Message(header=J1939Header.build(pgn=0xFECA, source_address=0x10), data=payload1)
    frames1 = segment_j1939_message(msg1, is_bam=True, channel="can1")

    reassembler.feed_frame(frames0[0])
    reassembler.feed_frame(frames1[0])
    assert len(reassembler.active_sessions) == 2

    for i in range(1, len(frames0) - 1):
        reassembler.feed_frame(frames0[i])
        reassembler.feed_frame(frames1[i])

    re0 = reassembler.feed_frame(frames0[-1])
    assert re0 is not None
    assert re0.data == payload0

    re1 = reassembler.feed_frame(frames1[-1])
    assert re1 is not None
    assert re1.data == payload1
