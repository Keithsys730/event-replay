"""Comprehensive unit tests for CAN-FD, SAE J1939, and DBC signal decoding."""

import json
from pathlib import Path
import pytest

from event_replay.domain.can import (
    CanFdFrame,
    dlc_to_length,
    length_to_dlc,
)
from event_replay.domain.j1939 import (
    J1939Header,
    J1939Message,
    J1939_GLOBAL_ADDRESS,
)
from event_replay.domain.dbc import (
    DbcDatabase,
    DbcMessage,
    DbcSignal,
)
from event_replay.adapters.can_adapter import CanLogAdapter
from event_replay.interfaces.cli import main


SAMPLE_OBC_DBC = """
VERSION ""

NS_ :

BS_:

BU_: OBC BMS VCU

BO_ 2566805502 OBC_Status: 8 OBC
 SG_ OBC_OutputVoltage : 0|16@1+ (0.1,0) [0|1000] "V" BMS,VCU
 SG_ OBC_OutputCurrent : 16|16@1- (0.1,0) [-200|200] "A" BMS,VCU
 SG_ OBC_State : 32|8@1+ (1,0) [0|255] "" VCU
 SG_ OBC_HardwareTrip : 40|1@1+ (1,0) [0|1] "" VCU
 SG_ OBC_ZvsAchieved : 41|1@1+ (1,0) [0|1] "" VCU

BO_ 2566805246 BMS_PackStatus: 8 BMS
 SG_ BMS_PackVoltage : 0|16@1+ (0.1,0) [0|1000] "V" OBC,VCU
 SG_ BMS_PackCurrent : 16|16@1- (0.1,0) [-500|500] "A" OBC,VCU
 SG_ BMS_StateOfCharge : 32|8@1+ (0.5,0) [0|100] "%" VCU

BO_ 512 MotorController: 8 VCU
 SG_ MotorSpeed_Intel : 0|16@1+ (0.5,0) [0|15000] "rpm" VCU
 SG_ MotorTorque_Moto : 23|12@0- (0.5,-500) [-500|500] "Nm" VCU
"""


def test_can_fd_frame_properties_and_dlc():
    # 1. Standard 11-bit Frame
    frame1 = CanFdFrame(arbitration_id=0x123, data=bytes([1, 2, 3, 4]))
    assert not frame1.is_extended_id
    assert not frame1.is_fd
    assert frame1.dlc == 4
    assert frame1.hex_data == "01020304"

    # 2. CAN-FD Extended Frame with 64-byte payload
    fd_data = bytes(range(64))
    frame2 = CanFdFrame(
        arbitration_id=0x18F00400,
        data=fd_data,
        is_extended_id=True,
        is_fd=True,
        bit_rate_switch=True,
    )
    assert frame2.is_extended_id
    assert frame2.is_fd
    assert frame2.bit_rate_switch
    assert frame2.dlc == 15
    assert len(frame2.data) == 64

    # 3. DLC helper mapping
    assert dlc_to_length(0) == 0
    assert dlc_to_length(8) == 8
    assert dlc_to_length(9) == 12
    assert dlc_to_length(15) == 64
    assert length_to_dlc(10) == 9  # rounds up to 12 bytes
    assert length_to_dlc(64) == 15

    # 4. Out of bounds validation
    with pytest.raises(ValueError, match="out of bounds"):
        CanFdFrame(arbitration_id=0x800, is_extended_id=False)  # > 11-bit max

    with pytest.raises(ValueError, match="exceeds maximum"):
        CanFdFrame(arbitration_id=0x100, data=bytes(10), is_fd=False)  # Classical CAN max 8


def test_candump_parsing_and_recorded_event_roundtrip():
    # Parse compact candump format
    line1 = "  can0  18F00400#0102030405060708"
    f1 = CanFdFrame.from_candump_line(line1)
    assert f1 is not None
    assert f1.arbitration_id == 0x18F00400
    assert f1.is_extended_id is True
    assert f1.data == bytes([1, 2, 3, 4, 5, 6, 7, 8])

    # Parse CAN-FD candump with BRS flag
    line2 = "(1730456123.456000) can1 7DF##111223344"
    f2 = CanFdFrame.from_candump_line(line2)
    assert f2 is not None
    assert f2.arbitration_id == 0x7DF
    assert f2.channel == "can1"
    assert f2.is_fd is True
    assert f2.bit_rate_switch is True
    assert f2.data == bytes.fromhex("11223344")

    # Roundtrip to RecordedEvent
    event = f1.to_recorded_event(seq_id=42, stream_topic="vehicle_bus")
    assert event.seq_id == 42
    assert event.headers["can_id"] == "0x18F00400"
    assert event.verify_integrity()

    reconstructed = CanFdFrame.from_recorded_event(event)
    assert reconstructed.arbitration_id == f1.arbitration_id
    assert reconstructed.data == f1.data
    assert reconstructed.is_extended_id is True


def test_j1939_header_parsing_and_pgn_resolution():
    # Case 1: PDU2 Broadcast Message (e.g. EEC1 = PGN 61444 / 0xF004)
    # CAN ID = Priority(3) + EDP(0) + DP(0) + PF(0xF0) + PS(0x04) + SA(0x00)
    # Binary: 000 0 0 11110000 00000100 00000000 -> 0x0CF00400
    can_id_eec1 = 0x0CF00400
    hdr1 = J1939Header.parse_can_id(can_id_eec1)
    assert hdr1.priority == 3
    assert hdr1.pdu_format == 0xF0
    assert hdr1.pdu_specific == 0x04
    assert hdr1.source_address == 0x00
    assert hdr1.destination_address is None
    assert hdr1.pgn == 61444  # 0xF004
    assert not hdr1.is_pdu1
    assert hdr1.to_can_id() == can_id_eec1

    # Case 2: PDU1 Point-to-Point Message (e.g. Torque Control PGN 0x0000, DA = 0x28, SA = 0x03, Priority = 3)
    # PF = 0x00 (< 240), PS = 0x28 (DA)
    # CAN ID: (3 << 26) | (0 << 16) | (0x28 << 8) | 0x03 -> 0x0C002803
    can_id_pdu1 = (3 << 26) | (0x00 << 16) | (0x28 << 8) | 0x03
    hdr2 = J1939Header.parse_can_id(can_id_pdu1)
    assert hdr2.is_pdu1 is True
    assert hdr2.destination_address == 0x28
    assert hdr2.source_address == 0x03
    assert hdr2.pgn == 0x0000
    assert hdr2.to_can_id() == can_id_pdu1

    # Case 3: J1939Header.build
    hdr_built = J1939Header.build(pgn=61444, source_address=0x17, priority=6)
    assert hdr_built.pgn == 61444
    assert hdr_built.source_address == 0x17
    assert hdr_built.priority == 6

    msg = J1939Message(header=hdr_built, data=bytes(8))
    can_frame = msg.to_can_frame()
    assert can_frame.is_extended_id is True
    assert J1939Message.from_can_frame(can_frame).pgn == 61444


def test_dbc_signal_decoding_intel_and_motorola():
    db = DbcDatabase.from_text(SAMPLE_OBC_DBC)
    assert len(db.messages_by_id) == 3

    # Test MotorController (ID 512):
    # SG_ MotorSpeed_Intel : 0|16@1+ (0.5,0)
    # SG_ MotorTorque_Moto : 23|12@0- (0.5,-500)
    # Payload:
    # Intel: speed = 4000 rpm -> raw = 8000 = 0x1F40 -> bytes[0]=0x40, bytes[1]=0x1F
    # Motorola: torque = +50.0 Nm -> phys = raw * 0.5 - 500 => raw = (50 + 500)/0.5 = 1100 = 0x44C
    # Start bit 23 is MSB (byte 2 bit 7). 12 bits spans byte 2 (8 bits: 0x44) and byte 3 bits 7..4 (4 bits: 0xC)
    # byte 2 = 0x44, byte 3 = 0xC0
    payload = bytearray(8)
    payload[0] = 0x40
    payload[1] = 0x1F
    payload[2] = 0x44
    payload[3] = 0xC0

    decoded = db.decode_frame(512, bytes(payload))
    assert decoded is not None
    assert decoded["message_name"] == "MotorController"
    signals = decoded["signals"]
    assert signals["MotorSpeed_Intel"] == 4000.0  # 8000 * 0.5
    assert signals["MotorTorque_Moto"] == 50.0    # 1100 * 0.5 - 500


def test_obc_j1939_end_to_end_telemetry_decoding():
    db = DbcDatabase.from_text(SAMPLE_OBC_DBC)

    # Encode OBC Status frame (matches PE_FW_WS OBC SIL simulation output):
    # V_out = 400.0 V (raw = 4000 = 0x0FA0 -> bytes 0..1 = 0xA0, 0x0F)
    # I_out = 8.5 A (raw = 85 = 0x0055 -> bytes 2..3 = 0x55, 0x00)
    # State = 2 (NORMAL_REGULATION -> byte 4 = 0x02)
    # Trip = 0, ZVS = 1 (byte 5: bit 0 = 0, bit 1 = 1 -> byte 5 = 0x02)
    obc_payload = bytearray(8)
    # 4000 in little endian 16-bit
    obc_payload[0] = 0xA0
    obc_payload[1] = 0x0F
    # 85 in little endian 16-bit
    obc_payload[2] = 0x55
    obc_payload[3] = 0x00
    obc_payload[4] = 0x02
    obc_payload[5] = 0x02

    # In DBC, OBC_Status ID is defined as 2566847230 = 0x98FE57FE (Extended Vector mask | 0x18FE57FE)
    # Clean 29-bit CAN ID is 0x18FE57FE (PGN 0xFE57 = 65111, SA = 0xFE, Priority = 6)
    can_id_obc = 0x18FE57FE

    decoded = db.decode_frame(can_id_obc, bytes(obc_payload))
    assert decoded is not None
    assert decoded["message_name"] == "OBC_Status"
    sig = decoded["signals"]
    assert sig["OBC_OutputVoltage"] == 400.0
    assert sig["OBC_OutputCurrent"] == 8.5
    assert sig["OBC_State"] == 2
    assert sig["OBC_HardwareTrip"] is False
    assert sig["OBC_ZvsAchieved"] is True

    # Test signed negative current (e.g. regenerative braking / discharge: -15.5 A)
    # Raw value = -155 -> 16-bit signed two's complement = 0xFF65 (little-endian: 0x65, 0xFF)
    obc_payload[2] = 0x65
    obc_payload[3] = 0xFF
    decoded_neg = db.decode_frame(can_id_obc, bytes(obc_payload))
    assert decoded_neg is not None
    assert decoded_neg["signals"]["OBC_OutputCurrent"] == -15.5


def test_can_log_adapter_and_cli_decode_command(tmp_path: Path):
    dbc_file = tmp_path / "vehicle.dbc"
    dbc_file.write_text(SAMPLE_OBC_DBC, encoding="utf-8")

    # 1. Test single frame CLI decode
    ret1 = main([
        "decode-can",
        "--dbc", str(dbc_file),
        "--can-id", "0x18FE57FE",
        "--payload", "A00F550002020000",
    ])
    assert ret1 == 0

    # 2. Test candump log file ingestion
    candump_file = tmp_path / "candump.log"
    candump_file.write_text(
        "(1730456100.100000) can0 18FE57FE#A00F550002020000\n"
        "(1730456100.120000) can0 18FE56FE#8813000064000000\n",
        encoding="utf-8",
    )

    out_json = tmp_path / "decoded.json"
    ret2 = main([
        "decode-can",
        "--dbc", str(dbc_file),
        "--log", str(candump_file),
        "--out", str(out_json),
    ])
    assert ret2 == 0
    assert out_json.exists()

    with open(out_json, "r", encoding="utf-8") as f:
        records = json.load(f)

    assert len(records) == 2
    assert records[0]["message_name"] == "OBC_Status"
    assert records[0]["signals"]["OBC_OutputVoltage"] == 400.0
    assert records[1]["message_name"] == "BMS_PackStatus"
    assert records[1]["signals"]["BMS_PackVoltage"] == 500.0  # 0x1388 = 5000 * 0.1
    assert records[1]["signals"]["BMS_StateOfCharge"] == 50.0 # 0x64 = 100 * 0.5
