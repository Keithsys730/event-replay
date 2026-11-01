"""Comprehensive unit tests for Automotive Diagnostics (SAE J1939-73 DM1/DM2 & ISO 14229 UDS)."""

import json
from pathlib import Path
import pytest

from event_replay.domain.can import CanFdFrame
from event_replay.domain.j1939 import (
    J1939Header,
    J1939Message,
    J1939_GLOBAL_ADDRESS,
)
from event_replay.domain.j1939_tp import PGN_TP_CM, PGN_TP_DT
from event_replay.domain.diagnostics import (
    PGN_DM1_ACTIVE_DTC,
    PGN_DM2_PREV_ACTIVE_DTC,
    LampStatus,
    FlashState,
    J1939LampState,
    J1939DTC,
    J1939DiagnosticMessage,
    UdsServiceId,
    UdsNegativeResponseCode,
    UdsSessionType,
    UdsMessage,
    DiagnosticFaultInjector,
)
from event_replay.adapters.can_adapter import CanLogAdapter
from event_replay.domain.stream import EventStream
from event_replay.interfaces.cli import main


def test_j1939_lamp_status_encode_decode():
    """Verify SAE J1939-73 2-byte lamp state bitfield packing and unpacking."""
    lamp = J1939LampState(
        protect_lamp=LampStatus.OFF,
        amber_warning_lamp=LampStatus.ON,
        red_stop_lamp=LampStatus.ERROR,
        malfunction_indicator_lamp=LampStatus.NOT_AVAILABLE,
        flash_protect=FlashState.SLOW_FLASH,
        flash_amber=FlashState.FAST_FLASH,
        flash_red=FlashState.RESERVED,
        flash_mil=FlashState.UNAVAILABLE,
    )

    encoded = lamp.to_bytes()
    assert len(encoded) == 2

    decoded = J1939LampState.from_bytes(encoded)
    assert decoded.protect_lamp == LampStatus.OFF
    assert decoded.amber_warning_lamp == LampStatus.ON
    assert decoded.red_stop_lamp == LampStatus.ERROR
    assert decoded.malfunction_indicator_lamp == LampStatus.NOT_AVAILABLE

    assert decoded.flash_protect == FlashState.SLOW_FLASH
    assert decoded.flash_amber == FlashState.FAST_FLASH
    assert decoded.flash_red == FlashState.RESERVED
    assert decoded.flash_mil == FlashState.UNAVAILABLE


def test_j1939_dtc_bitfield_packing_and_fmi_resolution():
    """Verify 4-byte DTC bitfield layout: 19-bit SPN, 5-bit FMI, 1-bit CM, 7-bit OC."""
    # Test SPN 110 (Engine Coolant Temp), FMI 0 (Above Normal - Most Severe), OC 3
    dtc1 = J1939DTC(spn=110, fmi=0, cm=0, oc=3)
    raw1 = dtc1.to_bytes()
    assert len(raw1) == 4
    # SPN 110 = 0x0006E -> byte0 = 0x6E, byte1 = 0x00, byte2 upper 3 bits = 0
    assert raw1[0] == 0x6E
    assert raw1[1] == 0x00
    assert raw1[2] & 0x1F == 0  # FMI 0
    assert raw1[3] & 0x7F == 3  # OC 3

    decoded1 = J1939DTC.from_bytes(raw1)
    assert decoded1.spn == 110
    assert decoded1.fmi == 0
    assert decoded1.cm == 0
    assert decoded1.oc == 3
    assert "Above Normal Operational Range" in decoded1.fmi_description

    # Test SPN at upper bit boundary (19-bit max = 524287 = 0x7FFFF), FMI 31, CM 1, OC 127
    dtc_max = J1939DTC(spn=0x7FFFF, fmi=31, cm=1, oc=127)
    raw_max = dtc_max.to_bytes()
    decoded_max = J1939DTC.from_bytes(raw_max)
    assert decoded_max.spn == 524287
    assert decoded_max.fmi == 31
    assert decoded_max.cm == 1
    assert decoded_max.oc == 127
    assert decoded_max.fmi_description == "Condition Exists"


def test_j1939_dm1_empty_no_active_dtc():
    """Verify empty DM1 indication (4 bytes of 0x00) decodes to zero DTCs."""
    lamp = J1939LampState()
    msg = J1939DiagnosticMessage(pgn=PGN_DM1_ACTIVE_DTC, lamp_state=lamp, dtcs=[])
    payload = msg.encode_payload()
    assert len(payload) == 8
    # Bytes 2..5 should be 0x00
    assert payload[2:6] == b"\x00\x00\x00\x00"

    decoded = J1939DiagnosticMessage.decode_payload(PGN_DM1_ACTIVE_DTC, payload)
    assert decoded.is_dm1 is True
    assert decoded.is_dm2 is False
    assert len(decoded.dtcs) == 0


def test_j1939_dm1_multi_dtc_tp_segmentation_and_reassembly():
    """Verify multi-DTC DM1 (> 8 bytes) automatically segments via TP.CM BAM and reassembles."""
    lamp = J1939LampState(red_stop_lamp=LampStatus.ON, malfunction_indicator_lamp=LampStatus.ON)
    # 3 DTCs: 2 bytes lamp + 3 * 4 bytes DTC = 14 bytes payload
    dtcs = [
        J1939DTC(spn=110, fmi=0, oc=1),   # Engine Coolant Over-temperature
        J1939DTC(spn=190, fmi=2, oc=4),   # Engine Speed Erratic
        J1939DTC(spn=168, fmi=4, oc=2),   # Battery Potential Low
    ]
    diag_msg = J1939DiagnosticMessage(pgn=PGN_DM1_ACTIVE_DTC, lamp_state=lamp, dtcs=dtcs)
    frames = diag_msg.to_can_frames(source_address=0x00, priority=6)

    # 14 bytes across 7 bytes/packet = 2 TP.DT packets + 1 TP.CM BAM = 3 frames
    assert len(frames) == 3

    # Build EventStream
    stream = EventStream("test_diag_stream")
    for seq, frame in enumerate(frames, start=1):
        stream.append_raw(frame.to_recorded_event(seq_id=seq))

    # Decode via CanLogAdapter
    records = CanLogAdapter.decode_stream(stream, reassemble_tp=True, decode_diagnostics=True)
    assert len(records) == 1
    rec = records[0]

    assert rec["tp_reassembled"] is True
    assert rec["total_bytes"] == 14
    assert rec["message_name"] == "DM1_ActiveDTC"

    diag = rec["diagnostics"]
    assert diag["diagnostic_type"] == "J1939_DM1"
    assert diag["dtc_count"] == 3
    assert diag["lamp_status"]["red_stop_lamp"] == "ON"
    assert diag["lamp_status"]["malfunction_indicator_lamp"] == "ON"

    decoded_dtcs = diag["dtcs"]
    assert decoded_dtcs[0]["spn"] == 110
    assert decoded_dtcs[0]["fmi"] == 0
    assert decoded_dtcs[1]["spn"] == 190
    assert decoded_dtcs[1]["fmi"] == 2
    assert decoded_dtcs[2]["spn"] == 168
    assert decoded_dtcs[2]["fmi"] == 4


def test_uds_message_single_frame_encode_decode():
    """Verify ISO 14229 UDS Request/Response and Negative Response (0x7F) handling."""
    # 1. DiagnosticSessionControl (0x10) - Extended Session (0x03) Request
    req_session = UdsMessage(
        service_id=int(UdsServiceId.DIAGNOSTIC_SESSION_CONTROL),
        is_response=False,
        sub_function=int(UdsSessionType.EXTENDED_DIAGNOSTIC_SESSION),
    )
    raw_session = req_session.encode(add_pci=True)
    assert raw_session[0] == 0x02  # SF PCI length = 2 bytes
    assert raw_session[1] == 0x10  # SID
    assert raw_session[2] == 0x03  # SubFunction

    dec_session = UdsMessage.decode(raw_session, has_pci=True)
    assert dec_session.service_id == 0x10
    assert dec_session.service_name == "DIAGNOSTIC_SESSION_CONTROL"
    assert dec_session.is_response is False
    assert dec_session.sub_function == 0x03

    # 2. ReadDataByIdentifier (0x22) - DID 0xF190 (VIN) Positive Response (0x62)
    vin_payload = b"1HGCR2F83HA123456"[:4]  # 4 bytes for Single Frame test
    resp_rdbi = UdsMessage(
        service_id=int(UdsServiceId.READ_DATA_BY_IDENTIFIER),
        is_response=True,
        data_identifier=0xF190,
        payload=vin_payload,
    )
    raw_rdbi = resp_rdbi.encode(add_pci=True)
    dec_rdbi = UdsMessage.decode(raw_rdbi, has_pci=True)
    assert dec_rdbi.service_id == 0x22
    assert dec_rdbi.service_name == "READ_DATA_BY_IDENTIFIER"
    assert dec_rdbi.is_response is True
    assert dec_rdbi.data_identifier == 0xF190
    assert dec_rdbi.payload == vin_payload

    # 3. Negative Response (0x7F) with CONDITIONS_NOT_CORRECT (0x22)
    nrc_msg = UdsMessage(
        service_id=int(UdsServiceId.SECURITY_ACCESS),
        is_response=True,
        is_negative_response=True,
        nrc=UdsNegativeResponseCode.CONDITIONS_NOT_CORRECT,
    )
    raw_nrc = nrc_msg.encode(add_pci=True)
    assert raw_nrc[0] == 0x03  # PCI: 3 bytes
    assert raw_nrc[1] == 0x7F  # Negative Response SID
    assert raw_nrc[2] == 0x27  # Rejected Service: SecurityAccess
    assert raw_nrc[3] == 0x22  # NRC: CONDITIONS_NOT_CORRECT

    dec_nrc = UdsMessage.decode(raw_nrc, has_pci=True)
    assert dec_nrc.is_negative_response is True
    assert dec_nrc.service_id == 0x27
    assert dec_nrc.nrc == UdsNegativeResponseCode.CONDITIONS_NOT_CORRECT


def test_diagnostic_fault_injector_and_can_adapter_integration():
    """Verify DiagnosticFaultInjector produces valid CAN frames decoded by CanLogAdapter."""
    # 1. Inject J1939 Active Fault for Overspeed (SPN 190, FMI 0)
    frames_dm1 = DiagnosticFaultInjector.create_j1939_dm1_active_fault(
        source_address=0x00,
        spn=190,
        fmi=0,
        occurrence_count=5,
        red_stop_lamp=LampStatus.ON,
    )
    assert len(frames_dm1) == 1

    # 2. Inject UDS 0x7F Negative Response on standard ECU response ID 0x7E8
    frame_uds_nrc = DiagnosticFaultInjector.create_uds_negative_response(
        arbitration_id=0x7E8,
        rejected_service=UdsServiceId.SECURITY_ACCESS,
        nrc=UdsNegativeResponseCode.SECURITY_ACCESS_DENIED,
    )

    # 3. Inject UDS 0x62 RDBI Response on 0x7E8 for Bus Voltage DID 0x0100 (400V)
    frame_uds_rdbi = DiagnosticFaultInjector.create_uds_read_data_response(
        arbitration_id=0x7E8,
        data_identifier=0x0100,
        data_payload=bytes([0x01, 0x90]),  # 400 decimal = 0x0190
    )

    stream = EventStream("fault_stream")
    stream.append_raw(frames_dm1[0].to_recorded_event(seq_id=1))
    stream.append_raw(frame_uds_nrc.to_recorded_event(seq_id=2))
    stream.append_raw(frame_uds_rdbi.to_recorded_event(seq_id=3))

    records = CanLogAdapter.decode_stream(stream, dbc=None, decode_diagnostics=True)
    assert len(records) == 3

    # Record 1: J1939 DM1
    r1 = records[0]
    assert r1["message_name"] == "DM1_ActiveDTC"
    assert r1["diagnostics"]["dtc_count"] == 1
    assert r1["diagnostics"]["dtcs"][0]["spn"] == 190
    assert r1["diagnostics"]["dtcs"][0]["fmi"] == 0
    assert r1["diagnostics"]["dtcs"][0]["occurrence_count"] == 5

    # Record 2: UDS Negative Response
    r2 = records[1]
    assert r2["message_name"] == "UDS_SECURITY_ACCESS"
    assert r2["uds"]["is_negative_response"] is True
    assert r2["uds"]["nrc"] == "SECURITY_ACCESS_DENIED"

    # Record 3: UDS Positive RDBI
    r3 = records[2]
    assert r3["message_name"] == "UDS_READ_DATA_BY_IDENTIFIER"
    assert r3["uds"]["is_response"] is True
    assert r3["uds"]["data_identifier"] == "0x0100"
    assert r3["uds"]["payload_hex"] == "0190"


def test_cli_decode_can_diagnostics_and_no_diag_flag(tmp_path: Path):
    """Verify CLI decode-can with diagnostic decoding and --no-diag flag."""
    # Write a candump log with 1 J1939 DM1 frame and 1 UDS response frame
    # J1939 DM1 CAN ID: 0x18FECA00 (Priority 6, PGN 0xFECA, SA 0x00)
    # Payload: 2 lamp bytes (0x10, 0x00) + 1 DTC (SPN 110, FMI 3, CM 0, OC 1 -> 6E 00 03 01) + 2 pad 0xFF
    # UDS CAN ID: 0x7E8, Single Frame PCI length 3, SID 0x7F, 0x22, 0x31 (RequestOutOfRange)
    log_content = (
        "can0 18FECA00#10006E000301FFFF\n"
        "can0 7E8#037F2231AAAAAAAA\n"
    )
    log_file = tmp_path / "diag.log"
    log_file.write_text(log_content, encoding="utf-8")

    out_diag = tmp_path / "out_diag.json"
    ret = main([
        "decode-can",
        "--log", str(log_file),
        "--out", str(out_diag),
    ])
    assert ret == 0

    with open(out_diag, "r", encoding="utf-8") as f:
        data = json.load(f)

    assert len(data) == 2
    assert data[0]["message_name"] == "DM1_ActiveDTC"
    assert data[0]["diagnostics"]["dtc_count"] == 1
    assert data[0]["diagnostics"]["dtcs"][0]["spn"] == 110
    assert data[0]["diagnostics"]["dtcs"][0]["fmi"] == 3

    assert data[1]["message_name"] == "UDS_READ_DATA_BY_IDENTIFIER"
    assert data[1]["uds"]["is_negative_response"] is True
    assert data[1]["uds"]["nrc"] == "REQUEST_OUT_OF_RANGE"

    # Now run with --no-diag flag
    out_no_diag = tmp_path / "out_no_diag.json"
    ret_no_diag = main([
        "decode-can",
        "--log", str(log_file),
        "--no-diag",
        "--out", str(out_no_diag),
    ])
    assert ret_no_diag == 0

    with open(out_no_diag, "r", encoding="utf-8") as f:
        data_no_diag = json.load(f)

    assert len(data_no_diag) == 2
    assert "diagnostics" not in data_no_diag[0]
    assert "uds" not in data_no_diag[1]
    assert data_no_diag[0]["message_name"] == "UNKNOWN"
    assert data_no_diag[1]["message_name"] == "UNKNOWN"
