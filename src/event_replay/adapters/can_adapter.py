"""Hexagonal adapter for CAN and CAN-FD log ingestion and DBC decoding."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

from event_replay.domain.can import CanFdFrame
from event_replay.domain.dbc import DbcDatabase
from event_replay.domain.diagnostics import (
    PGN_DM1_ACTIVE_DTC,
    PGN_DM2_PREV_ACTIVE_DTC,
    J1939DiagnosticMessage,
    UdsMessage,
)
from event_replay.domain.j1939_tp import J1939TransportReassembler
from event_replay.domain.models import RecordedEvent
from event_replay.domain.stream import EventStream


def _format_j1939_diagnostics(diag_msg: J1939DiagnosticMessage) -> Dict[str, Any]:
    """Format J1939 DM1/DM2 diagnostic message into structured dictionary."""
    return {
        "diagnostic_type": "J1939_DM1" if diag_msg.is_dm1 else "J1939_DM2",
        "lamp_status": {
            "protect_lamp": diag_msg.lamp_state.protect_lamp.name,
            "amber_warning_lamp": diag_msg.lamp_state.amber_warning_lamp.name,
            "red_stop_lamp": diag_msg.lamp_state.red_stop_lamp.name,
            "malfunction_indicator_lamp": diag_msg.lamp_state.malfunction_indicator_lamp.name,
            "flash_mil": diag_msg.lamp_state.flash_mil.name,
            "flash_red": diag_msg.lamp_state.flash_red.name,
        },
        "dtc_count": len(diag_msg.dtcs),
        "dtcs": [
            {
                "spn": dtc.spn,
                "fmi": dtc.fmi,
                "fmi_description": dtc.fmi_description,
                "cm": dtc.cm,
                "occurrence_count": dtc.oc,
            }
            for dtc in diag_msg.dtcs
        ],
    }


def _format_uds_diagnostics(uds_msg: UdsMessage) -> Dict[str, Any]:
    """Format ISO 14229 UDS message into structured dictionary."""
    res: Dict[str, Any] = {
        "service_id": f"0x{uds_msg.service_id:02X}",
        "service_name": uds_msg.service_name,
        "is_response": uds_msg.is_response,
        "is_negative_response": uds_msg.is_negative_response,
    }
    if uds_msg.sub_function is not None:
        res["sub_function"] = f"0x{uds_msg.sub_function:02X}"
    if uds_msg.data_identifier is not None:
        res["data_identifier"] = f"0x{uds_msg.data_identifier:04X}"
    if uds_msg.nrc is not None:
        res["nrc"] = uds_msg.nrc.name
        res["nrc_code"] = f"0x{int(uds_msg.nrc):02X}"
    if uds_msg.payload:
        res["payload_hex"] = uds_msg.payload.hex().upper()
    return res


class CanLogAdapter:
    """Ingests SocketCAN candump logs, ASC logs, or JSON event streams into EventStreams."""

    @classmethod
    def parse_log_file(
        cls,
        file_path: Union[str, Path],
        topic: str = "can_bus",
    ) -> EventStream:
        """Parse a CAN log file into an EventStream of RecordedEvents."""
        path = Path(file_path)
        events: List[RecordedEvent] = []
        seq = 1

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                try:
                    frame = CanFdFrame.from_candump_line(line)
                except (ValueError, IndexError):
                    # Corrupted line; skip gracefully
                    continue

                if frame is not None:
                    # Construct valid ISO-8601 UTC timestamp from microsecond timestamp
                    if frame.timestamp_us > 0:
                        sec_epoch = frame.timestamp_us / 1e6
                        iso_ts = datetime.fromtimestamp(sec_epoch, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                    else:
                        iso_ts = "2026-11-01T00:00:00.000000Z"

                    event = frame.to_recorded_event(seq_id=seq, stream_topic=topic, iso_timestamp=iso_ts)
                    events.append(event)
                    seq += 1

        stream = EventStream(name=path.stem)
        for ev in events:
            stream.append_raw(ev)
        return stream

    @classmethod
    def decode_stream(
        cls,
        stream: EventStream,
        dbc: Optional[DbcDatabase] = None,
        reassemble_tp: bool = True,
        include_tp_raw: bool = False,
        decode_diagnostics: bool = True,
    ) -> List[Dict[str, Any]]:
        """Decode all CAN frames in an EventStream using the provided DBC database and diagnostic parsers.

        Args:
            stream: EventStream containing CAN RecordedEvents.
            dbc: Optional DbcDatabase for signal decoding.
            reassemble_tp: If True, reassembles multi-packet SAE J1939 TP.CM / TP.DT streams.
            include_tp_raw: If True, also includes raw intermediate TP frames in output.
            decode_diagnostics: If True, decodes SAE J1939 DM1/DM2 and ISO 14229 UDS frames.
        """
        decoded_records: List[Dict[str, Any]] = []
        reassembler = J1939TransportReassembler() if reassemble_tp else None

        for event in stream.events:
            try:
                frame = CanFdFrame.from_recorded_event(event)

                # Check for J1939 Transport Protocol frames (strictly Data Page 0 with EDP=0, DP=0)
                if reassembler is not None and (frame.is_extended_id or frame.arbitration_id > 0x7FF):
                    dp_edp = (frame.arbitration_id >> 24) & 0x03
                    pf = (frame.arbitration_id >> 16) & 0xFF
                    if dp_edp == 0 and pf in (0xEC, 0xEB):  # TP.CM (0xEC) or TP.DT (0xEB) on Data Page 0
                        reassembled_msg = reassembler.feed_frame(frame)
                        if reassembled_msg is not None:
                            re_can_id = reassembled_msg.header.to_can_id()
                            rec: Dict[str, Any] = {
                                "seq_id": event.seq_id,
                                "timestamp_utc": event.timestamp_utc,
                                "channel": frame.channel,
                                "can_id": f"0x{re_can_id:X}",
                                "pgn": f"0x{reassembled_msg.pgn:04X}",
                                "message_name": "UNKNOWN",
                                "raw_hex": reassembled_msg.data.hex().upper(),
                                "tp_reassembled": True,
                                "total_bytes": len(reassembled_msg.data),
                            }

                            if dbc is not None:
                                decoded = dbc.decode_frame(re_can_id, reassembled_msg.data, is_extended_id=True)
                                if decoded is not None:
                                    rec["message_name"] = decoded["message_name"]
                                    rec["signals"] = decoded["signals"]

                            # Diagnostic inspection for reassembled J1939 messages (e.g. multi-packet DM1/DM2)
                            if decode_diagnostics and reassembled_msg.pgn in (PGN_DM1_ACTIVE_DTC, PGN_DM2_PREV_ACTIVE_DTC):
                                diag_msg = J1939DiagnosticMessage.decode_payload(reassembled_msg.pgn, reassembled_msg.data)
                                rec["diagnostics"] = _format_j1939_diagnostics(diag_msg)
                                if rec["message_name"] == "UNKNOWN":
                                    rec["message_name"] = "DM1_ActiveDTC" if diag_msg.is_dm1 else "DM2_PrevActiveDTC"

                            decoded_records.append(rec)

                        if not include_tp_raw:
                            continue

                # Standard (non-TP or intermediate TP raw) frame decoding
                rec: Dict[str, Any] = {
                    "seq_id": event.seq_id,
                    "timestamp_utc": event.timestamp_utc,
                    "channel": frame.channel,
                    "can_id": f"0x{frame.arbitration_id:X}",
                    "message_name": "UNKNOWN",
                    "raw_hex": frame.hex_data,
                }

                if dbc is not None:
                    decoded = dbc.decode_frame(frame.arbitration_id, frame.data, is_extended_id=frame.is_extended_id)
                    if decoded is not None:
                        rec["message_name"] = decoded["message_name"]
                        rec["signals"] = decoded["signals"]

                if decode_diagnostics:
                    # 1. Check for single-frame J1939 DM1/DM2
                    if frame.is_extended_id or frame.arbitration_id > 0x7FF:
                        dp_edp = (frame.arbitration_id >> 24) & 0x03
                        pf = (frame.arbitration_id >> 16) & 0xFF
                        ps = (frame.arbitration_id >> 8) & 0xFF
                        pgn = (dp_edp << 16) | (pf << 8) | (ps if pf >= 240 else 0)
                        if pgn in (PGN_DM1_ACTIVE_DTC, PGN_DM2_PREV_ACTIVE_DTC):
                            diag_msg = J1939DiagnosticMessage.decode_payload(pgn, frame.data)
                            rec["diagnostics"] = _format_j1939_diagnostics(diag_msg)
                            rec["pgn"] = f"0x{pgn:04X}"
                            if rec["message_name"] == "UNKNOWN":
                                rec["message_name"] = "DM1_ActiveDTC" if diag_msg.is_dm1 else "DM2_PrevActiveDTC"

                    # 2. Check for ISO 14229 UDS frame
                    # 11-bit diagnostic range (0x7DF broadcast, 0x7E0..0x7EF physical request/response)
                    # or 29-bit ISO 15765-2 / J1939-73 UDS (PF=0xDA)
                    is_uds_id = (
                        frame.arbitration_id == 0x7DF
                        or frame.arbitration_id in range(0x7E0, 0x7F0)
                        or (frame.is_extended_id and ((frame.arbitration_id >> 16) & 0xFF) == 0xDA)
                    )
                    if is_uds_id and len(frame.data) > 0:
                        try:
                            uds_msg = UdsMessage.decode(frame.data, has_pci=True)
                            rec["uds"] = _format_uds_diagnostics(uds_msg)
                            if rec["message_name"] == "UNKNOWN":
                                rec["message_name"] = f"UDS_{uds_msg.service_name}"
                        except Exception:
                            pass

                decoded_records.append(rec)
            except Exception:
                continue

        return decoded_records
