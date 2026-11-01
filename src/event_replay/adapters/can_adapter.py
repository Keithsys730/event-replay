"""Hexagonal adapter for CAN and CAN-FD log ingestion and DBC decoding."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

from event_replay.domain.can import CanFdFrame
from event_replay.domain.dbc import DbcDatabase
from event_replay.domain.j1939_tp import J1939TransportReassembler
from event_replay.domain.models import RecordedEvent
from event_replay.domain.stream import EventStream


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
        dbc: DbcDatabase,
        reassemble_tp: bool = True,
        include_tp_raw: bool = False,
    ) -> List[Dict[str, Any]]:
        """Decode all CAN frames in an EventStream using the provided DBC database.
        
        Args:
            stream: EventStream containing CAN RecordedEvents.
            dbc: DbcDatabase for signal decoding.
            reassemble_tp: If True, reassembles multi-packet SAE J1939 TP.CM / TP.DT streams.
            include_tp_raw: If True, also includes raw intermediate TP frames in output.
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
                            decoded = dbc.decode_frame(re_can_id, reassembled_msg.data, is_extended_id=True)
                            if decoded is not None:
                                decoded_records.append({
                                    "seq_id": event.seq_id,
                                    "timestamp_utc": event.timestamp_utc,
                                    "channel": frame.channel,
                                    "can_id": f"0x{re_can_id:X}",
                                    "pgn": f"0x{reassembled_msg.pgn:04X}",
                                    "message_name": decoded["message_name"],
                                    "signals": decoded["signals"],
                                    "tp_reassembled": True,
                                    "total_bytes": len(reassembled_msg.data),
                                })
                            else:
                                decoded_records.append({
                                    "seq_id": event.seq_id,
                                    "timestamp_utc": event.timestamp_utc,
                                    "channel": frame.channel,
                                    "can_id": f"0x{re_can_id:X}",
                                    "pgn": f"0x{reassembled_msg.pgn:04X}",
                                    "message_name": "UNKNOWN",
                                    "raw_hex": reassembled_msg.data.hex().upper(),
                                    "tp_reassembled": True,
                                    "total_bytes": len(reassembled_msg.data),
                                })
                        if not include_tp_raw:
                            continue

                decoded = dbc.decode_frame(frame.arbitration_id, frame.data, is_extended_id=frame.is_extended_id)
                if decoded is not None:
                    decoded_records.append({
                        "seq_id": event.seq_id,
                        "timestamp_utc": event.timestamp_utc,
                        "channel": frame.channel,
                        "can_id": f"0x{frame.arbitration_id:X}",
                        "message_name": decoded["message_name"],
                        "signals": decoded["signals"],
                    })
                else:
                    decoded_records.append({
                        "seq_id": event.seq_id,
                        "timestamp_utc": event.timestamp_utc,
                        "channel": frame.channel,
                        "can_id": f"0x{frame.arbitration_id:X}",
                        "message_name": "UNKNOWN",
                        "raw_hex": frame.hex_data,
                    })
            except Exception:
                continue

        return decoded_records
