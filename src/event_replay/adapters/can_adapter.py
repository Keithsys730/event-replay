"""Hexagonal adapter for CAN and CAN-FD log ingestion and DBC decoding."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Union

from event_replay.domain.can import CanFdFrame
from event_replay.domain.dbc import DbcDatabase
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
                    continue

                if frame is not None:
                    # Construct an ISO timestamp from microsecond epoch timestamp if present
                    if frame.timestamp_us > 0:
                        sec_epoch = frame.timestamp_us / 1e6
                        dt = datetime.fromtimestamp(sec_epoch, tz=timezone.utc)
                        iso_ts = dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
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
    ) -> List[Dict[str, Any]]:
        """Decode all CAN frames in an EventStream using the provided DBC database."""
        decoded_records: List[Dict[str, Any]] = []

        for event in stream.events:
            try:
                frame = CanFdFrame.from_recorded_event(event)
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
