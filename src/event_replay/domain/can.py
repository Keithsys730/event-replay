"""CAN-FD (Controller Area Network Flexible Data-Rate) Domain Models."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import re
from typing import Any, Dict, List, Optional, Tuple

from event_replay.domain.models import RecordedEvent


# CAN-FD DLC to payload byte length lookup table (ISO 11898-1:2015)
DLC_TO_LEN: Tuple[int, ...] = (0, 1, 2, 3, 4, 5, 6, 7, 8, 12, 16, 20, 24, 32, 48, 64)
LEN_TO_DLC_MAP: Dict[int, int] = {
    0: 0, 1: 1, 2: 2, 3: 3, 4: 4, 5: 5, 6: 6, 7: 7, 8: 8,
    12: 9, 16: 10, 20: 11, 24: 12, 32: 13, 48: 14, 64: 15,
}


def dlc_to_length(dlc: int) -> int:
    """Map a 4-bit CAN DLC code (0-15) to its payload byte length."""
    if dlc < 0 or dlc > 15:
        raise ValueError(f"CAN DLC must be in range 0..15, got {dlc}")
    return DLC_TO_LEN[dlc]


def length_to_dlc(length: int) -> int:
    """Find the smallest standard CAN/CAN-FD DLC code that accommodates length bytes."""
    if length < 0 or length > 64:
        raise ValueError(f"CAN payload length must be in range 0..64 bytes, got {length}")
    for valid_len in DLC_TO_LEN:
        if valid_len >= length:
            return LEN_TO_DLC_MAP[valid_len]
    return 15


@dataclass(frozen=True)
class CanFdFrame:
    """Immutable representation of a Classical CAN or CAN-FD physical frame.

    Supports:
    - Standard 11-bit ID (0x000 .. 0x7FF) and Extended 29-bit ID (0x00000000 .. 0x1FFFFFFF)
    - Payload lengths 0 to 64 bytes (CAN-FD) or 0 to 8 bytes (Classical CAN)
    - Bit Rate Switch (BRS) flag: higher transmission bitrate for data payload
    - Error State Indicator (ESI) flag: transceiver error-passive indication
    """
    arbitration_id: int
    data: bytes = b""
    is_extended_id: bool = False
    is_fd: bool = False
    bit_rate_switch: bool = False
    error_state_indicator: bool = False
    channel: str = "can0"
    timestamp_us: int = 0

    def __post_init__(self) -> None:
        # Validate Arbitration ID bounds
        max_id = 0x1FFFFFFF if self.is_extended_id else 0x7FF
        if self.arbitration_id < 0 or self.arbitration_id > max_id:
            id_type = "29-bit extended" if self.is_extended_id else "11-bit standard"
            raise ValueError(
                f"CAN ID 0x{self.arbitration_id:X} out of bounds for {id_type} (max 0x{max_id:X})"
            )

        # Validate Payload Length
        max_len = 64 if self.is_fd else 8
        if len(self.data) > max_len:
            bus_type = "CAN-FD" if self.is_fd else "Classical CAN"
            raise ValueError(
                f"{bus_type} payload length ({len(self.data)} bytes) exceeds maximum {max_len} bytes"
            )

    @property
    def dlc(self) -> int:
        """Calculate the CAN DLC code for this frame's payload length."""
        return length_to_dlc(len(self.data))

    @property
    def hex_data(self) -> str:
        """Hexadecimal representation of data payload (e.g. '01020304')."""
        return self.data.hex().upper()

    def to_recorded_event(
        self,
        seq_id: int,
        stream_topic: str = "can_bus",
        iso_timestamp: str = "",
    ) -> RecordedEvent:
        """Convert this frame into a generic event-replay RecordedEvent."""
        headers = {
            "can_id": f"0x{self.arbitration_id:08X}" if self.is_extended_id else f"0x{self.arbitration_id:03X}",
            "is_extended": str(self.is_extended_id).lower(),
            "is_fd": str(self.is_fd).lower(),
            "brs": str(self.bit_rate_switch).lower(),
            "esi": str(self.error_state_indicator).lower(),
            "channel": self.channel,
            "dlc": str(self.dlc),
            "timestamp_us": str(self.timestamp_us),
        }
        event_id = f"can-{self.channel}-{self.arbitration_id:X}-{seq_id}"
        ts = iso_timestamp or "2026-11-01T00:00:00.000000Z"
        return RecordedEvent.create(
            seq_id=seq_id,
            event_id=event_id,
            stream_topic=stream_topic,
            timestamp_utc=ts,
            payload=self.data,
            headers=headers,
        )

    @classmethod
    def from_recorded_event(cls, event: RecordedEvent) -> CanFdFrame:
        """Reconstruct a CanFdFrame from a RecordedEvent."""
        hdrs = event.headers
        raw_id_str = hdrs.get("can_id", "0x000")
        arb_id = int(raw_id_str, 16) if raw_id_str.startswith("0x") else int(raw_id_str)
        is_ext = hdrs.get("is_extended", "false").lower() == "true" or arb_id > 0x7FF
        is_fd = hdrs.get("is_fd", "false").lower() == "true" or len(event.payload) > 8
        brs = hdrs.get("brs", "false").lower() == "true"
        esi = hdrs.get("esi", "false").lower() == "true"
        channel = hdrs.get("channel", "can0")
        ts_us = int(hdrs.get("timestamp_us", "0"))

        return cls(
            arbitration_id=arb_id,
            data=event.payload,
            is_extended_id=is_ext,
            is_fd=is_fd,
            bit_rate_switch=brs,
            error_state_indicator=esi,
            channel=channel,
            timestamp_us=ts_us,
        )

    @classmethod
    def from_candump_line(cls, line: str, default_channel: str = "can0") -> Optional[CanFdFrame]:
        """Parse standard Linux socketcan candump output.

        Supported formats:
        - Classical CAN: "  can0  123   [4]  DE AD BE EF" or "can0 123#DEADBEEF"
        - Extended CAN:  "  can0  18F00400   [8]  01 02 03 04 05 06 07 08" or "can0 18F00400#01020304"
        - CAN-FD:        "  can0  123  ## 1 01020304..." or "can0 123##1DEADBEEF..."
        - Log format:    "(1730456123.456789) can0 18F00400#DEADBEEF"
        """
        clean = line.strip()
        if not clean or clean.startswith("#") or clean.startswith(";"):
            return None

        # Extract timestamp if present: (1234567890.123456)
        ts_us = 0
        ts_match = re.match(r"^\((\d+\.\d+)\)\s+(.*)$", clean)
        if ts_match:
            sec_float = float(ts_match.group(1))
            ts_us = int(round(sec_float * 1e6))
            clean = ts_match.group(2).strip()

        # Compact candump format: channel ID#DATA or channel ID##FLAGS_DATA
        compact_match = re.match(r"^(\w+)\s+([0-9a-fA-F]+)(#{1,2})([0-9a-fA-F]*)$", clean)
        if compact_match:
            channel = compact_match.group(1)
            arb_id_hex = compact_match.group(2)
            sep = compact_match.group(3)
            payload_hex = compact_match.group(4)

            arb_id = int(arb_id_hex, 16)
            is_ext = len(arb_id_hex) > 3 or arb_id > 0x7FF
            is_fd = (sep == "##")
            brs = False
            esi = False

            if is_fd and payload_hex:
                # First nibble or byte in CAN-FD compact separator may contain flags (1 = BRS)
                flags_char = payload_hex[0]
                if flags_char in ("1", "3"):
                    brs = True
                if flags_char in ("2", "3"):
                    esi = True
                # The rest is payload
                data_hex = payload_hex[1:]
                data = bytes.fromhex(data_hex) if data_hex else b""
            else:
                data = bytes.fromhex(payload_hex) if payload_hex else b""

            return cls(
                arbitration_id=arb_id,
                data=data,
                is_extended_id=is_ext,
                is_fd=is_fd,
                bit_rate_switch=brs,
                error_state_indicator=esi,
                channel=channel,
                timestamp_us=ts_us,
            )

        # Standard candump verbose format: can0 123 [4] 01 02 03 04
        verbose_match = re.match(r"^(\w+)\s+([0-9a-fA-F]+)\s+\[(\d+)\]\s*(.*)$", clean)
        if verbose_match:
            channel = verbose_match.group(1)
            arb_id = int(verbose_match.group(2), 16)
            is_ext = arb_id > 0x7FF
            hex_tokens = verbose_match.group(4).split()
            data = bytes(int(b, 16) for b in hex_tokens)
            is_fd = len(data) > 8

            return cls(
                arbitration_id=arb_id,
                data=data,
                is_extended_id=is_ext,
                is_fd=is_fd,
                channel=channel,
                timestamp_us=ts_us,
            )

        return None
