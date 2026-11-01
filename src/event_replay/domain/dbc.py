"""Lightweight, pure-Python CANdb (.dbc) file parser and signal decoder.

Parses Vector CANdb message (BO_) and signal (SG_) definitions with support for:
- Standard 11-bit and Extended 29-bit (0x80000000 mask) CAN IDs
- Intel (Little-Endian) and Motorola (Big-Endian) bit unpacking
- Signed (two's complement) and unsigned signals
- Linear physical scaling: Physical = Raw * Factor + Offset
- Min/Max range constraints and engineering units
- SAE J1939 Parameter Group Number (PGN) resolution
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
from typing import Any, Dict, List, Optional, Tuple, Union


@dataclass(frozen=True)
class DbcSignal:
    """Definition of a single CAN signal within a frame."""
    name: str
    start_bit: int
    length: int
    is_little_endian: bool  # True = Intel (@1), False = Motorola (@0)
    is_signed: bool         # True = Signed (-), False = Unsigned (+)
    factor: float = 1.0
    offset: float = 0.0
    min_val: float = 0.0
    max_val: float = 0.0
    unit: str = ""
    receivers: List[str] = field(default_factory=list)
    comment: str = ""

    def unpack_raw(self, payload: bytes) -> int:
        """Extract raw bitfield integer from payload bytes."""
        if not payload:
            return 0

        if self.is_little_endian:
            # Intel (Little Endian):
            # Payload bytes converted to little-endian integer; bit shift directly
            payload_int = int.from_bytes(payload, byteorder="little")
            raw_val = (payload_int >> self.start_bit) & ((1 << self.length) - 1)
        else:
            # Motorola (Big Endian, Vector CANdb standard):
            # start_bit is the MSB of the signal. Bit index decrements; byte increments on wrap.
            raw_val = 0
            byte_idx = self.start_bit // 8
            bit_idx = self.start_bit % 8

            for _ in range(self.length):
                raw_val <<= 1
                if byte_idx < len(payload):
                    bit = (payload[byte_idx] >> bit_idx) & 1
                    raw_val |= bit
                bit_idx -= 1
                if bit_idx < 0:
                    bit_idx = 7
                    byte_idx += 1

        # Two's complement conversion if signed
        if self.is_signed and (raw_val >= (1 << (self.length - 1))):
            raw_val -= (1 << self.length)

        return raw_val

    def decode(self, payload: bytes) -> Union[float, int, bool]:
        """Unpack raw bitfield and calculate scaled physical value."""
        raw = self.unpack_raw(payload)
        # Scaled value
        phys = (raw * self.factor) + self.offset
        # Format cleanly: if factor is integer and offset is integer, return int
        if self.length == 1 and self.factor == 1.0 and self.offset == 0.0:
            return bool(raw)
        if self.factor.is_integer() and self.offset.is_integer():
            return int(phys)
        return round(phys, 6)


@dataclass
class DbcMessage:
    """Definition of a CAN message container with one or more signals."""
    message_id: int               # Clean CAN arbitration ID (without CANdb 0x80000000 extended mask)
    name: str
    dlc: int
    transmitter: str = "Vector__XXX"
    is_extended_id: bool = False
    signals: Dict[str, DbcSignal] = field(default_factory=dict)
    comment: str = ""

    def add_signal(self, signal: DbcSignal) -> None:
        self.signals[signal.name] = signal

    def decode(self, payload: bytes) -> Dict[str, Any]:
        """Decode all signals contained in the payload."""
        results: Dict[str, Any] = {}
        for sig_name, sig in self.signals.items():
            results[sig_name] = sig.decode(payload)
        return results


class DbcDatabase:
    """In-memory collection of decoded CAN / J1939 messages and signals."""

    def __init__(self) -> None:
        self.messages_by_id: Dict[int, DbcMessage] = {}
        self.messages_by_name: Dict[str, DbcMessage] = {}
        self.messages_by_pgn: Dict[int, DbcMessage] = {}

    def add_message(self, message: DbcMessage) -> None:
        self.messages_by_id[message.message_id] = message
        self.messages_by_name[message.name] = message

        # If message has an extended 29-bit ID, index by SAE J1939 PGN as well
        if message.is_extended_id or message.message_id > 0x7FF:
            # Extract 18-bit PGN: EDP (bit 25), DP (bit 24), PF (bits 23..16), PS (bits 15..8)
            edp = (message.message_id >> 25) & 0x01
            dp = (message.message_id >> 24) & 0x01
            pf = (message.message_id >> 16) & 0xFF
            ps = (message.message_id >> 8) & 0xFF
            pgn = (edp << 17) | (dp << 16) | (pf << 8) if pf < 240 else (edp << 17) | (dp << 16) | (pf << 8) | ps
            self.messages_by_pgn[pgn] = message

    def find_message(
        self,
        arbitration_id: int,
        is_extended_id: Optional[bool] = None,
    ) -> Optional[DbcMessage]:
        """Lookup message by exact CAN arbitration ID or SAE J1939 PGN."""
        # 1. Exact ID match
        if arbitration_id in self.messages_by_id:
            msg = self.messages_by_id[arbitration_id]
            if is_extended_id is None or msg.is_extended_id == is_extended_id:
                return msg

        # 2. J1939 PGN lookup (handles priority 0 and low CAN IDs)
        should_check_pgn = (is_extended_id is not False)
        if should_check_pgn:
            edp = (arbitration_id >> 25) & 0x01
            dp = (arbitration_id >> 24) & 0x01
            pf = (arbitration_id >> 16) & 0xFF
            ps = (arbitration_id >> 8) & 0xFF
            pgn = (edp << 17) | (dp << 16) | (pf << 8) if pf < 240 else (edp << 17) | (dp << 16) | (pf << 8) | ps
            if pgn in self.messages_by_pgn:
                return self.messages_by_pgn[pgn]

        return None

    def decode_frame(
        self,
        arbitration_id: int,
        payload: bytes,
        is_extended_id: Optional[bool] = None,
    ) -> Optional[Dict[str, Any]]:
        """Decode a raw CAN frame's payload into structured physical signals."""
        msg = self.find_message(arbitration_id, is_extended_id=is_extended_id)
        if not msg:
            return None
        return {
            "message_name": msg.name,
            "message_id": f"0x{arbitration_id:X}",
            "signals": msg.decode(payload),
        }

    @classmethod
    def from_text(cls, dbc_text: str) -> DbcDatabase:
        """Parse raw CANdb (.dbc) file content string."""
        db = cls()
        current_msg: Optional[DbcMessage] = None

        # Regex for BO_ <ID> <Name>: <DLC> <Transmitter>
        bo_pattern = re.compile(r"^BO_\s+(\d+)\s+(\w+)\s*:\s*(\d+)\s+(\w+)")

        # Regex for SG_ <Name> [MUX] : <StartBit>|<Length>@<Order><Sign> (<Factor>,<Offset>) [<Min>|<Max>] "<Unit>" <Receivers>
        sg_pattern = re.compile(
            r"^\s*SG_\s+(\w+)(?:\s+[mM\d]+)?\s*:\s*(\d+)\|(\d+)@([01])([+-])\s+"
            r"\(([-0-9.eE+]+),([-0-9.eE+]+)\)\s+\[([-0-9.eE+]+)\|([-0-9.eE+]+)\]\s+\"([^\"]*)\"\s*(.*)"
        )

        for line in dbc_text.splitlines():
            line_str = line.strip()
            if not line_str:
                continue

            # 1. Match Message Header BO_
            bo_match = bo_pattern.match(line_str)
            if bo_match:
                raw_id = int(bo_match.group(1))
                name = bo_match.group(2)
                dlc = int(bo_match.group(3))
                transmitter = bo_match.group(4)

                # Check Vector extended frame flag (0x80000000)
                is_ext = bool(raw_id & 0x80000000) or raw_id > 0x7FF
                clean_id = raw_id & 0x1FFFFFFF if is_ext else raw_id & 0x7FF

                current_msg = DbcMessage(
                    message_id=clean_id,
                    name=name,
                    dlc=dlc,
                    transmitter=transmitter,
                    is_extended_id=is_ext,
                )
                db.add_message(current_msg)
                continue

            # 2. Match Signal SG_
            sg_match = sg_pattern.match(line_str)
            if sg_match and current_msg is not None:
                sig_name = sg_match.group(1)
                start_bit = int(sg_match.group(2))
                length = int(sg_match.group(3))
                byte_order = sg_match.group(4) == "1"  # 1 = Intel, 0 = Motorola
                is_signed = sg_match.group(5) == "-"   # - = Signed, + = Unsigned
                factor = float(sg_match.group(6))
                offset = float(sg_match.group(7))
                min_val = float(sg_match.group(8))
                max_val = float(sg_match.group(9))
                unit = sg_match.group(10)
                receivers = [r.strip() for r in sg_match.group(11).split(",") if r.strip()]

                signal = DbcSignal(
                    name=sig_name,
                    start_bit=start_bit,
                    length=length,
                    is_little_endian=byte_order,
                    is_signed=is_signed,
                    factor=factor,
                    offset=offset,
                    min_val=min_val,
                    max_val=max_val,
                    unit=unit,
                    receivers=receivers,
                )
                current_msg.add_signal(signal)

        return db

    @classmethod
    def from_file(cls, path: Union[str, Path]) -> DbcDatabase:
        """Load and parse a DBC file from the filesystem."""
        p = Path(path)
        with open(p, "r", encoding="utf-8", errors="replace") as f:
            return cls.from_text(f.read())
