"""SAE J1939 Heavy-Duty and Commercial Vehicle Protocol Parser.

Implements standard 29-bit CAN identifier decoding, Parameter Group Number (PGN)
resolution (PDU1 destination-directed vs PDU2 broadcast), and Suspect Parameter
Number (SPN) extraction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from event_replay.domain.can import CanFdFrame


# Global broadcast destination address
J1939_GLOBAL_ADDRESS: int = 0xFF
# Null / unassigned address
J1939_NULL_ADDRESS: int = 0xFE


@dataclass(frozen=True)
class J1939Header:
    """Parsed SAE J1939 29-bit CAN Identifier Header.

    Bit layout (29 bits total, MSB to LSB):
    - Bits 28..26 (3 bits): Priority (0 = highest priority, 7 = lowest)
    - Bit 25      (1 bit):  Extended Data Page (EDP, always 0 in J1939)
    - Bit 24      (1 bit):  Data Page (DP, 0 or 1)
    - Bits 23..16 (8 bits): PDU Format (PF, 0..255)
    - Bits 15..8  (8 bits): PDU Specific (PS, 0..255) - DA in PDU1, GE in PDU2
    - Bits 7..0   (8 bits): Source Address (SA, 0..255)
    """
    priority: int
    edp: int
    dp: int
    pdu_format: int
    pdu_specific: int
    source_address: int
    destination_address: Optional[int]
    pgn: int
    is_pdu1: bool

    @classmethod
    def parse_can_id(cls, arbitration_id: int) -> J1939Header:
        """Decode a 29-bit CAN identifier into J1939 header fields."""
        if arbitration_id < 0 or arbitration_id > 0x1FFFFFFF:
            raise ValueError(
                f"SAE J1939 requires a 29-bit CAN identifier (0x0..0x1FFFFFFF), got 0x{arbitration_id:X}"
            )

        priority = (arbitration_id >> 26) & 0x07
        edp = (arbitration_id >> 25) & 0x01
        dp = (arbitration_id >> 24) & 0x01
        pf = (arbitration_id >> 16) & 0xFF
        ps = (arbitration_id >> 8) & 0xFF
        sa = arbitration_id & 0xFF

        is_pdu1 = (pf < 240)
        if is_pdu1:
            # PDU1 (0..239): PDU Specific is Destination Address (DA)
            # PGN has the lower byte masked to 0x00
            destination_address: Optional[int] = ps
            pgn = (dp << 16) | (pf << 8)
        else:
            # PDU2 (240..255): PDU Specific is Group Extension (GE)
            # Broadcast message; PGN incorporates PS
            destination_address = None
            pgn = (dp << 16) | (pf << 8) | ps

        return cls(
            priority=priority,
            edp=edp,
            dp=dp,
            pdu_format=pf,
            pdu_specific=ps,
            source_address=sa,
            destination_address=destination_address,
            pgn=pgn,
            is_pdu1=is_pdu1,
        )

    def to_can_id(self) -> int:
        """Encode this J1939 header back into a 29-bit CAN identifier."""
        ps_value = self.destination_address if (self.is_pdu1 and self.destination_address is not None) else self.pdu_specific
        can_id = (
            ((self.priority & 0x07) << 26)
            | ((self.edp & 0x01) << 25)
            | ((self.dp & 0x01) << 24)
            | ((self.pdu_format & 0xFF) << 16)
            | ((ps_value & 0xFF) << 8)
            | (self.source_address & 0xFF)
        )
        return can_id

    @classmethod
    def build(
        cls,
        pgn: int,
        source_address: int,
        priority: int = 6,
        destination_address: Optional[int] = None,
    ) -> J1939Header:
        """Construct a J1939Header given PGN, SA, priority and optional destination."""
        dp = (pgn >> 16) & 0x01
        pf = (pgn >> 8) & 0xFF
        ps_low = pgn & 0xFF

        is_pdu1 = (pf < 240)
        if is_pdu1:
            da = destination_address if destination_address is not None else J1939_GLOBAL_ADDRESS
            pdu_specific = da
        else:
            da = None
            pdu_specific = ps_low

        return cls(
            priority=priority,
            edp=0,
            dp=dp,
            pdu_format=pf,
            pdu_specific=pdu_specific,
            source_address=source_address,
            destination_address=da,
            pgn=pgn,
            is_pdu1=is_pdu1,
        )


@dataclass(frozen=True)
class J1939Message:
    """An SAE J1939 high-level message consisting of header and data payload."""
    header: J1939Header
    data: bytes

    @property
    def pgn(self) -> int:
        return self.header.pgn

    @property
    def pgn_hex(self) -> str:
        return f"0x{self.pgn:04X}"

    @property
    def source_address(self) -> int:
        return self.header.source_address

    @property
    def destination_address(self) -> Optional[int]:
        return self.header.destination_address

    def to_can_frame(self, is_fd: bool = False) -> CanFdFrame:
        """Convert this J1939 message into a low-level CanFdFrame."""
        return CanFdFrame(
            arbitration_id=self.header.to_can_id(),
            data=self.data,
            is_extended_id=True,
            is_fd=is_fd,
        )

    @classmethod
    def from_can_frame(cls, frame: CanFdFrame) -> J1939Message:
        """Extract a J1939Message from a CanFdFrame with a 29-bit identifier."""
        if not frame.is_extended_id and frame.arbitration_id <= 0x7FF:
            raise ValueError(
                f"J1939 messages require 29-bit extended CAN ID; got standard 11-bit ID 0x{frame.arbitration_id:03X}"
            )
        header = J1939Header.parse_can_id(frame.arbitration_id)
        return cls(header=header, data=frame.data)
