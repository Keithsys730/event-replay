"""SAE J1939 Transport Protocol (SAE J1939-21) Segmentation and Reassembly.

Provides support for Parameter Groups larger than 8 bytes (up to 1785 bytes):
- Connection Management (TP.CM, PGN 60416 / 0xEC00)
  * BAM (Broadcast Announce Message, Control Byte 0x20 / 32)
  * RTS (Request To Send, Control Byte 0x10 / 16)
  * CTS (Clear To Send, Control Byte 0x11 / 17)
  * End-of-Message ACK (EOMACK, Control Byte 0x13 / 19)
  * Connection Abort (Conn_Abort, Control Byte 0xFF / 255)
- Data Transfer (TP.DT, PGN 60160 / 0xEB00)
  * Sequence numbers 1 to 255
  * 7 payload bytes per packet with 0xFF padding on final packet
- Multi-Session Reassembler (J1939TransportReassembler)
  * Tracks concurrent BAM and peer-to-peer unicast sessions per CAN channel
  * Supports receiver and transmitter Connection Aborts
  * Out-of-order packet reordering by sequence number
  * Validates total_packets == ceil(total_bytes / 7)
  * Exact payload truncation (stripping trailing padding)
  * Seamless conversion to high-level J1939Message
- Message Segmenter (segment_j1939_message)
  * Generates compliant TP.CM and TP.DT frame sequences from large payloads
  * Preserves message.destination_address in unicast RTS sessions
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
import math
from typing import Any, Dict, Iterator, List, Optional, Tuple

from event_replay.domain.can import CanFdFrame
from event_replay.domain.j1939 import (
    J1939Header,
    J1939Message,
    J1939_GLOBAL_ADDRESS,
)


PGN_TP_CM: int = 0x00EC00  # 60416 - Connection Management
PGN_TP_DT: int = 0x00EB00  # 60160 - Data Transfer

MAX_TP_MESSAGE_SIZE: int = 1785
MAX_TP_PACKETS: int = 255
TP_PACKET_DATA_SIZE: int = 7


class TpControlByte(IntEnum):
    """J1939 TP.CM Control Byte values (SAE J1939-21)."""
    RTS = 0x10     # 16: Request To Send
    CTS = 0x11     # 17: Clear To Send
    EOMACK = 0x13  # 19: End-of-Message Acknowledgment
    BAM = 0x20     # 32: Broadcast Announce Message
    ABORT = 0xFF   # 255: Connection Abort


class TpAbortReason(IntEnum):
    """SAE J1939-21 Connection Abort Reason Codes."""
    ALREADY_IN_SESSION = 1
    SYSTEM_RESOURCES = 2
    TIMEOUT = 3
    CTS_WHILE_DT_IN_PROGRESS = 4
    MAX_RETRANSMIT_REACHED = 5
    UNEXPECTED_DT_PACKET = 6
    BAD_SEQUENCE_NUMBER = 7
    DUPLICATE_SEQUENCE_NUMBER = 8
    TOTAL_SIZE_EXCEEDED = 9


@dataclass
class TpSession:
    """Active J1939 Transport Protocol reassembly session."""
    source_address: int
    destination_address: int
    pgn: int
    total_bytes: int
    total_packets: int
    is_bam: bool
    priority: int = 6
    channel: str = "can0"
    packets: Dict[int, bytes] = field(default_factory=dict)
    aborted: bool = False
    abort_reason: Optional[int] = None

    @property
    def is_complete(self) -> bool:
        """True if all packets from 1 to total_packets have been collected."""
        if self.aborted or self.total_packets == 0:
            return False
        return len(self.packets) == self.total_packets

    def add_packet(self, sequence_number: int, data: bytes) -> bool:
        """Add a TP.DT packet to the session.
        
        Returns:
            True if this packet completed the session, False otherwise.
        """
        if self.aborted:
            return False
        if sequence_number < 1 or sequence_number > self.total_packets:
            return False

        # Store only up to 7 payload bytes
        self.packets[sequence_number] = data[:TP_PACKET_DATA_SIZE]
        return self.is_complete

    def assemble_payload(self) -> bytes:
        """Concatenate all packets in sequence order and slice to exact byte count."""
        if not self.is_complete:
            raise ValueError(
                f"Cannot assemble incomplete TP session: have {len(self.packets)} of {self.total_packets} packets"
            )
        buffer = bytearray()
        for seq in range(1, self.total_packets + 1):
            buffer.extend(self.packets[seq])
        if len(buffer) < self.total_bytes:
            raise ValueError(
                f"Assembled payload length {len(buffer)} is less than expected {self.total_bytes} bytes"
            )
        return bytes(buffer[:self.total_bytes])


class J1939TransportReassembler:
    """State machine that reassembles multi-packet SAE J1939 TP streams.
    
    Maintains concurrent sessions keyed by (channel, source_address, destination_address).
    For BAM broadcasts, destination_address is always 0xFF.
    """

    def __init__(self) -> None:
        # Key: (channel, source_address, destination_address)
        self.active_sessions: Dict[Tuple[str, int, int], TpSession] = {}
        # History of completed or aborted sessions for diagnostics
        self.completed_count: int = 0
        self.aborted_count: int = 0

    def feed_frame(self, frame: CanFdFrame) -> Optional[J1939Message]:
        """Feed a single CAN frame to the reassembler.
        
        Returns:
            - A reconstructed J1939Message if this frame completes a multi-packet session.
            - None if the frame is part of an ongoing session, a control frame, or not a TP frame.
        """
        if not frame.is_extended_id and frame.arbitration_id <= 0x7FF:
            return None

        try:
            header = J1939Header.parse_can_id(frame.arbitration_id)
        except ValueError:
            return None

        # J1939 Transport Protocol is strictly located on Data Page 0 (EDP=0, DP=0)
        if header.edp != 0 or header.dp != 0:
            return None

        if header.pgn == PGN_TP_CM:
            self._handle_cm(header, frame.data, channel=frame.channel)
            return None
        elif header.pgn == PGN_TP_DT:
            return self._handle_dt(header, frame.data, channel=frame.channel)

        return None

    def _handle_cm(self, header: J1939Header, data: bytes, channel: str = "can0") -> None:
        """Process a TP.CM (Connection Management) frame."""
        if len(data) < 8:
            return

        control_byte = data[0]
        sa = header.source_address
        da = header.destination_address if header.destination_address is not None else J1939_GLOBAL_ADDRESS

        # Extract PGN of target message (little-endian 3-byte field in bytes 5..7)
        target_pgn = data[5] | (data[6] << 8) | (data[7] << 16)

        if control_byte == TpControlByte.BAM or control_byte == TpControlByte.RTS:
            total_bytes = data[1] | (data[2] << 8)
            total_packets = data[3]
            is_bam = (control_byte == TpControlByte.BAM)

            expected_packets = math.ceil(total_bytes / TP_PACKET_DATA_SIZE)
            if (
                total_bytes < 9
                or total_bytes > MAX_TP_MESSAGE_SIZE
                or total_packets < 2
                or total_packets > MAX_TP_PACKETS
                or total_packets != expected_packets
            ):
                # Invalid TP announcement
                return

            session_key = (channel, sa, da)
            self.active_sessions[session_key] = TpSession(
                source_address=sa,
                destination_address=da,
                pgn=target_pgn,
                total_bytes=total_bytes,
                total_packets=total_packets,
                is_bam=is_bam,
                priority=header.priority,
                channel=channel,
            )

        elif control_byte == TpControlByte.ABORT:
            abort_reason = data[1]
            # In peer-to-peer sessions, either originator (sa, da) or responder (da, sa) can abort
            for key in [(channel, sa, da), (channel, da, sa)]:
                if key in self.active_sessions and self.active_sessions[key].pgn == target_pgn:
                    sess = self.active_sessions.pop(key)
                    sess.aborted = True
                    sess.abort_reason = abort_reason
                    self.aborted_count += 1
                    break

    def _handle_dt(self, header: J1939Header, data: bytes, channel: str = "can0") -> Optional[J1939Message]:
        """Process a TP.DT (Data Transfer) packet."""
        if len(data) < 2:
            return None

        sa = header.source_address
        da = header.destination_address if header.destination_address is not None else J1939_GLOBAL_ADDRESS
        session_key = (channel, sa, da)

        session = self.active_sessions.get(session_key)
        if session is None:
            # No active session matching this channel, source and destination
            return None

        seq_num = data[0]
        payload_chunk = data[1:]

        is_finished = session.add_packet(seq_num, payload_chunk)
        if is_finished:
            # Session complete! Build full message and clean up session
            del self.active_sessions[session_key]
            self.completed_count += 1

            full_payload = session.assemble_payload()
            dest = None if session.is_bam else session.destination_address
            reconstructed_header = J1939Header.build(
                pgn=session.pgn,
                source_address=session.source_address,
                priority=session.priority,
                destination_address=dest,
            )
            return J1939Message(header=reconstructed_header, data=full_payload)

        return None


def segment_j1939_message(
    message: J1939Message,
    is_bam: bool = True,
    destination_address: Optional[int] = None,
    priority: int = 7,
    channel: str = "can0",
) -> List[CanFdFrame]:
    """Segment a J1939Message with payload > 8 bytes into TP.CM and TP.DT CAN frames.
    
    Args:
        message: The high-level J1939Message to transmit.
        is_bam: True for Broadcast Announce Message (BAM); False for peer-to-peer RTS.
        destination_address: Target node address (used for RTS/CTS peer-to-peer). If None,
            falls back to message.destination_address.
        priority: Transmission priority (0..7, defaults to 7 for BAM).
        channel: CAN channel interface name (e.g. 'can0').

    Returns:
        A list of CanFdFrames (one TP.CM frame followed by N TP.DT frames).
    """
    total_bytes = len(message.data)
    if total_bytes <= 8:
        # Standard frame, no TP required
        return [message.to_can_frame()]

    if total_bytes > MAX_TP_MESSAGE_SIZE:
        raise ValueError(
            f"J1939 TP payload size {total_bytes} exceeds maximum {MAX_TP_MESSAGE_SIZE} bytes"
        )

    total_packets = math.ceil(total_bytes / TP_PACKET_DATA_SIZE)
    if total_packets > MAX_TP_PACKETS:
        raise ValueError(f"Packet count {total_packets} exceeds maximum {MAX_TP_PACKETS}")

    frames: List[CanFdFrame] = []
    sa = message.source_address
    if is_bam:
        da = J1939_GLOBAL_ADDRESS
    elif destination_address is not None:
        da = destination_address
    elif message.destination_address is not None:
        da = message.destination_address
    else:
        da = 0x00

    # 1. Build TP.CM Frame
    cm_header = J1939Header.build(
        pgn=PGN_TP_CM,
        source_address=sa,
        priority=priority,
        destination_address=da,
    )

    control_byte = TpControlByte.BAM if is_bam else TpControlByte.RTS
    pgn_bytes = [
        message.pgn & 0xFF,
        (message.pgn >> 8) & 0xFF,
        (message.pgn >> 16) & 0xFF,
    ]

    cm_payload = bytearray([
        int(control_byte),
        total_bytes & 0xFF,
        (total_bytes >> 8) & 0xFF,
        total_packets,
        0xFF,  # Reserved or max packets per CTS
        pgn_bytes[0],
        pgn_bytes[1],
        pgn_bytes[2],
    ])

    frames.append(CanFdFrame(
        arbitration_id=cm_header.to_can_id(),
        data=bytes(cm_payload),
        is_extended_id=True,
        channel=channel,
    ))

    # 2. Build TP.DT Frames
    dt_header = J1939Header.build(
        pgn=PGN_TP_DT,
        source_address=sa,
        priority=priority,
        destination_address=da,
    )

    for seq in range(1, total_packets + 1):
        start_idx = (seq - 1) * TP_PACKET_DATA_SIZE
        end_idx = min(start_idx + TP_PACKET_DATA_SIZE, total_bytes)
        chunk = bytearray(message.data[start_idx:end_idx])

        # Pad final packet with 0xFF if less than 7 bytes
        while len(chunk) < TP_PACKET_DATA_SIZE:
            chunk.append(0xFF)

        dt_payload = bytes([seq]) + bytes(chunk)
        frames.append(CanFdFrame(
            arbitration_id=dt_header.to_can_id(),
            data=dt_payload,
            is_extended_id=True,
            channel=channel,
        ))

    return frames
