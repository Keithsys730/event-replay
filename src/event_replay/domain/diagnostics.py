"""Automotive Vehicle Diagnostic Protocols: SAE J1939-73 DM1/DM2 & ISO 14229 UDS.

Provides standard automotive and commercial vehicle diagnostic decoding and synthesis:
1. SAE J1939-73 Diagnostic Messages:
   - DM1 (PGN 65226 / 0xFECA): Active Diagnostic Trouble Codes
   - DM2 (PGN 65227 / 0xFECB): Previously Active Diagnostic Trouble Codes
   - Lamp Status decoding (MIL, Red Stop, Amber Warning, Protect)
   - 4-byte DTC bitfield extraction:
     * 19-bit Suspect Parameter Number (SPN)
     * 5-bit Failure Mode Identifier (FMI) with standard description mapping
     * 1-bit SPN Conversion Method (CM)
     * 7-bit Occurrence Count (OC)
   - Supports single-packet (<= 8 bytes, 0 or 1 DTC) and multi-packet (via J1939-21 TP)

2. ISO 14229-1 Unified Diagnostic Services (UDS) over CAN:
   - Service identifiers (SID): SessionControl (0x10), ECUReset (0x11), RDBI (0x22),
     SecurityAccess (0x27), WDBI (0x2E), TesterPresent (0x3E), NegativeResponse (0x7F)
   - Standard Negative Response Codes (NRC)
   - ISO 15765-2 Single Frame (SF) PCI encapsulation & payload extraction
   - Data Identifier (DID) resolution (e.g. 0xF190 VIN, 0x0100 Voltage)

3. Diagnostic Fault Injector:
   - Synthesizes compliant DM1/DM2 fault frames and UDS response sequences
   - Ideal for Software-in-the-Loop (SIL) closed-loop fault testing
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
import math
from typing import Any, Dict, List, Optional, Tuple, Union

from event_replay.domain.can import CanFdFrame
from event_replay.domain.j1939 import (
    J1939Header,
    J1939Message,
    J1939_GLOBAL_ADDRESS,
)
from event_replay.domain.j1939_tp import segment_j1939_message


# SAE J1939-73 Parameter Group Numbers (PGNs)
PGN_DM1_ACTIVE_DTC: int = 0x00FECA       # 65226 - Active Diagnostic Trouble Codes
PGN_DM2_PREV_ACTIVE_DTC: int = 0x00FECB  # 65227 - Previously Active DTCs
PGN_DM3_DIAG_DATA_CLEAR: int = 0x00FECC  # 65228 - Clear Active DTCs


class LampStatus(IntEnum):
    """SAE J1939-73 Diagnostic Lamp Status (2 bits)."""
    OFF = 0b00
    ON = 0b01
    ERROR = 0b10
    NOT_AVAILABLE = 0b11


class FlashState(IntEnum):
    """SAE J1939-73 Diagnostic Lamp Flash State (2 bits)."""
    SLOW_FLASH = 0b00       # 1 Hz
    FAST_FLASH = 0b01       # 2 Hz or faster
    RESERVED = 0b10
    UNAVAILABLE = 0b11      # Unavailable / Steady Continuous On


# SAE J1939-73 Standard Failure Mode Identifier (FMI) Definitions (0..31)
J1939_FMI_DESCRIPTIONS: Dict[int, str] = {
    0: "Data Valid But Above Normal Operational Range (Most Severe Level)",
    1: "Data Valid But Below Normal Operational Range (Most Severe Level)",
    2: "Data Erratic, Intermittent Or Incorrect",
    3: "Voltage Above Normal, Or Shorted To High Source",
    4: "Voltage Below Normal, Or Shorted To Low Source",
    5: "Current Below Normal Or Open Circuit",
    6: "Current Above Normal Or Grounded Circuit",
    7: "Mechanical System Not Responding Or Out Of Adjustment",
    8: "Abnormal Frequency Or Pulse Width Or Period",
    9: "Abnormal Update Rate",
    10: "Abnormal Rate Of Change",
    11: "Root Cause Not Known",
    12: "Bad Intelligent Device Or Component",
    13: "Out Of Calibration",
    14: "Special Instructions",
    15: "Data Valid But Above Normal Operating Range (Least Severe Level)",
    16: "Data Valid But Above Normal Operating Range (Moderately Severe Level)",
    17: "Data Valid But Below Normal Operating Range (Least Severe Level)",
    18: "Data Valid But Below Normal Operating Range (Moderately Severe Level)",
    19: "Received Network Data In Error",
    20: "Data Drifted High",
    21: "Data Drifted Low",
    31: "Condition Exists",
}


@dataclass(frozen=True)
class J1939LampState:
    """SAE J1939-73 Diagnostic Lamp Status and Flash States (Bytes 1-2)."""
    protect_lamp: LampStatus = LampStatus.OFF
    amber_warning_lamp: LampStatus = LampStatus.OFF
    red_stop_lamp: LampStatus = LampStatus.OFF
    malfunction_indicator_lamp: LampStatus = LampStatus.OFF
    flash_protect: FlashState = FlashState.UNAVAILABLE
    flash_amber: FlashState = FlashState.UNAVAILABLE
    flash_red: FlashState = FlashState.UNAVAILABLE
    flash_mil: FlashState = FlashState.UNAVAILABLE

    @classmethod
    def from_bytes(cls, raw: bytes) -> J1939LampState:
        """Decode LampState from first two bytes of a DM1/DM2 message."""
        if len(raw) < 2:
            return cls()

        b1, b2 = raw[0], raw[1]
        mil = LampStatus((b1 >> 6) & 0x03)
        rsl = LampStatus((b1 >> 4) & 0x03)
        awl = LampStatus((b1 >> 2) & 0x03)
        pl = LampStatus(b1 & 0x03)

        f_mil = FlashState((b2 >> 6) & 0x03)
        f_rsl = FlashState((b2 >> 4) & 0x03)
        f_awl = FlashState((b2 >> 2) & 0x03)
        f_pl = FlashState(b2 & 0x03)

        return cls(
            protect_lamp=pl,
            amber_warning_lamp=awl,
            red_stop_lamp=rsl,
            malfunction_indicator_lamp=mil,
            flash_protect=f_pl,
            flash_amber=f_awl,
            flash_red=f_rsl,
            flash_mil=f_mil,
        )

    def to_bytes(self) -> bytes:
        """Encode LampState into 2 bytes."""
        b1 = (
            ((int(self.malfunction_indicator_lamp) & 0x03) << 6)
            | ((int(self.red_stop_lamp) & 0x03) << 4)
            | ((int(self.amber_warning_lamp) & 0x03) << 2)
            | (int(self.protect_lamp) & 0x03)
        )
        b2 = (
            ((int(self.flash_mil) & 0x03) << 6)
            | ((int(self.flash_red) & 0x03) << 4)
            | ((int(self.flash_amber) & 0x03) << 2)
            | (int(self.flash_protect) & 0x03)
        )
        return bytes([b1, b2])


@dataclass(frozen=True)
class J1939DTC:
    """SAE J1939-73 4-byte Diagnostic Trouble Code representation."""
    spn: int           # 19 bits (0..524287)
    fmi: int           # 5 bits (0..31)
    cm: int = 0        # 1 bit conversion method (0 = standard, 1 = alt)
    oc: int = 1        # 7 bits occurrence count (0..127)

    @property
    def fmi_description(self) -> str:
        """Return standard human-readable explanation of the FMI."""
        return J1939_FMI_DESCRIPTIONS.get(self.fmi, f"Reserved / Manufacturer Specific ({self.fmi})")

    @classmethod
    def from_bytes(cls, raw: bytes) -> J1939DTC:
        """Decode a 4-byte J1939 DTC bitfield:

        Bit packing:
        - SPN: bits 31..16 (Byte 0, Byte 1, and upper 3 bits of Byte 2)
        - FMI: lower 5 bits of Byte 2
        - CM:  bit 7 of Byte 3
        - OC:  bits 6..0 of Byte 3
        """
        if len(raw) < 4:
            raise ValueError(f"DTC requires 4 bytes, got {len(raw)}")

        spn_low = raw[0]
        spn_mid = raw[1]
        spn_high = (raw[2] >> 5) & 0x07
        spn = spn_low | (spn_mid << 8) | (spn_high << 16)

        fmi = raw[2] & 0x1F
        cm = (raw[3] >> 7) & 0x01
        oc = raw[3] & 0x7F

        return cls(spn=spn, fmi=fmi, cm=cm, oc=oc)

    def to_bytes(self) -> bytes:
        """Encode DTC into 4-byte J1939 binary format."""
        b0 = self.spn & 0xFF
        b1 = (self.spn >> 8) & 0xFF
        b2 = (((self.spn >> 16) & 0x07) << 5) | (self.fmi & 0x1F)
        b3 = ((self.cm & 0x01) << 7) | (self.oc & 0x7F)
        return bytes([b0, b1, b2, b3])


@dataclass(frozen=True)
class J1939DiagnosticMessage:
    """Parsed SAE J1939-73 DM1 / DM2 Diagnostic Message."""
    pgn: int
    lamp_state: J1939LampState
    dtcs: List[J1939DTC] = field(default_factory=list)

    @property
    def is_dm1(self) -> bool:
        return self.pgn == PGN_DM1_ACTIVE_DTC

    @property
    def is_dm2(self) -> bool:
        return self.pgn == PGN_DM2_PREV_ACTIVE_DTC

    @classmethod
    def decode_payload(cls, pgn: int, payload: bytes) -> J1939DiagnosticMessage:
        """Decode a DM1 or DM2 message payload (single frame or reassembled from TP)."""
        if len(payload) < 2:
            return cls(pgn=pgn, lamp_state=J1939LampState(), dtcs=[])

        lamp_state = J1939LampState.from_bytes(payload[:2])
        dtcs: List[J1939DTC] = []

        # Check for zero DTC indicator (bytes 2..5 all 0x00 or length < 6)
        if len(payload) >= 6:
            dtc_bytes = payload[2:]
            # If standard empty indication (4 zero bytes)
            if len(dtc_bytes) >= 4 and dtc_bytes[:4] == b"\x00\x00\x00\x00":
                return cls(pgn=pgn, lamp_state=lamp_state, dtcs=[])

            idx = 2
            while idx + 4 <= len(payload):
                chunk = payload[idx:idx + 4]
                # If padding 0xFF or 0x00 termination
                if chunk == b"\xFF\xFF\xFF\xFF" or chunk == b"\x00\x00\x00\x00":
                    break
                dtc = J1939DTC.from_bytes(chunk)
                dtcs.append(dtc)
                idx += 4

        return cls(pgn=pgn, lamp_state=lamp_state, dtcs=dtcs)

    def encode_payload(self) -> bytes:
        """Encode message into binary payload."""
        out = bytearray(self.lamp_state.to_bytes())
        if not self.dtcs:
            # SAE J1939-73: No active DTCs is indicated by 4 bytes of 0x00 + 2 bytes 0xFF
            out.extend(b"\x00\x00\x00\x00\xFF\xFF")
        else:
            for dtc in self.dtcs:
                out.extend(dtc.to_bytes())
            # Minimum J1939 CAN frame is 8 bytes
            while len(out) < 8:
                out.append(0xFF)
        return bytes(out)

    def to_can_frames(
        self,
        source_address: int,
        priority: int = 6,
        destination_address: int = J1939_GLOBAL_ADDRESS,
    ) -> List[CanFdFrame]:
        """Convert DM1/DM2 into low-level CAN frames (BAM segmentation if > 8 bytes)."""
        payload = self.encode_payload()
        hdr = J1939Header.build(
            pgn=self.pgn,
            source_address=source_address,
            priority=priority,
            destination_address=destination_address,
        )
        msg = J1939Message(header=hdr, data=payload)

        if len(payload) <= 8:
            return [msg.to_can_frame()]
        return segment_j1939_message(msg, is_bam=(destination_address == J1939_GLOBAL_ADDRESS))


# ISO 14229-1 Unified Diagnostic Services (UDS) Constants
class UdsServiceId(IntEnum):
    """Standard ISO 14229-1 Diagnostic Service Identifiers (SIDs)."""
    DIAGNOSTIC_SESSION_CONTROL = 0x10
    ECU_RESET = 0x11
    CLEAR_DIAGNOSTIC_INFORMATION = 0x14
    READ_DTC_INFORMATION = 0x19
    READ_DATA_BY_IDENTIFIER = 0x22
    SECURITY_ACCESS = 0x27
    COMMUNICATION_CONTROL = 0x28
    WRITE_DATA_BY_IDENTIFIER = 0x2E
    INPUT_OUTPUT_CONTROL_BY_IDENTIFIER = 0x2F
    ROUTINE_CONTROL = 0x31
    REQUEST_DOWNLOAD = 0x34
    REQUEST_UPLOAD = 0x35
    TRANSFER_DATA = 0x36
    REQUEST_TRANSFER_EXIT = 0x37
    TESTER_PRESENT = 0x3E
    CONTROL_DTC_SETTING = 0x85
    NEGATIVE_RESPONSE = 0x7F


class UdsNegativeResponseCode(IntEnum):
    """Standard ISO 14229-1 Negative Response Codes (NRCs)."""
    GENERAL_REJECT = 0x10
    SERVICE_NOT_SUPPORTED = 0x11
    SUB_FUNCTION_NOT_SUPPORTED = 0x12
    INCORRECT_MESSAGE_LENGTH_OR_INVALID_FORMAT = 0x13
    RESPONSE_TOO_LONG = 0x14
    BUSY_REPEAT_REQUEST = 0x21
    CONDITIONS_NOT_CORRECT = 0x22
    REQUEST_SEQUENCE_ERROR = 0x24
    REQUEST_OUT_OF_RANGE = 0x31
    SECURITY_ACCESS_DENIED = 0x33
    INVALID_KEY = 0x35
    EXCEEDED_NUMBER_OF_ATTEMPTS = 0x36
    REQUIRED_TIME_DELAY_NOT_EXPIRED = 0x37
    UPLOAD_DOWNLOAD_NOT_ACCEPTED = 0x70
    TRANSFER_DATA_SUSPENDED = 0x71
    GENERAL_PROGRAMMING_FAILURE = 0x72
    WRONG_BLOCK_SEQUENCE_COUNTER = 0x73
    REQUEST_CORRECTLY_RECEIVED_RESPONSE_PENDING = 0x78
    SUB_FUNCTION_NOT_SUPPORTED_IN_ACTIVE_SESSION = 0x7E
    SERVICE_NOT_SUPPORTED_IN_ACTIVE_SESSION = 0x7F


class UdsSessionType(IntEnum):
    """DiagnosticSessionControl (0x10) sub-function types."""
    DEFAULT_SESSION = 0x01
    PROGRAMMING_SESSION = 0x02
    EXTENDED_DIAGNOSTIC_SESSION = 0x03
    SAFETY_SYSTEM_DIAGNOSTIC_SESSION = 0x04


@dataclass(frozen=True)
class UdsMessage:
    """Decoded ISO 14229-1 UDS request or response message."""
    service_id: int
    is_response: bool
    is_negative_response: bool = False
    sub_function: Optional[int] = None
    data_identifier: Optional[int] = None
    nrc: Optional[UdsNegativeResponseCode] = None
    payload: bytes = b""

    @property
    def service_name(self) -> str:
        """Resolve symbolic service name."""
        try:
            return UdsServiceId(self.service_id).name
        except ValueError:
            return f"CUSTOM_SERVICE_0x{self.service_id:02X}"

    @classmethod
    def decode(cls, raw_payload: bytes, has_pci: bool = True) -> UdsMessage:
        """Decode a UDS frame payload (with optional ISO 15765-2 Single Frame PCI)."""
        if not raw_payload:
            raise ValueError("Cannot decode empty UDS payload")

        pdu = raw_payload
        if has_pci:
            # ISO 15765-2 Single Frame (SF) detection
            first_nibble = (raw_payload[0] >> 4) & 0x0F
            if first_nibble != 0x0:
                raise ValueError(
                    f"Unsupported ISO 15765-2 frame type 0x{first_nibble:X}: only Single Frame (0x0) is supported"
                )

            sf_dl = raw_payload[0] & 0x0F
            if sf_dl == 0:
                # CAN-FD extended SF format: 0x00 followed by 1 byte DL
                if len(raw_payload) < 2:
                    raise ValueError("CAN-FD Single Frame missing extended length byte")
                sf_dl = raw_payload[1]
                if sf_dl == 0 or sf_dl > 62:
                    raise ValueError(f"Invalid CAN-FD Single Frame data length: {sf_dl}")
                pdu = raw_payload[2:2 + sf_dl]
                if len(pdu) < sf_dl:
                    raise ValueError(
                        f"Truncated ISO 15765-2 CAN-FD Single Frame: expected {sf_dl} bytes, got {len(pdu)}"
                    )
            else:
                if sf_dl > 7:
                    raise ValueError(f"Invalid Classical CAN Single Frame data length: {sf_dl}")
                pdu = raw_payload[1:1 + sf_dl]
                if len(pdu) < sf_dl:
                    raise ValueError(
                        f"Truncated ISO 15765-2 Single Frame: expected {sf_dl} bytes, got {len(pdu)}"
                    )

        if not pdu:
            raise ValueError("No UDS PDU bytes found after PCI extraction")

        sid_byte = pdu[0]

        # 1. Negative Response (0x7F)
        if sid_byte == UdsServiceId.NEGATIVE_RESPONSE:
            if len(pdu) < 3:
                raise ValueError(f"UDS Negative Response requires at least 3 bytes, got {len(pdu)}")
            rej_sid = pdu[1]
            try:
                nrc = UdsNegativeResponseCode(pdu[2])
            except ValueError:
                nrc = UdsNegativeResponseCode.GENERAL_REJECT

            return cls(
                service_id=rej_sid,
                is_response=True,
                is_negative_response=True,
                nrc=nrc,
                payload=pdu[3:],
            )

        # 2. Positive Response (SID >= 0x40 and (SID - 0x40) is valid)
        is_response = False
        base_sid = sid_byte
        if sid_byte >= 0x40:
            potential_base = sid_byte - 0x40
            try:
                UdsServiceId(potential_base)
                is_response = True
                base_sid = potential_base
            except ValueError:
                is_response = False
                base_sid = sid_byte

        sub_func: Optional[int] = None
        did: Optional[int] = None
        data = b""

        # 3. Extract sub-functions or Data Identifiers (DIDs)
        if base_sid in (UdsServiceId.READ_DATA_BY_IDENTIFIER, UdsServiceId.WRITE_DATA_BY_IDENTIFIER):
            if len(pdu) >= 3:
                did = (pdu[1] << 8) | pdu[2]
                data = pdu[3:]
        elif base_sid in (
            UdsServiceId.DIAGNOSTIC_SESSION_CONTROL,
            UdsServiceId.ECU_RESET,
            UdsServiceId.SECURITY_ACCESS,
            UdsServiceId.TESTER_PRESENT,
            UdsServiceId.READ_DTC_INFORMATION,
        ):
            if len(pdu) >= 2:
                sub_func = pdu[1]
                data = pdu[2:]
        else:
            data = pdu[1:]

        return cls(
            service_id=base_sid,
            is_response=is_response,
            is_negative_response=False,
            sub_function=sub_func,
            data_identifier=did,
            payload=data,
        )

    def encode(self, add_pci: bool = True, pad_to_8: bool = True) -> bytes:
        """Encode UDS message into binary frame with ISO 15765-2 Single Frame PCI."""
        pdu = bytearray()
        if self.is_negative_response:
            pdu.append(int(UdsServiceId.NEGATIVE_RESPONSE))
            pdu.append(self.service_id & 0xFF)
            nrc_val = int(self.nrc) if self.nrc is not None else int(UdsNegativeResponseCode.GENERAL_REJECT)
            pdu.append(nrc_val & 0xFF)
            pdu.extend(self.payload)
        else:
            sid_byte = (self.service_id + 0x40) if self.is_response else self.service_id
            pdu.append(sid_byte & 0xFF)

            if self.data_identifier is not None:
                pdu.append((self.data_identifier >> 8) & 0xFF)
                pdu.append(self.data_identifier & 0xFF)
            elif self.sub_function is not None:
                pdu.append(self.sub_function & 0xFF)

            pdu.extend(self.payload)

        if not add_pci:
            return bytes(pdu)

        pdu_len = len(pdu)
        if pdu_len == 0:
            raise ValueError("Cannot encode empty UDS Single Frame")
        if pdu_len > 62:
            raise ValueError(
                f"UDS Single Frame payload length {pdu_len} exceeds maximum CAN-FD SF capacity (62 bytes)"
            )

        if pdu_len > 7:
            # CAN-FD Extended Single Frame (0x00 followed by 1 byte DL)
            out = bytearray([0x00, pdu_len]) + pdu
        else:
            # Classical CAN Single Frame (0x0N where N = length)
            out = bytearray([pdu_len & 0x0F]) + pdu

        if pad_to_8 and len(out) < 8:
            while len(out) < 8:
                out.append(0xAA)  # Standard ISO 15765-2 padding byte

        return bytes(out)


class DiagnosticFaultInjector:
    """Synthesizes J1939-73 DM1/DM2 and ISO 14229 UDS diagnostic frames for test & SIL harness."""

    @staticmethod
    def create_j1939_dm1_active_fault(
        source_address: int,
        spn: int,
        fmi: int,
        occurrence_count: int = 1,
        red_stop_lamp: LampStatus = LampStatus.ON,
        malfunction_indicator_lamp: LampStatus = LampStatus.ON,
        priority: int = 6,
    ) -> List[CanFdFrame]:
        """Create a J1939 DM1 frame indicating an active vehicle fault."""
        lamp_state = J1939LampState(
            red_stop_lamp=red_stop_lamp,
            malfunction_indicator_lamp=malfunction_indicator_lamp,
        )
        dtc = J1939DTC(spn=spn, fmi=fmi, oc=occurrence_count)
        msg = J1939DiagnosticMessage(
            pgn=PGN_DM1_ACTIVE_DTC,
            lamp_state=lamp_state,
            dtcs=[dtc],
        )
        return msg.to_can_frames(source_address=source_address, priority=priority)

    @staticmethod
    def create_uds_negative_response(
        arbitration_id: int,
        rejected_service: Union[int, UdsServiceId],
        nrc: UdsNegativeResponseCode,
        is_extended_id: bool = False,
    ) -> CanFdFrame:
        """Create a UDS 0x7F Negative Response CAN frame."""
        uds_msg = UdsMessage(
            service_id=int(rejected_service),
            is_response=True,
            is_negative_response=True,
            nrc=nrc,
        )
        return CanFdFrame(
            arbitration_id=arbitration_id,
            data=uds_msg.encode(add_pci=True),
            is_extended_id=is_extended_id,
        )

    @staticmethod
    def create_uds_read_data_response(
        arbitration_id: int,
        data_identifier: int,
        data_payload: bytes,
        is_extended_id: bool = False,
    ) -> CanFdFrame:
        """Create a UDS 0x62 ReadDataByIdentifier positive response frame."""
        uds_msg = UdsMessage(
            service_id=int(UdsServiceId.READ_DATA_BY_IDENTIFIER),
            is_response=True,
            data_identifier=data_identifier,
            payload=data_payload,
        )
        return CanFdFrame(
            arbitration_id=arbitration_id,
            data=uds_msg.encode(add_pci=True),
            is_extended_id=is_extended_id,
        )


def format_j1939_diagnostics(diag_msg: J1939DiagnosticMessage) -> Dict[str, Any]:
    """Format J1939 DM1/DM2 diagnostic message into standard structured dictionary."""
    return {
        "diagnostic_type": "J1939_DM1" if diag_msg.is_dm1 else "J1939_DM2",
        "lamp_status": {
            "protect_lamp": diag_msg.lamp_state.protect_lamp.name,
            "amber_warning_lamp": diag_msg.lamp_state.amber_warning_lamp.name,
            "red_stop_lamp": diag_msg.lamp_state.red_stop_lamp.name,
            "malfunction_indicator_lamp": diag_msg.lamp_state.malfunction_indicator_lamp.name,
            "flash_protect": diag_msg.lamp_state.flash_protect.name,
            "flash_amber": diag_msg.lamp_state.flash_amber.name,
            "flash_red": diag_msg.lamp_state.flash_red.name,
            "flash_mil": diag_msg.lamp_state.flash_mil.name,
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


def format_uds_diagnostics(uds_msg: UdsMessage) -> Dict[str, Any]:
    """Format ISO 14229 UDS message into standard structured dictionary."""
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

