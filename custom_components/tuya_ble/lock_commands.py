"""Payload builders and parsers for Tuya BLE lock credential and unlock DPs.

Layouts follow Tuya's BLE lock data point reference
(https://developer.tuya.com/en/docs/iot/ble?id=K9ow3vcpn71ua, read 2026-11-07)
for ``unlock_method_create`` (DP 1) and ``unlock_method_delete`` (DP 2). The
``ble_unlock_check`` (DP 71) frame and the check code it carries follow the app
capture documented in frankhommers/ha-tuya-ble-access (MIT,
Copyright (c) 2026 Frank Hommers), which also confirms the DP 1 / DP 2 layouts.

Everything here is pure and side-effect free. Payloads carry a PIN or the lock
check code, so callers must never log them.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct
from typing import Final

CRED_TYPE_PASSWORD: Final = 0x01

STAGE_START: Final = 0x00
STAGE_IN_PROGRESS: Final = 0xFC
STAGE_FAILED: Final = 0xFD
STAGE_CANCELLED: Final = 0xFE
STAGE_DONE: Final = 0xFF
FINAL_STAGES: Final = frozenset({STAGE_FAILED, STAGE_CANCELLED, STAGE_DONE})

HARDWARE_ID_AUTO: Final = 0xFF
DELETE_SPECIFIED_METHOD: Final = 0x01
DELETE_RESULT_SUCCESS: Final = 0xFF
DELETE_RESULT_NOT_FOUND: Final = 0x01

MEMBER_ID_MIN: Final = 1
MEMBER_ID_MAX: Final = 100
HARDWARE_ID_MAX: Final = 0xFE
PIN_MIN_DIGITS: Final = 4
PIN_MAX_DIGITS: Final = 10

CHECK_CODE_LENGTH: Final = 8
UNLOCK_CHECK_ADMIN_MEMBER: Final = 0xFFFF
UNLOCK_CHECK_VERSION: Final = 0x0001
UNLOCK_CHECK_TRAILER: Final = b"\x00\x01"
UNLOCK_CHECK_LENGTH: Final = 19
UNLOCK_CHECK_RESULT_SUCCESS: Final = 0x00

# Permanent validity: 2000-01-01 00:00:00 to 2037-12-31 23:59:59 UTC. The end
# stays below 2**31 so a lock that reads the field as signed cannot wrap it.
_VALID_FROM: Final = 946684800
_VALID_UNTIL: Final = 2145916799


@dataclass(frozen=True)
class EnrollResult:
    """A lock's DP 1 report for a credential enrollment."""

    cred_type: int
    stage: int
    admin: bool
    member_id: int
    hardware_id: int
    result_code: int

    @property
    def is_final(self) -> bool:
        """Return whether this report ends the enrollment."""
        return self.stage in FINAL_STAGES

    @property
    def succeeded(self) -> bool:
        """Return whether the enrollment finished without an error."""
        return self.stage == STAGE_DONE and self.result_code == 0


@dataclass(frozen=True)
class DeleteResult:
    """A lock's DP 2 report for a credential deletion."""

    member_id: int
    hardware_id: int
    method: int
    result_code: int

    @property
    def succeeded(self) -> bool:
        """Return whether the lock deleted the credential."""
        return self.result_code == DELETE_RESULT_SUCCESS


def _validity_permanent() -> bytes:
    """Return the 17-byte validity block for a credential that never expires.

    Start and end Unix timestamps, no recurrence, 00:00 to 23:59 every day.
    """
    return (
        struct.pack(">II", _VALID_FROM, _VALID_UNTIL)
        + b"\x00"  # recurrence pattern: none
        + b"\x00\x00\x00\x00"  # recurrence bits
        + bytes([0, 0, 23, 59])  # daily window start hh:mm, end hh:mm
    )


def validate_pin(pin: str) -> bytes:
    """Return the PIN as one byte per digit (0-9), or raise ValueError."""
    if not pin.isascii() or not pin.isdigit():
        raise ValueError("PIN must contain digits only")
    if not PIN_MIN_DIGITS <= len(pin) <= PIN_MAX_DIGITS:
        raise ValueError(
            f"PIN must be {PIN_MIN_DIGITS} to {PIN_MAX_DIGITS} digits long"
        )
    return bytes(int(digit) for digit in pin)


def _check_member(member_id: int) -> None:
    if not MEMBER_ID_MIN <= member_id <= MEMBER_ID_MAX:
        raise ValueError(f"member_id must be {MEMBER_ID_MIN} to {MEMBER_ID_MAX}")


def build_add_pin(member_id: int, pin: str, *, admin: bool = False) -> bytes:
    """Build the DP 1 ``unlock_method_create`` payload for a permanent PIN.

    ``[type][stage][admin][member][hw id][validity:17][times][len][digits]``;
    the lock assigns the hardware id (slot) and reports it back on DP 1.
    """
    _check_member(member_id)
    digits = validate_pin(pin)
    return (
        bytes([
            CRED_TYPE_PASSWORD,
            STAGE_START,
            0x01 if admin else 0x00,
            member_id,
            HARDWARE_ID_AUTO,
        ])
        + _validity_permanent()
        + bytes([0x00, len(digits)])  # times: 0 = unlimited
        + digits
    )


def build_delete_pin(member_id: int, hardware_id: int) -> bytes:
    """Build the DP 2 ``unlock_method_delete`` payload for one PIN slot.

    ``[type: specified method][stage][admin][member][hw id][method: password]``
    per Tuya's reference. frankhommers reads the first byte as the credential
    type and the last as "single"; for a password both readings give 0x01 in
    both places, which is why only PIN deletion is offered.
    """
    _check_member(member_id)
    if not 0 <= hardware_id <= HARDWARE_ID_MAX:
        raise ValueError(f"hardware_id must be 0 to {HARDWARE_ID_MAX}")
    return bytes([
        DELETE_SPECIFIED_METHOD,
        STAGE_START,
        0x00,
        member_id,
        hardware_id,
        CRED_TYPE_PASSWORD,
    ])


def parse_enroll_report(raw: bytes) -> EnrollResult | None:
    """Parse a DP 1 report: ``[type][stage][admin][member][hw id][times][result]``."""
    if len(raw) < 7:
        return None
    return EnrollResult(
        cred_type=raw[0],
        stage=raw[1],
        admin=bool(raw[2]),
        member_id=raw[3],
        hardware_id=raw[4],
        result_code=raw[6],
    )


def parse_delete_report(raw: bytes) -> DeleteResult | None:
    """Parse a DP 2 report: the command's six bytes followed by the result."""
    if len(raw) < 7:
        return None
    return DeleteResult(
        member_id=raw[3], hardware_id=raw[4], method=raw[5], result_code=raw[6]
    )


def build_unlock_check(check_code: str, *, unlock: bool, timestamp: int) -> bytes:
    """Build the 19-byte DP 71 ``ble_unlock_check`` lock/unlock command.

    ``[member 0xFFFF][version 0x0001][check code:8][action][timestamp:4][00 01]``.
    """
    code = check_code.encode("ascii")
    if len(code) != CHECK_CODE_LENGTH:
        raise ValueError("check code must be 8 ASCII characters")
    return (
        struct.pack(">HH", UNLOCK_CHECK_ADMIN_MEMBER, UNLOCK_CHECK_VERSION)
        + code
        + bytes([0x01 if unlock else 0x00])
        + struct.pack(">I", timestamp)
        + UNLOCK_CHECK_TRAILER
    )


@dataclass(frozen=True)
class UnlockCheckReport:
    """A lock's DP 71 report answering a lock/unlock command."""

    unlock: bool
    timestamp: int
    result_code: int

    @property
    def succeeded(self) -> bool:
        """Return whether the lock carried out the command."""
        return self.result_code == UNLOCK_CHECK_RESULT_SUCCESS


def parse_unlock_check_report(raw: bytes) -> UnlockCheckReport | None:
    """Parse a DP 71 report.

    ``[peripheral id:2][central id:2][check code:8][action][timestamp:4]``
    ``[method][result]``, the command's fields echoed with the result last.
    """
    if len(raw) < UNLOCK_CHECK_LENGTH:
        return None
    (timestamp,) = struct.unpack_from(">I", raw, 13)
    return UnlockCheckReport(
        unlock=raw[12] == 0x01, timestamp=timestamp, result_code=raw[18]
    )
