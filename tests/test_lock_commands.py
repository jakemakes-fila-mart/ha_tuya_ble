"""Tests for the lock PIN and DP 71 payload builders and parsers."""

from __future__ import annotations

import pytest

from custom_components.tuya_ble import lock_commands
from custom_components.tuya_ble.lock_commands import (
    DeleteResult,
    EnrollResult,
    build_add_pin,
    build_delete_pin,
    build_unlock_check,
    parse_delete_report,
    parse_enroll_report,
    parse_unlock_check_result,
    validate_pin,
)

_VALIDITY = bytes.fromhex("386d43807fe8177f00000000000000173b")


def test_validity_block_is_permanent_and_17_bytes() -> None:
    """The validity block spans 2000-01-01 to 2037-12-31, all day, no recurrence."""
    block = lock_commands._validity_permanent()  # pylint: disable=protected-access

    assert len(block) == 17
    assert block == _VALIDITY


def test_build_add_pin_matches_the_dp1_layout() -> None:
    """type, stage, admin, member, auto hw id, validity, times, length, digits."""
    payload = build_add_pin(3, "1290")

    assert payload == bytes([0x01, 0x00, 0x00, 0x03, 0xFF]) + _VALIDITY + bytes([
        0x00,
        0x04,
        1,
        2,
        9,
        0,
    ])


def test_build_add_pin_sets_the_admin_flag() -> None:
    """The third byte carries the admin flag."""
    assert build_add_pin(1, "123456", admin=True)[2] == 0x01


@pytest.mark.parametrize("pin", ["123", "12345678901", "12a456", "", " 1234", "١٢٣٤"])
def test_validate_pin_rejects_bad_pins_without_echoing_them(pin: str) -> None:
    """Only 4 to 10 ASCII digits pass, and the error never contains the PIN."""
    with pytest.raises(ValueError, match="PIN must") as err:
        validate_pin(pin)
    if pin.strip():
        assert pin not in str(err.value)


def test_validate_pin_returns_one_byte_per_digit() -> None:
    """Digits are sent as their values 0-9, not as ASCII."""
    assert validate_pin("0987654321") == bytes([0, 9, 8, 7, 6, 5, 4, 3, 2, 1])


@pytest.mark.parametrize("member", [0, 101])
def test_member_id_is_bounded(member: int) -> None:
    """Member ids outside 1 to 100 are rejected for both commands."""
    with pytest.raises(ValueError, match="member_id"):
        build_add_pin(member, "1234")
    with pytest.raises(ValueError, match="member_id"):
        build_delete_pin(member, 0)


def test_build_delete_pin_matches_the_dp2_layout() -> None:
    """specified method, stage, admin, member, hw id, method password."""
    assert build_delete_pin(2, 7) == bytes([0x01, 0x00, 0x00, 0x02, 0x07, 0x01])


@pytest.mark.parametrize("hardware_id", [-1, 255])
def test_build_delete_pin_bounds_the_hardware_id(hardware_id: int) -> None:
    """0xFF is the auto-assign marker, never a real slot."""
    with pytest.raises(ValueError, match="hardware_id"):
        build_delete_pin(1, hardware_id)


def test_parse_enroll_report() -> None:
    """A finished password enrollment reports its member and slot."""
    report = parse_enroll_report(bytes([0x01, 0xFF, 0x00, 0x03, 0x05, 0x01, 0x00]))

    assert report == EnrollResult(
        cred_type=0x01,
        stage=0xFF,
        admin=False,
        member_id=3,
        hardware_id=5,
        result_code=0,
    )
    assert report.is_final
    assert report.succeeded


@pytest.mark.parametrize(
    ("stage", "result", "final", "ok"),
    [
        (0x00, 0x00, False, False),
        (0xFC, 0x00, False, False),
        (0xFD, 0x01, True, False),
        (0xFE, 0x00, True, False),
        (0xFF, 0x03, True, False),
    ],
)
def test_enroll_report_stages(stage: int, result: int, final: bool, ok: bool) -> None:
    """Only a done stage with result 0 is a success; three stages are final."""
    report = parse_enroll_report(bytes([0x01, stage, 0, 1, 2, 0, result]))

    assert report is not None
    assert report.is_final is final
    assert report.succeeded is ok


def test_parse_enroll_report_rejects_short_frames() -> None:
    """A frame shorter than seven bytes is not an enrollment report."""
    assert parse_enroll_report(b"\x01\xff\x00\x01\x02\x00") is None


@pytest.mark.parametrize(("result", "ok"), [(0xFF, True), (0x00, False), (0x01, False)])
def test_parse_delete_report(result: int, ok: bool) -> None:
    """The seventh byte is the result; 0xFF means deleted."""
    report = parse_delete_report(bytes([0x01, 0x00, 0x00, 0x02, 0x07, 0x01, result]))

    assert report == DeleteResult(member_id=2, hardware_id=7, result_code=result)
    assert report.succeeded is ok


def test_parse_delete_report_rejects_short_frames() -> None:
    """A frame shorter than seven bytes is not a deletion report."""
    assert parse_delete_report(b"\x01\x00\x00\x02\x07\x01") is None


@pytest.mark.parametrize(("unlock", "action"), [(True, 0x01), (False, 0x00)])
def test_build_unlock_check(unlock: bool, action: int) -> None:
    """member 0xFFFF, version 1, check code, action, timestamp, trailer 00 01."""
    payload = build_unlock_check("A1b2C3d4", unlock=unlock, timestamp=0x01020304)

    assert payload == (
        b"\xff\xff\x00\x01" + b"A1b2C3d4" + bytes([action]) + b"\x01\x02\x03\x04"
        b"\x00\x01"
    )
    assert len(payload) == lock_commands.UNLOCK_CHECK_LENGTH


@pytest.mark.parametrize("code", ["1234567", "123456789", ""])
def test_build_unlock_check_needs_an_8_character_code(code: str) -> None:
    """The lock compares exactly eight characters."""
    with pytest.raises(ValueError, match="check code"):
        build_unlock_check(code, unlock=True, timestamp=0)


def test_build_unlock_check_rejects_non_ascii_codes() -> None:
    """A non-ASCII code cannot be encoded into the frame."""
    with pytest.raises(ValueError):
        build_unlock_check("1234567é", unlock=True, timestamp=0)


def test_parse_unlock_check_result() -> None:
    """The result byte follows the 18-byte echo of the command."""
    assert parse_unlock_check_result(bytes(18) + b"\x00") == 0
    assert parse_unlock_check_result(bytes(18) + b"\x04") == 4
    assert parse_unlock_check_result(bytes(18)) is None
