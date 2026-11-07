"""Tests for the lock check code, the DP 71 lock handler and credential redaction."""
# pylint: disable=protected-access

from __future__ import annotations

import asyncio
import base64
import logging
from struct import pack
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock, patch

from bleak.exc import BleakDBusError, BleakError
from homeassistant.components.lock import LockEntityDescription
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from homeassistant.exceptions import HomeAssistantError
import pytest

import custom_components.tuya_ble as integration
from custom_components.tuya_ble import cloud, diagnostics, dp_command, lock
from custom_components.tuya_ble.const import CONF_CHECK_CODE, DOMAIN
from custom_components.tuya_ble.coordinator import TuyaBLECoordinator
from custom_components.tuya_ble.device_descriptors.handlers import ble_lock
from custom_components.tuya_ble.device_registry import get_registry
from custom_components.tuya_ble.lock_commands import build_unlock_check
from custom_components.tuya_ble.tuya_ble import (
    TuyaBLEDataPointType,
    TuyaBLEDevice,
    TuyaBLEDeviceCredentials,
    protocol_send,
)
from custom_components.tuya_ble.tuya_ble.const import REDACTED, TuyaBLECode
from custom_components.tuya_ble.tuya_ble.datapoints import TuyaBLEDataPoints
from tests.conftest import (
    FakeBLEManager,
    FakeDatapointsOwner,
    build_context,
    make_device,
)
from tests.test_cloud import make_device as make_cloud_device
from tests.test_config_flow import (
    FakeManager,
    build_flow,
    captured_irrigation_discovery,
)

_CODE = "Ab3dE6g8"
_FUNCTIONS = [
    {"code": "unlock_method_create", "dp_id": 1, "type": "Raw"},
    {"code": "ble_unlock_check", "dp_id": 71, "type": "Raw"},
]
_STATUS = [
    {"code": "lock_motor_state", "dp_id": 47, "type": "Boolean"},
    {"code": "unlock_method_create", "dp_id": 1, "type": "Raw"},
    {"code": "temporary_password_creat", "dp_id": 51, "type": "Raw"},
]


def _credentials(**overrides: Any) -> TuyaBLEDeviceCredentials:
    values: dict[str, Any] = {
        "uuid": "1234567890abcdef",
        "local_key": "abcdef",
        "device_id": "device123",
        "category": "jtmspro",
        "product_id": "6hqka6he",
        "device_name": "Lock",
        "product_model": None,
        "product_name": "Smart Lock",
        "functions": _FUNCTIONS,
        "status_range": _STATUS,
        "check_code": _CODE,
    }
    values.update(overrides)
    return TuyaBLEDeviceCredentials(**values)


def _lock_device(**overrides: Any) -> TuyaBLEDevice:
    credentials = _credentials(**overrides)
    device = make_device(FakeBLEManager(credentials))
    device.initialize_with_credentials(credentials)
    return device


def _status_value(code: bytes) -> str:
    return base64.b64encode(
        b"\x00\x01\xff\xff" + code + b"\x01\x00\x00\x00\x00"
    ).decode()


# --- check code from the cloud ---


def test_extract_check_code_reads_the_status_snapshot() -> None:
    """The 8 characters after the two 2-byte ids are the check code."""
    device = SimpleNamespace(status={"ble_unlock_check": _status_value(b"Ab3dE6g8")})

    assert cloud.extract_check_code(cast(Any, device)) == _CODE


@pytest.mark.parametrize(
    "status",
    [
        None,
        {},
        {"ble_unlock_check": 5},
        {"ble_unlock_check": ""},
        {"ble_unlock_check": "not base64!"},
        {"ble_unlock_check": base64.b64encode(b"\x00\x01\xff\xffAb3d").decode()},
        {"ble_unlock_check": _status_value(b"Ab3d\x00\x00\x00\x00")},
    ],
)
def test_extract_check_code_ignores_unusable_values(status: Any) -> None:
    """Missing, non-string, malformed, short or non-printable values give None."""
    assert cloud.extract_check_code(cast(Any, SimpleNamespace(status=status))) is None


def test_extract_check_code_without_a_status_attribute() -> None:
    """A cloud device without a status snapshot has no check code."""
    assert cloud.extract_check_code(cast(Any, SimpleNamespace())) is None


def test_built_credentials_carry_the_check_code() -> None:
    """The cloud credentials pass the check code on to the config entry."""
    device = make_cloud_device(status={"ble_unlock_check": _status_value(b"Ab3dE6g8")})

    assert cloud._build_credentials(device).check_code == _CODE


def test_credentials_from_the_entry_restore_the_check_code() -> None:
    """A stored check code reaches the device credentials on setup."""
    entry = MagicMock()
    entry.data = {
        "uuid": "u",
        "local_key": "abcdef",
        "device_id": "d",
        "category": "jtmspro",
        "product_id": "6hqka6he",
        CONF_CHECK_CODE: _CODE,
    }

    assert integration._build_credentials_from_entry(entry).check_code == _CODE


def test_credentials_str_never_shows_the_check_code() -> None:
    """The credentials' string form, used in logs, omits the check code."""
    assert _CODE not in str(_credentials())


async def test_async_setup_registers_the_pin_services(hass: HomeAssistant) -> None:
    """The integration-wide setup registers both PIN actions."""
    assert await integration.async_setup(hass, {})

    assert hass.services.has_service(DOMAIN, "add_pin")
    assert hass.services.has_service(DOMAIN, "delete_pin")


# --- device properties ---


def test_device_check_code_and_sensitive_ids() -> None:
    """Credential DPs are found by Tuya code in both function tables."""
    device = _lock_device()

    assert device.check_code == _CODE
    assert device.sensitive_dp_ids == frozenset({1, 51, 71})


def test_device_without_credentials_has_no_check_code() -> None:
    """Before credentials are loaded there is no check code."""
    device = make_device()

    assert device.check_code is None
    assert device.sensitive_dp_ids == frozenset()


# --- redaction ---


def test_datapoints_without_a_device_owner_are_not_sensitive(
    datapoints_owner: FakeDatapointsOwner,
) -> None:
    """An owner with no sensitive ids redacts nothing."""
    points = TuyaBLEDataPoints(cast(TuyaBLEDevice, datapoints_owner))
    datapoint = points.get_or_create(1, TuyaBLEDataPointType.DT_RAW, b"\x01")

    assert points.is_sensitive(1) is False
    assert datapoint.loggable(b"\x01") == b"\x01"


def test_credential_datapoint_values_are_redacted_in_logs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Device reports and local writes of a credential DP log no value."""
    device = _lock_device()
    caplog.set_level(logging.DEBUG)

    device.datapoints.update_from_device(
        71, 0.0, 0, TuyaBLEDataPointType.DT_RAW, b"first-secret"
    )
    datapoint = device.datapoints.update_from_device(
        71, 0.0, 0, TuyaBLEDataPointType.DT_RAW, b"secret-code-71"
    )
    datapoint.set_value_no_notify(b"another-secret")
    for value in (False, True):
        device.datapoints.update_from_device(
            47, 0.0, 0, TuyaBLEDataPointType.DT_BOOL, value
        )

    assert "first-secret" not in caplog.text
    assert "secret-code-71" not in caplog.text
    assert "another-secret" not in caplog.text
    assert REDACTED in caplog.text
    assert "changed by device: False -> True" in caplog.text


def test_received_credential_datapoints_are_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The protocol layer's receive log hides credential DP bytes only."""
    device = _lock_device()
    secret = b"\x00\x01\xff\xff" + _CODE.encode()
    payload = pack(">BBB", 71, TuyaBLEDataPointType.DT_RAW.value, len(secret))
    payload += (
        secret + pack(">BBB", 47, TuyaBLEDataPointType.DT_BOOL.value, 1) + b"\x01"
    )
    caplog.set_level(logging.DEBUG)

    device._parse_datapoints_v3(0.0, 0, payload, 0)

    assert secret.hex() not in caplog.text
    assert _CODE not in caplog.text
    assert f"Received DP id=71 type=DT_RAW flags=0x00 raw={REDACTED}" in caplog.text
    assert (
        "Received DP id=47 type=DT_BOOL flags=0x00 raw=01 decoded=True" in caplog.text
    )


async def test_sent_credential_datapoints_are_redacted(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The send log hides a PIN or check code being written."""
    device = _lock_device()
    device._protocol_version = 3
    datapoint = device.datapoints.get_or_create(1, TuyaBLEDataPointType.DT_RAW, b"")
    datapoint.set_value_no_notify(b"\x01\x02\x03\x04")
    caplog.set_level(logging.DEBUG)

    with patch.object(device, "_send_packet", AsyncMock()) as send_packet:
        await device.send_datapoints([1])

    send_packet.assert_awaited_once()
    assert send_packet.await_args is not None
    assert send_packet.await_args.args[0] == TuyaBLECode.FUN_SENDER_DPS
    assert "value: **REDACTED**" in caplog.text
    assert "\\x01\\x02\\x03\\x04" not in caplog.text


@pytest.mark.parametrize(
    ("product_id", "level"), [("6hqka6he", "DEBUG"), ("unknownpid", "WARNING")]
)
async def test_unmapped_credential_datapoints_are_redacted(
    hass: HomeAssistant,
    caplog: pytest.LogCaptureFixture,
    product_id: str,
    level: str,
) -> None:
    """Both unmapped-DP log lines hide credential DP bytes."""
    device = _lock_device(product_id=product_id)
    coordinator = TuyaBLECoordinator(hass, device)
    datapoint = device.datapoints.update_from_device(
        71, 0.0, 0, TuyaBLEDataPointType.DT_RAW, b"secret", b"secret"
    )
    caplog.set_level(logging.DEBUG)

    coordinator._log_unmapped_dp([datapoint])

    records = [r for r in caplog.records if "Unmapped DP id=71" in r.getMessage()]
    assert [r.levelname for r in records] == [level]
    assert b"secret".hex() not in caplog.text
    assert f"raw={REDACTED} decoded={REDACTED}" in records[0].getMessage()


def test_diagnostics_redact_credential_datapoints() -> None:
    """The live section keeps the type but drops a credential DP's bytes."""
    device = _lock_device()
    device.datapoints.update_from_device(
        71, 0.0, 0, TuyaBLEDataPointType.DT_RAW, b"secret", b"secret"
    )
    device.datapoints.update_from_device(47, 0.0, 0, TuyaBLEDataPointType.DT_BOOL, True)

    live = diagnostics._live_section(device)

    assert live["71"] == {
        "type": "DT_RAW",
        "value": REDACTED,
        "raw": REDACTED,
        "changed_by_device": False,
    }
    assert live["47"]["value"] is True


def test_check_code_is_redacted_from_entry_data() -> None:
    """The stored check code is in the diagnostics redaction set."""
    assert CONF_CHECK_CODE in diagnostics._TO_REDACT


# --- lock entity write handler ---


def _lock_entity(
    hass: HomeAssistant, setter: Any = None
) -> tuple[lock.TuyaBLELock, TuyaBLEDevice]:
    device, coordinator, product = build_context(hass)
    mapping = lock.TuyaBLELockMapping(
        dp_id=47, description=LockEntityDescription(key="lock"), setter=setter
    )
    entity = lock.TuyaBLELock(hass, coordinator, device, product, mapping)
    entity.hass = hass
    return entity, device


@pytest.mark.parametrize(
    ("method", "value"), [("async_lock", False), ("async_unlock", True)]
)
async def test_lock_with_a_write_handler_delegates_to_it(
    hass: HomeAssistant, method: str, value: bool
) -> None:
    """A write handler replaces the boolean write on the state DP."""
    setter = AsyncMock()
    entity, device = _lock_entity(hass, setter)

    await getattr(entity, method)()

    setter.assert_awaited_once_with(entity, entity._product, value)
    assert device.datapoints[47] is None


def test_descriptor_wires_the_dp71_handlers() -> None:
    """The 6hqka6he lock entity resolves the ble_lock write and when handlers."""
    descriptors = get_registry().get_entities("jtmspro", "6hqka6he", "lock")
    mapping = lock._build_lock_mapping(descriptors[0])

    assert mapping.dp_id == 47
    assert mapping.setter is ble_lock.send_unlock_check
    assert mapping.is_available is ble_lock.has_check_code


# --- DP 71 handler ---

_NOW = 1_700_000_000


def _handler_entity(device: TuyaBLEDevice) -> Any:
    return SimpleNamespace(device=device)


def _unlock_report(unlock: bool, timestamp: int = _NOW, result: int = 0) -> bytes:
    return (
        b"\x00\x01\xff\xff"
        + _CODE.encode()
        + bytes([0x01 if unlock else 0x00])
        + pack(">I", timestamp)
        + bytes([0x00, result])
    )


def _replying_send(
    device: TuyaBLEDevice, sent: list[bytes], reports: list[bytes]
) -> Any:
    async def _send(ids: list[int]) -> None:
        datapoint = device.datapoints[ids[0]]
        assert datapoint is not None
        sent.append(cast(bytes, datapoint.value))
        for raw in reports:
            reported = device.datapoints.update_from_device(
                ids[0], 0.0, 0, TuyaBLEDataPointType.DT_RAW, raw, raw
            )
            device._fire_callbacks([reported])

    return _send


def test_has_check_code_needs_a_code_and_the_function() -> None:
    """The lock is only available with a check code and a ble_unlock_check DP."""
    product = MagicMock()

    assert ble_lock.has_check_code(_handler_entity(_lock_device()), product) is True
    variants: list[dict[str, Any]] = [{"check_code": None}, {"functions": []}]
    for overrides in variants:
        device = _lock_device(**overrides)
        assert ble_lock.has_check_code(_handler_entity(device), product) is False


@pytest.mark.parametrize(
    ("functions", "dp_id"),
    [
        (_FUNCTIONS, 71),
        ([{"code": "ble_unlock_check", "dp_id": 75, "type": "Raw"}], 75),
    ],
)
@pytest.mark.parametrize("unlock", [True, False])
async def test_send_unlock_check_writes_the_frame(
    functions: list[dict[str, Any]], dp_id: int, unlock: bool
) -> None:
    """The frame goes to the ble_unlock_check DP; stale reports are skipped."""
    device = _lock_device(functions=functions)
    sent: list[bytes] = []
    reports = [
        b"\x00",  # too short
        _unlock_report(not unlock),  # the other action
        _unlock_report(unlock, timestamp=_NOW - 60),  # an earlier command
        _unlock_report(unlock),
    ]

    with (
        patch.object(device, "send_datapoints", _replying_send(device, sent, reports)),
        patch("time.time", return_value=_NOW),
    ):
        await ble_lock.send_unlock_check(_handler_entity(device), MagicMock(), unlock)

    assert sent == [build_unlock_check(_CODE, unlock=unlock, timestamp=_NOW)]
    assert dp_id in device.sensitive_dp_ids


async def test_send_unlock_check_reports_a_rejection() -> None:
    """A non-zero result in the lock's DP 71 report fails the command."""
    device = _lock_device()
    send = _replying_send(device, [], [_unlock_report(True, result=0x04)])

    with (
        patch.object(device, "send_datapoints", send),
        patch("time.time", return_value=_NOW),
        pytest.raises(HomeAssistantError, match="rejected the unlock command"),
    ):
        await ble_lock.send_unlock_check(_handler_entity(device), MagicMock(), True)


async def test_send_unlock_check_accepts_a_silent_lock(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """A lock that does not report on DP 71 is not treated as a failure."""
    device = _lock_device()
    monkeypatch.setattr(ble_lock, "REPLY_TIMEOUT", 0.01)
    caplog.set_level(logging.DEBUG)

    with patch.object(device, "send_datapoints", _replying_send(device, [], [])):
        await ble_lock.send_unlock_check(_handler_entity(device), MagicMock(), False)

    assert "no DP 71 report for the command" in caplog.text
    assert _CODE not in caplog.text


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"check_code": None}, "no check code"),
        ({"check_code": "short"}, "malformed"),
        ({"functions": []}, "does not list ble_unlock_check"),
    ],
)
async def test_send_unlock_check_refuses_without_a_valid_code(
    overrides: dict[str, Any], message: str
) -> None:
    """No frame is sent without a usable check code and a listed DP."""
    device = _lock_device(**overrides)
    send = AsyncMock()

    with (
        patch.object(device, "send_datapoints", send),
        pytest.raises(HomeAssistantError, match=message),
    ):
        await ble_lock.send_unlock_check(_handler_entity(device), MagicMock(), True)
    send.assert_not_awaited()


# --- raw credential writes ---


async def test_send_raw_refuses_a_non_raw_datapoint() -> None:
    """A DP the device reported with another type never gets a credential frame."""
    device = _lock_device()
    device.datapoints.update_from_device(71, 0.0, 0, TuyaBLEDataPointType.DT_VALUE, 5)
    send = AsyncMock()

    with (
        patch.object(device, "send_datapoints", send),
        pytest.raises(HomeAssistantError, match="DT_VALUE, not raw") as err,
    ):
        await dp_command.async_send_raw(device, 71, b"secret-frame")

    send.assert_not_awaited()
    assert "secret-frame" not in str(err.value)


async def test_send_raw_without_a_matcher_returns_after_the_ack() -> None:
    """With nothing to wait for, the call ends once the write is acknowledged."""
    device = _lock_device()
    send = AsyncMock()

    with patch.object(device, "send_datapoints", send):
        await dp_command.async_send_raw(device, 1, b"\x01")

    send.assert_awaited_once_with([1])


async def test_send_raw_bounds_the_whole_send(monkeypatch: pytest.MonkeyPatch) -> None:
    """A send stuck in connection retries is cancelled and rolled back."""
    device = _lock_device()
    monkeypatch.setattr(dp_command, "COMMAND_SEND_TIMEOUT", 0.01)

    async def _stuck(_ids: list[int]) -> None:
        await asyncio.sleep(10)

    with (
        patch.object(device, "send_datapoints", _stuck),
        pytest.raises(HomeAssistantError, match="could not be reached"),
    ):
        await dp_command.async_send_raw(device, 1, b"\x01")

    datapoint = device.datapoints[1]
    assert datapoint is not None
    assert datapoint.value == b""


@pytest.mark.parametrize(("dp_id", "expected"), [(1, True), (47, False)])
async def test_credential_writes_suppress_the_background_resend(
    dp_id: int, expected: bool
) -> None:
    """Only a write that carries a credential DP is marked as never-resend."""
    device = _lock_device()
    device._protocol_version = 3
    device.datapoints.get_or_create(dp_id, TuyaBLEDataPointType.DT_RAW, b"\x01")
    seen: list[bool] = []

    async def _send_packet(*_args: Any, **_kwargs: Any) -> None:
        seen.append(protocol_send._NO_RESEND.get())

    with patch.object(device, "_send_packet", _send_packet):
        await device.send_datapoints([dp_id])

    assert seen == [expected]
    assert protocol_send._NO_RESEND.get() is False


@pytest.mark.parametrize("no_resend", [True, False])
@pytest.mark.parametrize("dbus", [True, False])
async def test_failed_credential_packets_are_not_resent(
    no_resend: bool, dbus: bool
) -> None:
    """A failed credential write reconnects instead of replaying its packets."""
    device = _lock_device()
    device._is_paired = True
    failure: Exception = (
        BleakDBusError("org.bluez.Error.Failed", []) if dbus else BleakError()
    )
    token = protocol_send._NO_RESEND.set(no_resend)
    try:
        with (
            patch.object(
                device, "_int_send_packets_locked", AsyncMock(side_effect=failure)
            ),
            patch.object(device, "_schedule_resend") as resend,
            patch.object(device, "_schedule_reconnect") as reconnect,
            patch.object(protocol_send, "BLEAK_BACKOFF_TIME", 0),
            pytest.raises(BleakError),
        ):
            await device._send_packets_locked([b"packet"])
    finally:
        protocol_send._NO_RESEND.reset(token)

    assert resend.called is not no_resend
    assert reconnect.called is no_resend


async def test_config_flow_stores_the_check_code(hass: HomeAssistant) -> None:
    """A check code from the cloud is kept in the new entry's data."""
    flow = build_flow(hass)
    flow.context = {}
    discovery = captured_irrigation_discovery()
    flow.discovery_info = discovery  # type: ignore[assignment]
    manager = FakeManager(credentials=_credentials(uuid="0237f144b99142e6"))
    with (
        patch(
            "custom_components.tuya_ble.config_flow.HASSTuyaBLEDeviceManager",
            return_value=manager,
        ),
        patch.object(flow, "_async_scan_device", return_value=discovery),
    ):
        result = await flow.async_step_scan({})

    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert cast(dict[str, Any], result["data"])[CONF_CHECK_CODE] == _CODE
