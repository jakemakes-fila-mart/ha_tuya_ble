"""Tests for the tuya_ble.add_pin and tuya_ble.delete_pin services."""
# pylint: disable=protected-access

from __future__ import annotations

import logging
from typing import Any, cast
from unittest.mock import MagicMock

from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import device_registry as dr
import probatio
import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.tuya_ble import services
from custom_components.tuya_ble.const import DOMAIN
from custom_components.tuya_ble.devices import TuyaBLEData
from custom_components.tuya_ble.lock_commands import build_add_pin, build_delete_pin
from custom_components.tuya_ble.tuya_ble import TuyaBLEDataPointType
from custom_components.tuya_ble.tuya_ble.exceptions import TuyaBLEDeviceError
from tests.conftest import EntityDevice, FakeAdvertisementData, FakeBLEAddress

_PIN = "864209"
_FUNCTIONS = [
    {"code": "unlock_method_create", "dp_id": 1, "type": "Raw"},
    {"code": "unlock_method_delete", "dp_id": 2, "type": "Raw"},
]

Reply = tuple[int, TuyaBLEDataPointType, bytes | bool]


class ReplyingDevice(EntityDevice):
    """Device double that answers a write with scripted data point reports."""

    def __init__(self) -> None:
        """Start with no scripted replies and no recorded payloads."""
        super().__init__(
            None,
            cast(BLEDevice, FakeBLEAddress("AA:BB:CC:DD:EE:01")),
            cast(
                AdvertisementData,
                FakeAdvertisementData(rssi=-50, service_data={}, manufacturer_data={}),
            ),
        )
        self.replies: list[Reply] = []
        self.payloads: list[Any] = []
        self.fail: Exception | None = None

    async def send_datapoints(self, datapoint_ids: list[int]) -> None:
        """Record the payload, then push every scripted report to the callbacks."""
        if self.fail is not None:
            raise self.fail
        await super().send_datapoints(datapoint_ids)
        for dp_id in datapoint_ids:
            datapoint = self.datapoints[dp_id]
            assert datapoint is not None
            self.payloads.append(datapoint.value)
        replies, self.replies = self.replies, []
        for dp_id, dp_type, value in replies:
            raw = value if isinstance(value, bytes) else None
            reported = self.datapoints.update_from_device(
                dp_id, 0.0, 0, dp_type, value, raw
            )
            self._fire_callbacks([reported])


def _raw(dp_id: int, data: list[int]) -> Reply:
    return (dp_id, TuyaBLEDataPointType.DT_RAW, bytes(data))


@pytest.fixture(name="lock_device")
def fixture_lock_device(hass: HomeAssistant) -> tuple[ReplyingDevice, str]:
    """Register a loaded lock device and the services; return it and its id."""
    entry = MockConfigEntry(domain=DOMAIN, data={}, entry_id="lock_entry")
    entry.add_to_hass(hass)
    registry_device = dr.async_get(hass).async_get_or_create(
        config_entry_id=entry.entry_id, identifiers={(DOMAIN, "lock")}
    )
    device = ReplyingDevice()
    device.append_functions(_FUNCTIONS, None)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = TuyaBLEData(
        "Lock", device, MagicMock(), MagicMock(), MagicMock()
    )
    services.async_setup_services(hass)
    return device, registry_device.id


async def _add_pin(hass: HomeAssistant, device_id: str, **extra: Any) -> Any:
    return await hass.services.async_call(
        DOMAIN,
        services.SERVICE_ADD_PIN,
        {"device_id": device_id, "pin": _PIN, **extra},
        blocking=True,
        return_response=True,
    )


async def _delete_pin(hass: HomeAssistant, device_id: str, **extra: Any) -> None:
    await hass.services.async_call(
        DOMAIN,
        services.SERVICE_DELETE_PIN,
        {"device_id": device_id, "hardware_id": 7, **extra},
        blocking=True,
    )


async def test_add_pin_returns_the_assigned_slot(
    hass: HomeAssistant,
    lock_device: tuple[ReplyingDevice, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Non-matching reports are skipped; the final one for the member wins."""
    device, device_id = lock_device
    device.replies = [
        (1, TuyaBLEDataPointType.DT_BOOL, True),  # not a raw frame
        _raw(9, [0x01, 0xFF, 1, 2, 5, 0, 0]),  # another data point
        _raw(1, [0x01, 0xFF]),  # too short to be a report
        _raw(1, [0x03, 0xFF, 1, 2, 5, 0, 0]),  # a fingerprint, not a PIN
        _raw(1, [0x01, 0xFF, 1, 9, 5, 0, 0]),  # another member
        _raw(1, [0x01, 0xFF, 0, 2, 5, 0, 0]),  # not an admin PIN
        _raw(1, [0x01, 0xFC, 1, 2, 5, 0, 0]),  # still in progress
        _raw(1, [0x01, 0xFF, 1, 2, 5, 1, 0]),  # done: slot 5
        _raw(1, [0x01, 0xFF, 1, 2, 6, 1, 0]),  # late duplicate is ignored
    ]

    with caplog.at_level(logging.DEBUG):
        response = await _add_pin(hass, device_id, member_id=2, admin=True)

    assert response == {"member_id": 2, "hardware_id": 5}
    assert device.payloads == [build_add_pin(2, _PIN, admin=True)]
    assert _PIN not in caplog.text
    assert "PIN added for member 2 in slot 5" in caplog.text


async def test_add_pin_reports_a_refusal(
    hass: HomeAssistant, lock_device: tuple[ReplyingDevice, str]
) -> None:
    """A failed final stage becomes an error naming the stage and result."""
    device, device_id = lock_device
    device.replies = [_raw(1, [0x01, 0xFD, 0, 1, 0xFF, 0, 0x03])]

    with pytest.raises(HomeAssistantError, match="stage 0xfd, result 0x03"):
        await _add_pin(hass, device_id)


async def test_add_pin_times_out_without_a_report(
    hass: HomeAssistant,
    lock_device: tuple[ReplyingDevice, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A lock that never answers fails the call instead of hanging."""
    _, device_id = lock_device
    monkeypatch.setattr(services, "RESPONSE_TIMEOUT", 0.01)

    with pytest.raises(HomeAssistantError, match="did not answer"):
        await _add_pin(hass, device_id)


async def test_add_pin_rejects_a_bad_pin_without_echoing_it(
    hass: HomeAssistant, lock_device: tuple[ReplyingDevice, str]
) -> None:
    """Validation names the rule, never the PIN, and nothing is sent."""
    device, device_id = lock_device

    with pytest.raises(ServiceValidationError) as err:
        await _add_pin(hass, device_id, pin="12x4")

    assert "12x4" not in str(err.value)
    assert device.payloads == []


async def test_send_failure_becomes_a_service_error(
    hass: HomeAssistant, lock_device: tuple[ReplyingDevice, str]
) -> None:
    """A BLE failure while sending is reported as a Home Assistant error."""
    device, device_id = lock_device
    device.fail = TuyaBLEDeviceError(0)

    with pytest.raises(HomeAssistantError, match="Could not send"):
        await _add_pin(hass, device_id)


async def test_unknown_device_is_rejected(
    hass: HomeAssistant, lock_device: tuple[ReplyingDevice, str]
) -> None:
    """A device id that is not in the registry is a validation error."""
    with pytest.raises(ServiceValidationError, match="Unknown device"):
        await _add_pin(hass, "no-such-device")


async def test_device_of_an_unloaded_entry_is_rejected(
    hass: HomeAssistant, lock_device: tuple[ReplyingDevice, str]
) -> None:
    """A registry device whose entry is not loaded cannot be commanded."""
    other = MockConfigEntry(domain=DOMAIN, data={}, entry_id="other_entry")
    other.add_to_hass(hass)
    registry_device = dr.async_get(hass).async_get_or_create(
        config_entry_id=other.entry_id, identifiers={(DOMAIN, "other")}
    )

    with pytest.raises(ServiceValidationError, match="not a loaded"):
        await _add_pin(hass, registry_device.id)


async def test_device_without_the_data_point_is_rejected(
    hass: HomeAssistant, lock_device: tuple[ReplyingDevice, str]
) -> None:
    """A device that does not report unlock_method_create gets no command."""
    device, device_id = lock_device
    device._function.clear()

    with pytest.raises(ServiceValidationError, match="unlock_method_create"):
        await _add_pin(hass, device_id)
    assert device.payloads == []


async def test_delete_pin_succeeds(
    hass: HomeAssistant,
    lock_device: tuple[ReplyingDevice, str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Reports for other members or slots are skipped; 0xFF means deleted."""
    device, device_id = lock_device
    device.replies = [
        _raw(2, [0x01, 0x00]),  # too short
        _raw(2, [0x01, 0x00, 0x00, 0x09, 0x07, 0x01, 0xFF]),  # another member
        _raw(2, [0x01, 0x00, 0x00, 0x03, 0x08, 0x01, 0xFF]),  # another slot
        _raw(2, [0x03, 0x00, 0x00, 0x03, 0x07, 0x03, 0xFF]),  # a fingerprint
        _raw(2, [0x01, 0x00, 0x00, 0x03, 0x07, 0x01, 0xFF]),
    ]

    with caplog.at_level(logging.INFO):
        await _delete_pin(hass, device_id, member_id=3)

    assert device.payloads == [build_delete_pin(3, 7)]
    assert "PIN deleted for member 3 in slot 7" in caplog.text


@pytest.mark.parametrize(
    ("result", "message"),
    [(0x01, "No PIN for member 1 in slot 7"), (0x00, "refused to delete")],
)
async def test_delete_pin_reports_failures(
    hass: HomeAssistant,
    lock_device: tuple[ReplyingDevice, str],
    result: int,
    message: str,
) -> None:
    """An empty slot and a refusal are distinct errors."""
    device, device_id = lock_device
    device.replies = [_raw(2, [0x01, 0x00, 0x00, 0x01, 0x07, 0x01, result])]

    with pytest.raises(HomeAssistantError, match=message):
        await _delete_pin(hass, device_id)


async def test_commands_to_one_lock_share_a_lock(hass: HomeAssistant) -> None:
    """Credential commands to one device are serialized by one asyncio lock."""
    device = ReplyingDevice()

    first = services._command_lock(hass, device)

    assert services._command_lock(hass, device) is first


@pytest.mark.parametrize("pin", [864209, 8.5, None])
async def test_add_pin_needs_the_pin_as_text(
    hass: HomeAssistant, lock_device: tuple[ReplyingDevice, str], pin: Any
) -> None:
    """A YAML number is rejected rather than silently converted."""
    device, device_id = lock_device

    with pytest.raises((probatio.Invalid, ServiceValidationError)) as err:
        await _add_pin(hass, device_id, pin=pin)

    assert "quoted text" in str(err.value)
    assert str(pin) not in str(err.value)
    assert device.payloads == []


async def test_add_pin_refuses_a_non_raw_datapoint(
    hass: HomeAssistant, lock_device: tuple[ReplyingDevice, str]
) -> None:
    """A credential frame is never coerced into another data point type."""
    device, device_id = lock_device
    device.datapoints.update_from_device(1, 0.0, 0, TuyaBLEDataPointType.DT_VALUE, 3)

    with pytest.raises(HomeAssistantError, match="not raw"):
        await _add_pin(hass, device_id)
    assert device.payloads == []
