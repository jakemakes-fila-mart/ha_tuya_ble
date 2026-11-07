"""PIN management services for Tuya BLE locks.

``tuya_ble.add_pin`` enrolls a permanent PIN through the lock's
``unlock_method_create`` data point and returns the slot (hardware id) the lock
assigned; ``tuya_ble.delete_pin`` removes one slot through
``unlock_method_delete``. Both write the command and wait for the lock's report
on the same data point, so the caller learns whether the lock accepted it.

A PIN is a credential: it is validated here rather than by the schema (so an
error message never echoes it) and is never logged.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import logging
from typing import TYPE_CHECKING, Any, Final, cast

from homeassistant.core import (
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
)
from homeassistant.exceptions import HomeAssistantError, ServiceValidationError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers import device_registry as dr
import probatio

from .const import DOMAIN
from .lock_commands import (
    CRED_TYPE_PASSWORD,
    DELETE_RESULT_NOT_FOUND,
    HARDWARE_ID_MAX,
    MEMBER_ID_MAX,
    MEMBER_ID_MIN,
    DeleteResult,
    EnrollResult,
    build_add_pin,
    build_delete_pin,
    parse_delete_report,
    parse_enroll_report,
    validate_pin,
)
from .tuya_ble import BLE_CONNECTION_EXCEPTIONS, TuyaBLEDataPointType

if TYPE_CHECKING:
    from .tuya_ble import TuyaBLEDataPoint, TuyaBLEDevice

_LOGGER = logging.getLogger(__name__)

SERVICE_ADD_PIN: Final = "add_pin"
SERVICE_DELETE_PIN: Final = "delete_pin"

ATTR_DEVICE_ID: Final = "device_id"
ATTR_PIN: Final = "pin"
ATTR_MEMBER_ID: Final = "member_id"
ATTR_ADMIN: Final = "admin"
ATTR_HARDWARE_ID: Final = "hardware_id"

CREATE_CODE: Final = "unlock_method_create"
DELETE_CODE: Final = "unlock_method_delete"

# A PIN enrollment needs no input on the lock, so its report follows the
# command almost at once; this only bounds a lock that never answers.
RESPONSE_TIMEOUT: Final = 15.0

_LOCKS_KEY: Final = f"{DOMAIN}_pin_command_locks"

_MEMBER = probatio.All(
    probatio.Coerce(int), probatio.Range(min=MEMBER_ID_MIN, max=MEMBER_ID_MAX)
)

ADD_PIN_SCHEMA: Final = probatio.Schema({
    probatio.Required(ATTR_DEVICE_ID): cv.string,
    probatio.Required(ATTR_PIN): cv.string,
    probatio.Optional(ATTR_MEMBER_ID, default=1): _MEMBER,
    probatio.Optional(ATTR_ADMIN, default=False): cv.boolean,
})

DELETE_PIN_SCHEMA: Final = probatio.Schema({
    probatio.Required(ATTR_DEVICE_ID): cv.string,
    probatio.Required(ATTR_HARDWARE_ID): probatio.All(
        probatio.Coerce(int), probatio.Range(min=0, max=HARDWARE_ID_MAX)
    ),
    probatio.Optional(ATTR_MEMBER_ID, default=1): _MEMBER,
})


def _device_for_call(hass: HomeAssistant, device_id: str) -> TuyaBLEDevice:
    """Return the loaded Tuya BLE device behind a device registry id."""
    registry_device = dr.async_get(hass).async_get(device_id)
    if registry_device is None:
        raise ServiceValidationError(f"Unknown device: {device_id}")
    loaded: dict[str, Any] = hass.data.get(DOMAIN, {})
    for entry_id in registry_device.config_entries:
        data = loaded.get(entry_id)
        if data is not None:
            return cast("TuyaBLEDevice", data.device)
    raise ServiceValidationError(
        f"Device {device_id} is not a loaded Tuya BLE device"
    )


def _dp_for(device: TuyaBLEDevice, code: str) -> int:
    """Return the DP id a device uses for `code`, or reject the call."""
    function = device.function.get(code)
    if function is None:
        raise ServiceValidationError(
            f"This device does not support {code}; PIN management needs a lock "
            "that reports it"
        )
    return function.dp_id


def _command_lock(hass: HomeAssistant, device: TuyaBLEDevice) -> asyncio.Lock:
    """Return the per-device lock that keeps one credential command in flight."""
    locks: dict[str, asyncio.Lock] = hass.data.setdefault(_LOCKS_KEY, {})
    return locks.setdefault(device.address, asyncio.Lock())


async def _async_command[ResultT](
    device: TuyaBLEDevice,
    dp_id: int,
    payload: bytes,
    match: Callable[[bytes], ResultT | None],
) -> ResultT:
    """Write `payload` to `dp_id` and return the first matching report."""
    future: asyncio.Future[ResultT] = asyncio.get_running_loop().create_future()

    def _on_datapoints(datapoints: list[TuyaBLEDataPoint]) -> None:
        if future.done():
            return
        for datapoint in datapoints:
            if datapoint.dp_id != dp_id or not isinstance(datapoint.value, bytes):
                continue
            result = match(datapoint.value)
            if result is not None:
                future.set_result(result)
                return

    unregister = device.register_callback(_on_datapoints)
    try:
        datapoint = device.datapoints.get_or_create(
            dp_id, TuyaBLEDataPointType.DT_RAW, b""
        )
        try:
            await datapoint.set_value(payload)
        except BLE_CONNECTION_EXCEPTIONS as exc:
            raise HomeAssistantError("Could not send the command to the lock") from exc
        try:
            async with asyncio.timeout(RESPONSE_TIMEOUT):
                return await future
        except TimeoutError as exc:
            raise HomeAssistantError(
                f"The lock did not answer within {RESPONSE_TIMEOUT:.0f} seconds"
            ) from exc
    finally:
        unregister()


async def _async_add_pin(call: ServiceCall) -> ServiceResponse:
    """Enroll a permanent PIN and return the slot the lock assigned."""
    hass = call.hass
    device = _device_for_call(hass, call.data[ATTR_DEVICE_ID])
    dp_id = _dp_for(device, CREATE_CODE)
    member_id: int = call.data[ATTR_MEMBER_ID]
    try:
        payload = build_add_pin(
            member_id, call.data[ATTR_PIN], admin=call.data[ATTR_ADMIN]
        )
    except ValueError as exc:
        # The message names the rule, never the PIN.
        raise ServiceValidationError(str(exc)) from None

    def _match(raw: bytes) -> EnrollResult | None:
        report = parse_enroll_report(raw)
        if (
            report is None
            or report.cred_type != CRED_TYPE_PASSWORD
            or report.member_id != member_id
            or not report.is_final
        ):
            return None
        return report

    async with _command_lock(hass, device):
        report = await _async_command(device, dp_id, payload, _match)
    if not report.succeeded:
        raise HomeAssistantError(
            f"The lock refused the PIN (stage 0x{report.stage:02x}, "
            f"result 0x{report.result_code:02x})"
        )
    _LOGGER.info(
        "%s: PIN added for member %s in slot %s",
        device.address,
        report.member_id,
        report.hardware_id,
    )
    return {
        ATTR_MEMBER_ID: report.member_id,
        ATTR_HARDWARE_ID: report.hardware_id,
    }


async def _async_delete_pin(call: ServiceCall) -> None:
    """Delete the PIN in one slot."""
    hass = call.hass
    device = _device_for_call(hass, call.data[ATTR_DEVICE_ID])
    dp_id = _dp_for(device, DELETE_CODE)
    member_id: int = call.data[ATTR_MEMBER_ID]
    hardware_id: int = call.data[ATTR_HARDWARE_ID]
    payload = build_delete_pin(member_id, hardware_id)

    def _match(raw: bytes) -> DeleteResult | None:
        report = parse_delete_report(raw)
        if (
            report is None
            or report.member_id != member_id
            or report.hardware_id != hardware_id
        ):
            return None
        return report

    async with _command_lock(hass, device):
        report = await _async_command(device, dp_id, payload, _match)
    if report.result_code == DELETE_RESULT_NOT_FOUND:
        raise HomeAssistantError(
            f"No PIN for member {member_id} in slot {hardware_id}"
        )
    if not report.succeeded:
        raise HomeAssistantError(
            f"The lock refused to delete the PIN (result 0x{report.result_code:02x})"
        )
    _LOGGER.info(
        "%s: PIN deleted for member %s in slot %s",
        device.address,
        member_id,
        hardware_id,
    )


def async_setup_services(hass: HomeAssistant) -> None:
    """Register the PIN management services."""
    hass.services.async_register(
        DOMAIN,
        SERVICE_ADD_PIN,
        _async_add_pin,
        schema=ADD_PIN_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_DELETE_PIN,
        _async_delete_pin,
        schema=DELETE_PIN_SCHEMA,
    )
