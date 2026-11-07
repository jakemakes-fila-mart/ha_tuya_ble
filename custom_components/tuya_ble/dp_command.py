"""Send one raw credential data point and optionally wait for the lock's report.

Used by the PIN actions and the DP 71 lock handler. The payloads carry a PIN or
the lock check code, so nothing here logs them, and every failure is turned
into a Home Assistant error whose message never contains them.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import TYPE_CHECKING, Final

from homeassistant.exceptions import HomeAssistantError

from .tuya_ble import BLE_CONNECTION_EXCEPTIONS, TuyaBLEDataPointType

if TYPE_CHECKING:
    from .tuya_ble import TuyaBLEDataPoint, TuyaBLEDevice

# Bounds the whole send, connection retries included. Without it a command
# could reach the lock minutes after it was asked for, once the person who
# tapped Unlock has walked away. Cancellation rolls the write back before the
# frame is written; a frame already on the air when the limit hits cannot be
# recalled, and the protocol layer never replays a credential write.
COMMAND_SEND_TIMEOUT: Final = 20.0


async def async_send_raw[ResultT](
    device: TuyaBLEDevice,
    dp_id: int,
    payload: bytes,
    *,
    match: Callable[[bytes], ResultT | None] | None = None,
    reply_timeout: float = 0.0,
    reply_required: bool = True,
) -> ResultT | None:
    """Write `payload` to raw DP `dp_id`; return the first matching report.

    With no `match`, returns None once the device acknowledged the write. With
    a `match`, waits up to `reply_timeout` seconds for a report on `dp_id` that
    `match` accepts; if none arrives, raises when `reply_required`, otherwise
    returns None.
    """
    datapoint = device.datapoints.get_or_create(dp_id, TuyaBLEDataPointType.DT_RAW, b"")
    if datapoint.dp_type is not TuyaBLEDataPointType.DT_RAW:
        raise HomeAssistantError(
            f"Data point {dp_id} is reported as {datapoint.dp_type.name}, not raw; "
            "refusing to send a credential command to it"
        )

    future: asyncio.Future[ResultT] = asyncio.get_running_loop().create_future()

    def _on_datapoints(datapoints: list[TuyaBLEDataPoint]) -> None:
        if match is None or future.done():
            return
        for report in datapoints:
            if report.dp_id != dp_id or not isinstance(report.value, bytes):
                continue
            result = match(report.value)
            if result is not None:
                future.set_result(result)
                return

    unregister = device.register_callback(_on_datapoints)
    try:
        try:
            async with asyncio.timeout(COMMAND_SEND_TIMEOUT):
                await datapoint.set_value(payload)
        except TimeoutError as exc:
            raise HomeAssistantError(
                f"The lock did not confirm the command within "
                f"{COMMAND_SEND_TIMEOUT:.0f} seconds; it may or may not have acted, "
                "so check its state before trying again"
            ) from exc
        except BLE_CONNECTION_EXCEPTIONS as exc:
            raise HomeAssistantError("Could not send the command to the lock") from exc
        if match is None:
            return None
        try:
            async with asyncio.timeout(reply_timeout):
                return await future
        except TimeoutError as exc:
            if not reply_required:
                return None
            raise HomeAssistantError(
                f"The lock did not answer within {reply_timeout:.0f} seconds"
            ) from exc
    finally:
        unregister()
