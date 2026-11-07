"""Lock handlers for jtmspro locks commanded through DP 71 ``ble_unlock_check``.

These locks report their state on ``lock_motor_state`` but only act on a
``ble_unlock_check`` frame carrying the lock's 8-character check code, which
the cloud supplies when the device is added (see ``cloud.extract_check_code``).
The code is a credential: nothing here logs it or the frame built from it.

The lock must list ``ble_unlock_check`` among its cloud functions. That is how
its data point is found, and it is what marks the data point as a credential so
the protocol layer redacts it from logs and diagnostics and never replays it.
A lock without it is never sent a frame.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Final

from homeassistant.exceptions import HomeAssistantError

from ...dp_command import async_send_raw
from ...lock_commands import (
    UnlockCheckReport,
    build_unlock_check,
    parse_unlock_check_report,
)

if TYPE_CHECKING:
    from ...entity import TuyaBLEEntity, TuyaBLEProductInfo
    from ...tuya_ble import TuyaBLEDevice

_LOGGER = logging.getLogger(__name__)

UNLOCK_CHECK_CODE: Final = "ble_unlock_check"

# The lock answers on DP 71 right after acting. A lock that does not report is
# not treated as a failure: the state DP still shows what happened.
REPLY_TIMEOUT: Final = 5.0


def _unlock_check_dp(device: TuyaBLEDevice) -> int | None:
    function = device.function.get(UNLOCK_CHECK_CODE)
    return function.dp_id if function is not None else None


def has_check_code(entity: TuyaBLEEntity, _product: TuyaBLEProductInfo) -> bool:
    """Return whether the lock can be commanded.

    It needs a stored check code and a ``ble_unlock_check`` cloud function.
    """
    device = entity.device
    return bool(device.check_code) and _unlock_check_dp(device) is not None


async def send_unlock_check(
    entity: TuyaBLEEntity, _product: TuyaBLEProductInfo, unlock: bool
) -> None:
    """Send a DP 71 lock (``False``) or unlock (``True``) command."""
    device = entity.device
    check_code = device.check_code
    if not check_code:
        raise HomeAssistantError(
            "This lock has no check code; remove the device and add it again "
            "so the cloud can supply one"
        )
    dp_id = _unlock_check_dp(device)
    if dp_id is None:
        raise HomeAssistantError(
            f"This lock does not list {UNLOCK_CHECK_CODE}; it cannot be commanded"
        )
    timestamp = int(time.time())
    try:
        payload = build_unlock_check(check_code, unlock=unlock, timestamp=timestamp)
    except ValueError as exc:
        raise HomeAssistantError("The stored lock check code is malformed") from exc

    def _match(raw: bytes) -> UnlockCheckReport | None:
        report = parse_unlock_check_report(raw)
        if report is None or report.unlock != unlock or report.timestamp != timestamp:
            return None
        return report

    _LOGGER.debug(
        "%s: sending %s command on DP %s",
        device.address,
        "unlock" if unlock else "lock",
        dp_id,
    )
    report = await async_send_raw(
        device,
        dp_id,
        payload,
        match=_match,
        reply_timeout=REPLY_TIMEOUT,
        reply_required=False,
    )
    if report is None:
        _LOGGER.debug("%s: no DP %s report for the command", device.address, dp_id)
    elif not report.succeeded:
        raise HomeAssistantError(
            f"The lock rejected the {'unlock' if unlock else 'lock'} command "
            f"(result 0x{report.result_code:02x})"
        )
