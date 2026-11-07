"""Lock handlers for jtmspro locks commanded through DP 71 ``ble_unlock_check``.

These locks report their state on ``lock_motor_state`` but only act on a
``ble_unlock_check`` frame carrying the lock's 8-character check code, which
the cloud supplies when the device is added (see ``cloud.extract_check_code``).
The code is a credential: nothing here logs it or the frame built from it.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

from homeassistant.exceptions import HomeAssistantError

from ...lock_commands import build_unlock_check
from ...tuya_ble import TuyaBLEDataPointType

if TYPE_CHECKING:
    from ...entity import TuyaBLEEntity, TuyaBLEProductInfo

_LOGGER = logging.getLogger(__name__)

UNLOCK_CHECK_CODE = "ble_unlock_check"
UNLOCK_CHECK_DEFAULT_DP = 71


def has_check_code(entity: TuyaBLEEntity, _product: TuyaBLEProductInfo) -> bool:
    """Return whether the lock can be commanded (a check code is stored)."""
    return bool(entity.device.check_code)


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
    function = device.function.get(UNLOCK_CHECK_CODE)
    dp_id = function.dp_id if function is not None else UNLOCK_CHECK_DEFAULT_DP
    try:
        payload = build_unlock_check(
            check_code, unlock=unlock, timestamp=int(time.time())
        )
    except ValueError as exc:
        raise HomeAssistantError("The stored lock check code is malformed") from exc
    datapoint = device.datapoints.get_or_create(dp_id, TuyaBLEDataPointType.DT_RAW, b"")
    _LOGGER.debug(
        "%s: sending %s command on DP %s",
        device.address,
        "unlock" if unlock else "lock",
        dp_id,
    )
    await datapoint.set_value(payload)
