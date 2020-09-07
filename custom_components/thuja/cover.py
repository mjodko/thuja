import logging
from datetime import timedelta
from enum import Enum, IntEnum

from homeassistant.components.cover import (
    CoverEntity,
    PLATFORM_SCHEMA,
    DEVICE_CLASS_BLIND,
)

from homeassistant.const import (
    CONF_ID,
    CONF_TOKEN,
    CONF_NAME,
    CONF_IP_ADDRESS,
    STATE_OPEN,
    STATE_CLOSED,
    STATE_OPENING,
    STATE_CLOSING,
)

from homeassistant.core import callback
from typing import Optional, Union
from .thuja import ThujaClient
from .device import ThujaDevice
from .platform import BASE_SCHEMA, CONF_MANUFACTURER, CONF_MODEL, CONF_VERSION


_LOGGER = logging.getLogger(__name__)
SCAN_INTERVAL = timedelta(seconds=30)
DEFAULT_NAME = "Tuya Blinds"
PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(BASE_SCHEMA)


class CoverDatapointIndex(IntEnum):
    STATE = 1
    POSITION = 3


class CoverState(Enum):
    IDLE = "stop"
    OPENING = "open"
    CLOSING = "close"


async def async_setup_platform(hass, config, async_add_devices, discovery_info=None):
    thuja_client = ThujaClient(
        ip_address=config[CONF_IP_ADDRESS],
        device_id=config[CONF_ID],
        device_key=config[CONF_TOKEN],
        logger=_LOGGER,
    )

    thuja_client.add_datapoint(CoverDatapointIndex.STATE)
    thuja_client.add_datapoint(CoverDatapointIndex.POSITION)

    cover = Cover(
        thuja_client=thuja_client,
        base_name=config[CONF_NAME],
        manufacturer=config[CONF_MANUFACTURER],
        model=config[CONF_MODEL],
        version=config[CONF_VERSION],
    )

    await thuja_client.start()
    async_add_devices([cover], update_before_add=True)


class Cover(ThujaDevice, CoverEntity):
    _state: str
    _state_value: str
    _position_value: int

    def __init__(
        self,
        thuja_client: ThujaClient,
        base_name: str,
        manufacturer: str,
        model: str,
        version: str,
    ):
        super().__init__(
            thuja_client=thuja_client,
            base_name=base_name,
            manufacturer=manufacturer,
            model=model,
            version=version,
        )

        self._state_value = CoverState.IDLE.value
        self._position_value = 0
        self._update_state()
        self._state = STATE_OPEN

    @property
    def current_cover_position(self):
        return None

    @property
    def current_cover_tilt_position(self):
        return None

    @property
    def is_opening(self) -> bool:
        return self._state == STATE_OPENING

    @property
    def is_closing(self) -> bool:
        return self._state == STATE_CLOSING

    @property
    def is_closed(self) -> bool:
        return self._state == STATE_CLOSED

    def _update_state(self) -> None:
        try:
            cover_state = CoverState(self._state_value)
        except ValueError:
            _LOGGER.exception("Unexpected state value received")
            return

        if cover_state == CoverState.OPENING:
            self._state = STATE_OPENING
        elif cover_state == CoverState.CLOSING:
            self._state = STATE_CLOSING
        elif self._position_value:
            self._state = STATE_CLOSED
        else:
            self._state = STATE_OPEN

    async def async_update(self) -> None:
        self._state_value = await self.thuja_client.get_datapoint_value(
            CoverDatapointIndex.STATE
        )
        self._position_value = await self.thuja_client.get_datapoint_value(
            CoverDatapointIndex.POSITION
        )
        self._update_state()

    async def async_open_cover(self, **kwargs):
        await self.thuja_client.set_datapoint_value(
            CoverDatapointIndex.STATE, CoverState.OPENING.value
        )

    async def async_close_cover(self, **kwargs):
        await self.thuja_client.set_datapoint_value(
            CoverDatapointIndex.STATE, CoverState.CLOSING.value
        )

    async def async_added_to_hass(self) -> None:
        @callback
        def datapoint_value_updated(index: int, value: Union[int, bool, str]) -> None:
            if index == CoverDatapointIndex.STATE:
                self._state_value = value
            elif index == CoverDatapointIndex.POSITION:
                self._position_value = value

            self._update_state()
            self.async_write_ha_state()

        self.thuja_client.set_datapoint_callback(
            CoverDatapointIndex.STATE, datapoint_value_updated
        )
        self.thuja_client.set_datapoint_callback(
            CoverDatapointIndex.POSITION, datapoint_value_updated
        )

    async def async_will_remove_from_hass(self) -> None:
        self.thuja_client.set_datapoint_callback(CoverDatapointIndex.STATE, None)
        self.thuja_client.set_datapoint_callback(CoverDatapointIndex.POSITION, None)

    @property
    def name(self) -> Optional[str]:
        return self.base_name

    @property
    def unique_id(self) -> str:
        return self.thuja_client.device_id

    @property
    def device_class(self) -> str:
        return DEVICE_CLASS_BLIND
