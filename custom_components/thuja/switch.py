import logging
import voluptuous
from datetime import timedelta

from homeassistant.components.switch import (
    SwitchEntity,
    PLATFORM_SCHEMA,
    DEVICE_CLASS_SWITCH,
)

from homeassistant.const import (
    CONF_ID,
    CONF_TOKEN,
    CONF_NAME,
    CONF_IP_ADDRESS,
    CONF_SWITCHES,
)

from homeassistant.core import callback
from homeassistant.helpers import config_validation
from typing import List, Optional, Any, Union
from .thuja import ThujaClient
from .device import ThujaDevice
from .platform import BASE_SCHEMA, CONF_MANUFACTURER, CONF_MODEL, CONF_VERSION


_LOGGER = logging.getLogger(__name__)
SCAN_INTERVAL = timedelta(seconds=30)
DEFAULT_NAME = "Tuya Switch"

SCHEMA = BASE_SCHEMA.copy()

SCHEMA.update(
    {
        voluptuous.Required(CONF_SWITCHES): voluptuous.All(
            [
                voluptuous.Schema(
                    {
                        voluptuous.Required(CONF_ID): voluptuous.All(
                            voluptuous.Coerce(int), voluptuous.Range(min=1, max=9)
                        ),
                        voluptuous.Optional(
                            CONF_NAME, default="Switch"
                        ): config_validation.string,
                    }
                )
            ],
            voluptuous.Length(min=0),
        )
    }
)

PLATFORM_SCHEMA = PLATFORM_SCHEMA.extend(SCHEMA)


async def async_setup_platform(hass, config, async_add_devices, discovery_info=None):
    thuja_client = ThujaClient(
        ip_address=config[CONF_IP_ADDRESS],
        device_id=config[CONF_ID],
        device_key=config[CONF_TOKEN],
        logger=_LOGGER,
    )

    switches: List[Switch] = []

    for switch_configuration in config[CONF_SWITCHES]:
        thuja_client.add_datapoint(
            index=switch_configuration[CONF_ID], name=switch_configuration[CONF_NAME]
        )

        switch = Switch(
            thuja_client=thuja_client,
            base_name=config[CONF_NAME],
            manufacturer=config[CONF_MANUFACTURER],
            model=config[CONF_MODEL],
            version=config[CONF_VERSION],
            datapoint_index=switch_configuration[CONF_ID],
        )

        switches.append(switch)

    await thuja_client.start()
    async_add_devices(switches, update_before_add=True)


class Switch(ThujaDevice, SwitchEntity):
    _state: bool
    _datapoint_index: int

    def __init__(
        self,
        thuja_client: ThujaClient,
        base_name: str,
        manufacturer: str,
        model: str,
        version: str,
        datapoint_index: int,
    ):
        super().__init__(
            thuja_client=thuja_client,
            base_name=base_name,
            manufacturer=manufacturer,
            model=model,
            version=version,
        )
        self._state = False
        self._datapoint_index = datapoint_index

    async def async_update(self) -> None:
        self._state = await self.thuja_client.get_datapoint_value(self._datapoint_index)

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self.thuja_client.set_datapoint_value(self._datapoint_index, True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self.thuja_client.set_datapoint_value(self._datapoint_index, False)

    @property
    def is_on(self) -> bool:
        return self._state

    async def async_added_to_hass(self) -> None:
        @callback
        def datapoint_value_updated(index: int, value: Union[int, bool, str]) -> None:
            self._state = bool(value)
            self.async_write_ha_state()

        self.thuja_client.set_datapoint_callback(
            self._datapoint_index, datapoint_value_updated
        )

    async def async_will_remove_from_hass(self) -> None:
        self.thuja_client.set_datapoint_callback(self._datapoint_index, None)

    @property
    def name(self) -> Optional[str]:
        name = self.thuja_client.get_datapoint_name(self._datapoint_index)

        if self.base_name:
            name = f"{self.base_name} {name}"

        return name

    @property
    def unique_id(self) -> str:
        return f"{self.thuja_client.device_id}_{self._datapoint_index}"

    @property
    def device_class(self) -> str:
        return DEVICE_CLASS_SWITCH
