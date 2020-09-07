from typing import Any, Optional, Dict
from .thuja import ThujaClient
from .platform import DOMAIN


class ThujaDevice:
    thuja_client: ThujaClient
    base_name: str
    manufacturer: str
    model: str
    version: str

    def __init__(
        self,
        thuja_client: ThujaClient,
        base_name: str,
        manufacturer: str,
        model: str,
        version: str,
    ):
        self.thuja_client = thuja_client
        self.base_name = base_name
        self.manufacturer = manufacturer
        self.model = model
        self.version = version

    async def async_update(self):
        await self.thuja_client.update_datapoint_values()

    @property
    def unique_id(self) -> str:
        return self.thuja_client.device_id

    @property
    def name(self) -> str:
        return self.base_name

    @property
    def available(self) -> bool:
        return self.thuja_client.is_available

    @property
    def should_poll(self) -> bool:
        return True

    @property
    def device_info(self) -> Optional[Dict[str, Any]]:
        return {
            "identifiers": {(DOMAIN, self.thuja_client.device_id)},
            "name": self.name,
            "manufacturer": self.manufacturer,
            "model": self.model,
            "sw_version": self.version,
        }
