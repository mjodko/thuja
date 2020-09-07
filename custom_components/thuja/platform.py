import re
import socket
import voluptuous
from homeassistant.const import CONF_ID, CONF_TOKEN, CONF_NAME, CONF_IP_ADDRESS
from homeassistant.helpers import config_validation
from typing import Any


DOMAIN = "thuja"
CONF_MANUFACTURER = "manufacturer"
CONF_MODEL = "model"
CONF_VERSION = "version"


def device_id_validation(value: Any) -> str:
    value = config_validation.string(value).strip().lower()

    if not re.match(r"^[a-z0-9]{22}$", value):
        raise voluptuous.Invalid("value should be a valid device identifier")

    return value


def device_key_validation(value: Any) -> str:
    value = config_validation.string(value).strip().lower()

    if not re.match(r"^[a-f0-9]{16}$", value):
        raise voluptuous.Invalid("value should be a valid device key")

    return value


def ip_address_validation(value: Any) -> str:
    value = config_validation.string(value).strip().lower()

    try:
        socket.inet_pton(socket.AF_INET, value)
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, value)
        except socket.error:
            raise voluptuous.Invalid("value should be a IP address")

    return value


BASE_SCHEMA = {
    voluptuous.Required(CONF_ID): device_id_validation,
    voluptuous.Required(CONF_TOKEN): device_key_validation,
    voluptuous.Required(CONF_IP_ADDRESS): ip_address_validation,
    voluptuous.Optional(CONF_NAME, default="Tuya Device"): config_validation.string,
    voluptuous.Optional(CONF_MANUFACTURER, default="Thuja"): config_validation.string,
    voluptuous.Optional(CONF_MODEL, default="Generic"): config_validation.string,
    voluptuous.Optional(CONF_VERSION, default="Unknown"): config_validation.string,
}
