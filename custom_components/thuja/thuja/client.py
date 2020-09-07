import asyncio
import binascii
import json
import logging
import time
from dataclasses import dataclass
from enum import Enum, IntEnum, auto
from typing import Optional, Dict, Any, NamedTuple, List, Callable, Union
from . import pyaes
from .exceptions import ThujaError

from .constants import (
    CONNECTION_LOOP_INTERVAL,
    CONNECTION_TIMEOUT,
    HEARTBEAT_INTERVAL,
    HEARTBEAT_TIMEOUT_INTERVAL,
    LOGGER_NAME,
    RECONNECT_INTERVAL,
    REQUEST_INTERVAL,
    TUYA_PORT,
)

from .logger import PrefixedLoggerAdapter


ThujaCallback = Callable[[int, Union[int, bool, str]], None]


@dataclass
class Datapoint:
    index: int
    name: Optional[str] = None
    value: Union[int, bool, str, None] = None
    callback: Optional[ThujaCallback] = None


class CommandCode(IntEnum):
    STATUS = 8
    HEARTBEAT = 9
    CONTROL = 13


class Request(NamedTuple):
    sequence_number: int
    command_code: CommandCode
    time: int
    data: Optional[dict] = None


class Response(NamedTuple):
    sequence_number: int
    command_code: CommandCode
    return_code: int
    time: Optional[int] = None
    data: Optional[dict] = None


class Status(Enum):
    IDLE = auto()
    RUNNING = auto()
    STOPPING = auto()


class ConnectionStatus(Enum):
    DISCONNECTED = auto()
    CONNECTING = auto()
    RECONNECTING = auto()
    CONNECTED = auto()
    DISCONNECTING = auto()


class ThujaClient:
    _ip_address: str
    _device_id: str
    _device_key: bytes
    _logger: logging.LoggerAdapter
    _datapoints: Dict[int, Datapoint]

    _request_queue: asyncio.Queue
    _request_sequence_number: int
    _response_queue: asyncio.Queue
    _last_heartbeat_request_time: Optional[float]
    _last_heartbeat_response_time: Optional[float]
    _control_events: Dict[int, asyncio.Event]
    _datapoint_update_event: asyncio.Event
    _running_tasks: List[asyncio.Task]

    _status: Status
    _connection_status: ConnectionStatus
    _connection_event: asyncio.Event
    _should_reconnect: bool
    _stream_reader: Optional[asyncio.StreamReader] = None
    _stream_writer: Optional[asyncio.StreamWriter] = None

    def __init__(
        self,
        ip_address: str,
        device_id: str,
        device_key: str,
        logger: Optional[logging.Logger] = None,
    ):
        self._ip_address = ip_address
        self._device_id = device_id
        self._device_key = device_key.encode("latin1")
        self._logger = self._create_logger_adapter(logger or self._create_logger())
        self._datapoints = {}

        self._status = Status.IDLE
        self._connection_status = ConnectionStatus.DISCONNECTED
        self._should_reconnect = False
        self._connection_event = asyncio.Event()

        self._request_queue = asyncio.Queue()
        self._request_sequence_number = 0
        self._response_queue = asyncio.Queue()
        self._last_heartbeat_request_time = None
        self._last_heartbeat_response_time = None
        self._control_events = {}
        self._datapoint_update_event = asyncio.Event()
        self._running_tasks = []

    @property
    def device_id(self) -> str:
        return self._device_id

    @property
    def status(self) -> Status:
        return self._status

    @property
    def is_available(self) -> bool:
        return (self._status == Status.RUNNING) and (
            self._connection_status == ConnectionStatus.CONNECTED
        )

    def _create_logger(self) -> logging.Logger:
        logger = logging.getLogger(LOGGER_NAME)
        logger.setLevel(logging.DEBUG)

        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)

        formatter = logging.Formatter(
            fmt="[%(asctime)s] %(levelname)s [thuja] %(message)s"
        )
        handler.setFormatter(formatter)

        logger.addHandler(handler)
        return logger

    def _create_logger_adapter(self, logger: logging.Logger) -> logging.LoggerAdapter:
        return PrefixedLoggerAdapter(logger, prefix=self._device_id)

    @property
    def logging_level(self) -> int:
        return self._logger.logger.level

    @logging_level.setter
    def logging_level(self, level: int) -> None:
        self._logger.setLevel(level)

    def _get_datapoint(self, index: int) -> Datapoint:
        try:
            return self._datapoints[index]
        except KeyError:
            raise ThujaError(f"Datapoint with index {index} does not exist")

    def add_datapoint(self, index: int, name: Optional[str] = None) -> None:
        if self._status != Status.IDLE:
            raise ThujaError("Adding datapoints is only possible in the idle state")

        if index in self._datapoints:
            raise ThujaError(f"Datapoint with index {index} already exists")

        name = name or f"DP{index}"
        datapoint = Datapoint(index=index, name=name)
        self._datapoints[index] = datapoint

    def get_datapoint_name(self, index: int) -> Optional[str]:
        return self._get_datapoint(index).name

    def get_last_datapoint_value(self, index: int) -> Union[int, bool, str, None]:
        return self._get_datapoint(index).value

    async def get_datapoint_value(self, index: int) -> Any:
        datapoint = self._get_datapoint(index)
        await self.update_datapoint_values()
        return datapoint.value

    async def set_datapoint_value(
        self, index: int, value: Union[int, bool, str]
    ) -> None:
        await self.set_datapoint_values({index: value})

    async def set_datapoint_values(
        self, values: Dict[int, Union[int, bool, str]]
    ) -> None:
        for index, value in values.items():
            _ = self._get_datapoint(index)

            if not isinstance(value, (bool, int, str)):
                raise ThujaError(f"Invalid datapoint value type: {repr(value)}")

        request = await self._add_request(command_code=CommandCode.CONTROL, data=values)

        if request.sequence_number not in self._control_events:
            return

        await self._control_events[request.sequence_number].wait()

    def set_datapoint_callback(
        self, index: int, callback: Optional[ThujaCallback]
    ) -> None:
        self._get_datapoint(index).callback = callback

    async def start(self) -> None:
        if self._status != Status.IDLE:
            raise ThujaError("Client already running")

        self._logger.info("Starting")

        event_loop = asyncio.get_running_loop()
        self._running_tasks = []
        self._running_tasks.append(event_loop.create_task(self._request_loop()))
        self._running_tasks.append(event_loop.create_task(self._response_loop()))
        self._running_tasks.append(event_loop.create_task(self._connection_loop()))
        self._status = Status.RUNNING

        self._logger.info("Started")

    async def stop(self) -> None:
        if self._status != Status.RUNNING:
            raise ThujaError("Client not running")

        self._logger.info("Stopping")
        self._status = Status.STOPPING
        await self._request_queue.put(None)
        await self._disconnect()
        await asyncio.gather(*self._running_tasks)
        self._running_tasks = []
        self._status = Status.IDLE
        self._logger.info("Stopped")

    async def update_datapoint_values(self) -> None:
        data = {datapoint.index: None for datapoint in self._datapoints.values()}
        await self._add_request(command_code=CommandCode.CONTROL, data=data)
        await self._datapoint_update_event.wait()

    async def _add_request(
        self, command_code: CommandCode, data: Optional[dict] = None
    ) -> Request:
        request = Request(
            sequence_number=self._request_sequence_number,
            time=int(time.time()),
            command_code=command_code,
            data=data,
        )

        if command_code == CommandCode.CONTROL:
            self._control_events[request.sequence_number] = asyncio.Event()

        self._request_sequence_number += 1
        await self._request_queue.put(request)
        self._logger.debug(f"Created request: {request}")
        return request

    async def _request_loop(self):
        while self._status == Status.RUNNING:
            if self._connection_status == ConnectionStatus.CONNECTED:
                request = await self._request_queue.get()

                if not request:
                    self._logger.debug(f"[REQUESTS] Stopping")
                    continue

                self._logger.debug(f"[REQUESTS] Processing request: {request}")

                try:
                    data = self._serialize_request(request)
                except Exception:
                    self._logger.exception("[REQUESTS] Failed to serialize request")
                    continue

                self._logger.debug(f"[REQUESTS] Sending request data: {data.hex()}")

                try:
                    self._stream_writer.write(data)
                    await self._stream_writer.drain()
                except Exception:
                    self._logger.exception("Failed to send request data")
                    await self._request_queue.put(request)
                    self._should_reconnect = True
                    await self._connection_event.wait()
                    continue

                await asyncio.sleep(REQUEST_INTERVAL)
            else:
                await self._connection_event.wait()

    async def _response_loop(self):
        while self._status == Status.RUNNING:
            if self._connection_status == ConnectionStatus.CONNECTED:
                try:
                    data = await self._stream_reader.read(4096)

                    if not data:
                        raise IOError("Connection closed")
                except IOError:
                    self._logger.exception("Failed to read response data")
                    self._should_reconnect = True
                    await self._connection_event.wait()
                    continue

                self._logger.debug(f"[RESPONSES] Received {len(data)} bytes")
                responses = self._parse_responses(data)
                self._logger.debug(f"Parsed {len(responses)} response(s)")

                for response in responses:
                    await self._handle_response(response)
            else:
                await self._connection_event.wait()

    async def _connection_loop(self):
        while self._status == Status.RUNNING:
            if self._should_reconnect and self._connection_status in (
                ConnectionStatus.DISCONNECTED,
                ConnectionStatus.CONNECTED,
            ):
                if await self._reconnect():
                    self._should_reconnect = False
            elif self._connection_status == ConnectionStatus.DISCONNECTED:
                if not await self._connect():
                    self._should_reconnect = True

            if self._connection_status != ConnectionStatus.CONNECTED:
                continue

            now = time.time()

            time_since_last_heartbeat_response = (
                now - self._last_heartbeat_response_time
            )

            if time_since_last_heartbeat_response > HEARTBEAT_TIMEOUT_INTERVAL:
                self._logger.info(
                    f"[CONNECTION] No heartbeat from the device in {int(time_since_last_heartbeat_response)} second(s)"
                )
                self._should_reconnect = True
                continue

            time_since_last_heartbeat_request = now - self._last_heartbeat_request_time

            if time_since_last_heartbeat_request > HEARTBEAT_INTERVAL:
                self._logger.debug(
                    f"[CONNECTION] Adding heartbeat request to the queue"
                )
                self._last_heartbeat_request_time = now
                await self._add_request(command_code=CommandCode.HEARTBEAT)

            await asyncio.sleep(CONNECTION_LOOP_INTERVAL)

    async def _connect(self) -> bool:
        self._connection_status = ConnectionStatus.CONNECTING
        self._logger.info(f"Connecting to {self._ip_address}:{TUYA_PORT}")

        try:
            connection = asyncio.open_connection(self._ip_address, TUYA_PORT)

            self._stream_reader, self._stream_writer = await asyncio.wait_for(
                connection, CONNECTION_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError):
            self._connection_status = ConnectionStatus.DISCONNECTED
            self._logger.exception("Failed to connect")
            return False

        self._connection_status = ConnectionStatus.CONNECTED
        self._last_heartbeat_request_time = time.time()
        self._last_heartbeat_response_time = time.time()
        self._connection_event.set()
        self._connection_event.clear()
        self._logger.info("Connected")
        return True

    async def _disconnect(self) -> bool:
        if self._connection_status == ConnectionStatus.DISCONNECTED:
            return True

        self._connection_status = ConnectionStatus.DISCONNECTING
        self._logger.info("Disconnecting")

        if self._stream_reader:
            self._stream_reader = None

        if self._stream_writer:
            try:
                self._stream_writer.close()
                await self._stream_writer.wait_closed()
            except Exception:
                self._logger.exception("Failed to close connection")

            self._stream_writer = None

        self._connection_status = ConnectionStatus.DISCONNECTED
        self._connection_event.set()
        self._connection_event.clear()
        self._logger.info("Disconnected")
        return True

    async def _reconnect(self) -> bool:
        self._connection_status = ConnectionStatus.RECONNECTING
        self._logger.info(f"Reconnecting in {RECONNECT_INTERVAL} second(s)")
        await asyncio.sleep(RECONNECT_INTERVAL)
        await self._disconnect()
        return await self._connect()

    def _serialize_request(self, request: Request) -> bytes:
        payload = self._get_request_payload(request)
        serialized_payload = self._serialize_request_payload(payload)
        encrypted_payload = self._encrypt_request_payload(serialized_payload)

        payload_data = b"".join(
            [b"3.3", bytes(12), encrypted_payload, b"\0\0\0\0\0\0\xaa\x55"]
        )

        header_data = b"".join(
            [
                b"\0\0\x55\xaa",
                request.sequence_number.to_bytes(4, byteorder="big"),
                request.command_code.value.to_bytes(4, byteorder="big"),
                len(payload_data).to_bytes(4, byteorder="big"),
            ]
        )

        crc = self._calculate_data_crc(header_data + payload_data[:-8])

        request_data = b"".join(
            [
                header_data,
                payload_data[:-8],
                crc.to_bytes(4, byteorder="big"),
                payload_data[-4:],
            ]
        )

        return request_data

    def _calculate_data_crc(self, data: bytes) -> int:
        return binascii.crc32(data) & 0xFFFFFFFF

    def _serialize_request_payload(self, payload: Dict[str, Any]) -> bytes:
        return json.dumps(payload, separators=(",", ":")).encode("utf-8")

    def _encrypt_request_payload(self, serialized_payload: bytes) -> bytes:
        encrypted_payload = b""
        block_size = 16
        aes = pyaes.AESModeOfOperationECB(self._device_key)

        for offset in range(0, len(serialized_payload), block_size):
            block = serialized_payload[offset : offset + block_size].ljust(
                block_size, b"\0"
            )

            encrypted_payload += aes.encrypt(block)

        return encrypted_payload

    def _get_request_payload(self, request: Request) -> Dict[str, Any]:
        if request.command_code == CommandCode.HEARTBEAT:
            payload = {}
        elif request.command_code == CommandCode.CONTROL:
            payload = {
                "devId": self._device_id,
                "uid": self._device_id,
                "t": str(request.time),
            }

            if request.data:
                payload["dps"] = request.data
        else:
            raise ValueError(
                f"Unsupported request command code: {request.command_code}"
            )

        return payload

    def _parse_responses(self, data: bytes) -> List[Response]:
        self._logger.debug(f"Parsing responses from data: {data.hex()}")

        delimiter = b"\0\0\x55\xaa"
        chunks = [chunk for chunk in data.split(delimiter) if chunk]

        self._logger.debug(f"Split response data into {len(chunks)} chunk(s)")

        responses: List[Response] = []

        for chunk in chunks:
            try:
                response = self._parse_response(delimiter + chunk)
            except Exception:
                self._logger.exception(
                    f"Failed to parse response from data: {chunk.hex()}"
                )

                continue

            if response:
                self._logger.debug(f"Parsed response: {response}")
                responses.append(response)

        return responses

    def _parse_response(self, data: bytes) -> Optional[Response]:
        if not data:
            return None

        if (len(data) < 28) or not data.endswith(b"\0\0\xaa\x55"):
            self._logger.debug(f"Ignoring invalid response chunk: {data.hex()}")
            return None

        command_code = int.from_bytes(data[8:12], byteorder="big")

        if command_code not in (
            CommandCode.CONTROL,
            CommandCode.STATUS,
            CommandCode.HEARTBEAT,
        ):
            self._logger.debug(
                f"Ignoring unsupported response command code: {command_code}"
            )
            return None

        sequence_number = int.from_bytes(data[4:8], byteorder="big")
        payload_size = int.from_bytes(data[12:16], byteorder="big")
        return_code = int.from_bytes(data[16:20], byteorder="big")
        crc = int.from_bytes(data[-8:-4], byteorder="big")

        if crc != self._calculate_data_crc(data[:-8]):
            self._logger.debug(f"Response CRC32 mismatch: {data.hex()}")
            return None

        if payload_size > 12:
            payload = data[20 : 8 + payload_size]

            if command_code == CommandCode.STATUS:
                payload = payload[15:]

            decrypted_payload = self._decrypt_response_payload(payload)
            payload = self._deserialize_response_payload(decrypted_payload)
            response_time = payload.get("t")
            response_data = payload.get("dps")
        else:
            response_time = None
            response_data = None

        response = Response(
            sequence_number=sequence_number,
            command_code=CommandCode(command_code),
            return_code=return_code,
            time=response_time,
            data=response_data,
        )

        return response

    def _decrypt_response_payload(self, encrypted_payload: bytes) -> bytes:
        decrypted_payload = b""
        block_size = 16
        aes = pyaes.AESModeOfOperationECB(self._device_key)

        for offset in range(0, len(encrypted_payload), block_size):
            block = encrypted_payload[offset : offset + block_size].ljust(
                block_size, b"\0"
            )

            decrypted_payload += aes.decrypt(block)

        decrypted_payload = decrypted_payload[: -decrypted_payload[-1]]
        return decrypted_payload

    def _deserialize_response_payload(self, payload: bytes) -> dict:
        deserialized_payload = json.loads(payload.decode("utf-8"))

        if not isinstance(deserialized_payload, dict):
            raise ValueError("Unexpected response payload format")

        return deserialized_payload

    async def _run_datapoint_callback(self, datapoint: Datapoint) -> None:
        if datapoint.callback:
            datapoint.callback(datapoint.index, datapoint.value)

    async def _handle_response(self, response: Response) -> None:
        if (response.command_code == CommandCode.STATUS) and isinstance(
            response.data, dict
        ):
            updated_datapoint_indexes = set()

            for index, value in response.data.items():
                if not isinstance(index, str) or not index.isnumeric():
                    continue

                index = int(index)
                datapoint = self._datapoints.get(index)

                if not datapoint:
                    continue

                datapoint.value = value
                self._logger.debug(
                    f"Updated value of datapoint #{datapoint.index}: {datapoint.value}"
                )

                asyncio.create_task(self._run_datapoint_callback(datapoint))
                updated_datapoint_indexes.add(index)

            if updated_datapoint_indexes == set(self._datapoints.keys()):
                self._datapoint_update_event.set()
                self._datapoint_update_event.clear()
        elif (response.command_code == CommandCode.CONTROL) and (
            response.sequence_number in self._control_events
        ):
            self._control_events[response.sequence_number].set()
            del self._control_events[response.sequence_number]
        elif response.command_code == CommandCode.HEARTBEAT:
            self._last_heartbeat_response_time = time.time()
