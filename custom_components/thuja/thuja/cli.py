import argparse
import asyncio
import sys
import tty
from typing import Union
from .client import ThujaClient


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--ip_address", type=str, help="IP address", required=True
    )
    parser.add_argument("-d", "--device_id", type=str, help="Device ID", required=True)
    parser.add_argument(
        "-k", "--device_key", type=str, help="Device key", required=True
    )
    parser.add_argument(
        "-c", "--dp_count", type=int, help="Datapoint count", required=True
    )
    arguments = parser.parse_args()

    if (arguments.dp_count < 1) or (arguments.dp_count > 10):
        raise argparse.ArgumentError(
            "Datapoint count must fall in range between 1 and 10"
        )

    return arguments


def cli() -> None:
    arguments = parse_arguments()

    print(
        "\n".join(
            [
                "Thuja CLI",
                "Usage:",
                "- [u]pdate datapoint values",
                "- [t]oggle datapoint values",
                "- toggle value of datapoint #[1 - 3]",
                "- turn all datapoints of[f]",
                "- turn all datapoints o[n]",
                "- [q]uit",
            ]
        )
    )

    thuja = ThujaClient(
        ip_address=arguments.ip_address,
        device_id=arguments.device_id,
        device_key=arguments.device_key,
    )

    def datapoint_value_updated(index: int, value: Union[int, bool, str]) -> None:
        print(f"Value of datapoint #{index} updated: {repr(value)}")

    for index in range(1, arguments.dp_count + 1):
        thuja.add_datapoint(index)
        thuja.set_datapoint_callback(index, datapoint_value_updated)

    tty.setcbreak(sys.stdin.fileno())

    async def control_loop() -> None:
        await thuja.start()
        event_loop = asyncio.get_running_loop()
        input_queue = asyncio.Queue()

        def handle_input():
            character = sys.stdin.read(1).lower()
            asyncio.ensure_future(input_queue.put(character), loop=event_loop)

        event_loop.add_reader(sys.stdin, handle_input)

        while True:
            character = await input_queue.get()

            if character == "q":
                await thuja.stop()
                break
            elif character == "u":
                await thuja.update_datapoint_values()
            elif character.isnumeric():
                index = int(character)

                if 1 <= index <= arguments.dp_count:
                    value = await thuja.get_datapoint_value(index)

                    if isinstance(value, bool):
                        value = not value

                    await thuja.set_datapoint_value(index, value)
            elif character == "n":
                values = {index: True for index in range(1, arguments.dp_count + 1)}
                await thuja.set_datapoint_values(values)
            elif character == "f":
                values = {index: False for index in range(1, arguments.dp_count + 1)}
                await thuja.set_datapoint_values(values)
            elif character == "t":
                await thuja.update_datapoint_values()

                values = {
                    index: not thuja.get_last_datapoint_value(index)
                    for index in range(1, arguments.dp_count + 1)
                }

                await thuja.set_datapoint_values(values)

    event_loop = asyncio.get_event_loop()
    event_loop.run_until_complete(control_loop())


if __name__ == "__main__":
    cli()
