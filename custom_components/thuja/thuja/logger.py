import logging
from typing import Dict, Any, Tuple


class PrefixedLoggerAdapter(logging.LoggerAdapter):
    prefix: str

    def __init__(self, logger: logging.Logger, prefix: str):
        super().__init__(logger, {})
        self.prefix = prefix

    def process(self, msg: str, kwargs: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
        return f"[{self.prefix}] {msg}", kwargs
