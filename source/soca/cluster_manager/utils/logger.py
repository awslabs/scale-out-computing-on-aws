# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import logging.handlers
import sys
from typing import Optional
import os
import inspect


class PathTruncatingFormatter(logging.Formatter):
    def format(self, record):
        # custom_pathname return anything after /opt/soca/<cluster_id>/
        _truncate_after = f"/opt/soca/{os.environ.get('SOCA_CLUSTER_ID')}/"
        start_pos = record.pathname.find(_truncate_after) + len(_truncate_after)
        record.custom_pathname = record.pathname[start_pos:]

        # Traverse the call stack to get the call chain
        call_stack = inspect.stack()
        call_chain = []
        for frame_info in call_stack:
            filename = frame_info.filename
            function_name = frame_info.function
            # Only track SOCA cluster_manager files, and drop Python libs and logger.py
            if (
                f"{_truncate_after}cluster_manager" in filename
                and "utils/logger.py" not in filename
            ):
                start_pos = filename.find(_truncate_after) + len(_truncate_after)
                truncated_path = filename[start_pos:]
                call_chain.append(f"{truncated_path}:{function_name}")

        # Combine call chain
        record.call_chain = " > ".join(call_chain[::-1])

        return super(PathTruncatingFormatter, self).format(record)


class SocaLogger:
    def __init__(
        self,
        name: str = "soca_logger",
        level: Optional[int] = None,
        formatter: Optional[str] = None,
    ):
        """
        Constructor for SocaLogger.

        Note: All SOCA scripts expects name to be soca_logger

        Parameters:
        name (str):  # Name of the logger. ! IMPORTANT: All SOCA scripts expects soca_logger !
        level (int / logging.Level): Minimum logging level to be captured, default to INFO, enable debug via export SOCA_DEBUG=1
        formatter (int): Optional: Enforce a customized formatter
        """
        self._logger = logging.getLogger(name)
        _soca_debug = os.environ.get("SOCA_DEBUG", "0")
        if str(_soca_debug) in ["true", "on", "1", "yes", "enabled"]:
            _debug = True
        else:
            _debug = False

        if level is None:
            if _debug:
                self._level = logging.DEBUG
            else:
                self._level = logging.INFO
        else:
            self._level = level

        self._logger.setLevel(self._level)
        if not formatter:
            if _debug or self._level == logging.DEBUG:
                _format = "[%(asctime)s] [%(levelname)s] [%(lineno)d] [%(custom_pathname)s] [%(call_chain)s] [%(funcName)s] [%(message)s]"
            else:
                # call_chain is left empty when debug is disabled to avoid un-necessary text.
                _format = "[%(asctime)s] [%(levelname)s] [%(lineno)d] [%(custom_pathname)s] [] [%(funcName)s] [%(message)s]"
            self._formatter = PathTruncatingFormatter(_format)
        else:
            self._formatter = logging.Formatter(formatter)

    def stdout_handler(self):
        _handler = logging.StreamHandler(sys.stdout)
        _handler.setLevel(self._level)
        _handler.setFormatter(self._formatter)
        self._logger.addHandler(_handler)
        return self.get_logger()

    def file_handler(self, file_path: str):
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        _handler = logging.FileHandler(file_path)
        _handler.setLevel(self._level)
        _handler.setFormatter(self._formatter)
        self._logger.addHandler(_handler)
        return self.get_logger()

    def rotating_file_handler(
        self, file_path: str, max_bytes: int = 1024 * 1024 * 5, backup_count: int = 5
    ):
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        _handler = logging.handlers.RotatingFileHandler(
            file_path, maxBytes=max_bytes, backupCount=backup_count
        )
        _handler.setLevel(self._level)
        _handler.setFormatter(self._formatter)
        self._logger.addHandler(_handler)
        return self.get_logger()

    def timed_rotating_file_handler(
        self,
        file_path: str,
        when: str = "midnight",
        interval: int = 1,
        backup_count: int = 30,
    ):
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        _handler = logging.handlers.TimedRotatingFileHandler(
            file_path, when=when, interval=interval, backupCount=backup_count
        )
        _handler.setLevel(self._level)
        _handler.setFormatter(self._formatter)
        self._logger.addHandler(_handler)
        return self.get_logger()

    def get_logger(self):
        return self._logger
