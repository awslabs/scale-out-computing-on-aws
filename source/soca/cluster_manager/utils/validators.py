# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Union
import logging

logger = logging.getLogger("soca_logger")


class Validators:

    @staticmethod
    def exist(value: Any) -> Union[Any, bool]:
        return value if value is not None else False

    @staticmethod
    def is_string(value: Any) -> Union[str, bool]:
        return value if isinstance(value, str) else False

    @staticmethod
    def is_int(value: Any) -> Union[int, bool]:
        return value if isinstance(value, int) else False

    @staticmethod
    def is_float(value: Any) -> Union[float, bool]:
        return value if isinstance(value, float) else False

    @staticmethod
    def is_bool(value: Any) -> Union[bool, bool]:
        return value if isinstance(value, bool) else False

    @staticmethod
    def is_list(value: Any) -> Union[list, bool]:
        return value if isinstance(value, list) else False

    @staticmethod
    def is_dict(value: Any) -> Union[dict, bool]:
        return value if isinstance(value, dict) else False
