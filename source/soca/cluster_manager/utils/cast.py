# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Type
import logging
import ast
from utils.response import SocaResponse
from utils.error import SocaError
import os
import sys
logger = logging.getLogger("soca_logger")


def auto_cast(data: Any) -> Any:
    """
    This function automatically cast a data to its original type.
    Support nested list/dictionary
    """
    if isinstance(data, str):
        try:
            if data.lower() in SocaCastEngine.ALLOWED_TRUE_VALUES:
                return True
            elif data.lower() in SocaCastEngine.ALLOWED_FALSE_VALUES:
                return False
            else:
                parsed_value = ast.literal_eval(data)
                return parsed_value
        except (ValueError, SyntaxError):
            # If parsing fails, just return the original string value
            return data
    elif isinstance(data, list):
        # Recursively process each element in the list
        return [auto_cast(item) for item in data]
    elif isinstance(data, dict):
        # Recursively process each key-value pair in the dictionary
        return {k: auto_cast(v) for k, v in data.items()}

    return data


class SocaCastEngine:
    """
    Return None if we cannot cast the data as requested type
    """

    ALLOWED_FALSE_VALUES = ["false", "no", "off", "0", "disabled"]
    ALLOWED_TRUE_VALUES = ["true", "yes", "on", "1", "enabled"]

    def __init__(self, data: Any):
        self._data = data

    def cast_as(self, expected_type: Type):
        logger.debug(f"Trying to cast {self._data} as {expected_type}")
        _allowed_types = [bool, dict, float, int, list, set, str, tuple]
        if expected_type not in _allowed_types:
            return SocaError.CAST_ERROR(
                helper=f"Invalid type, must be one of {''.join(str(_allowed_types))}"
            )
        else:
            if self.is_type(expected_type=expected_type):
                return SocaResponse(success=True, message=self._data)
            else:
                try:
                    if isinstance(self._data, bytes):
                        logger.debug("bytes detected, casting it back as str first.")
                        self._data = self._data.decode()

                    if expected_type == bool:
                        # Cast specific str as bool
                        if (
                            str(self._data).lower()
                            in SocaCastEngine.ALLOWED_FALSE_VALUES
                        ):
                            return SocaResponse(success=True, message=False)
                        elif (
                            str(self._data).lower()
                            in SocaCastEngine.ALLOWED_TRUE_VALUES
                        ):
                            return SocaResponse(success=True, message=True)
                        else:
                            return SocaError.CAST_ERROR(
                                helper=f"{self._data} is not a valid bool value."
                            )

                    elif expected_type == dict:
                        # casting a dict to str (e.g for Redis) then back to dict could cause:
                        # ValueError: dictionary update sequence element #0 has length 1; 2 is required
                        # As a safety measure we use ast.literal_eval() as fail over
                        try:
                            return SocaResponse(success=True, message=dict(self._data))
                        except Exception as _e:
                            _dict_cast = ast.literal_eval(self._data)
                            if isinstance(_dict_cast, dict):
                                return SocaResponse(success=True, message=_dict_cast)
                            else:
                                return SocaError.CAST_ERROR(
                                    helper=f"Unable to cast {self._data} as dict because of {_e}"
                                )
                    elif expected_type == list:
                        _list_cast = ast.literal_eval(self._data)
                        if isinstance(_list_cast, list):
                            return SocaResponse(success=True, message=_list_cast)
                        else:
                            return SocaError.CAST_ERROR(
                                helper=f"Unable to cast {self._data} as list"
                            )

                    # All other types
                    else:
                        return SocaResponse(
                            success=True, message=expected_type(self._data)
                        )

                except Exception as e:
                    return SocaError.CAST_ERROR(
                        helper=f"Unable to cast {self._data} to {expected_type} due to {e}"
                    )

    def is_type(self, expected_type: Type):
        if isinstance(self._data, expected_type):
            return True
        else:
            return False

    def autocast(self, preserve_key_name: bool = False) -> dict:
        # This function will try to automatically cast self._data as its best type
        # Support nested list and dictionary
        _result = {}
        _cluster_id = f"/soca/{os.environ.get('SOCA_CLUSTER_ID')}"
        logger.debug(f"Trying to autocast dictionary {self._data} with preserve_key_name to {preserve_key_name}")

        if preserve_key_name is False:
            if not isinstance(self._data, dict):
                return SocaError.CAST_ERROR(helper=f"Data must be a dict when preserve_key_name is set to False")

            _updated_dict = {}
            for key, value in self._data.items():
                _updated_dict[key.replace(_cluster_id, "")] = value
            self._data.clear()
            self._data.update(_updated_dict)

        try:
            _result = auto_cast(self._data)
            return SocaResponse(success=True, message=_result)

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.CAST_ERROR(
                helper=f"Unable to autocast {self._data} due to {err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            )