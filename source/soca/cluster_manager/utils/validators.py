# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class Validators:
    @staticmethod
    def _return(name: str, result: bool, *args) -> bool:
        logger.debug(f"{name} {args}: {result}")
        return result

    @staticmethod
    def exist(value: Any) -> bool:
        return Validators._return("exist", value is not None, value)

    @staticmethod
    def is_string(value: Any) -> bool:
        return Validators._return("is_string", isinstance(value, str), value)
    
    @staticmethod
    def _string_len_check(value: Any, predicate, number: int, name: str) -> bool:
        # number -> expected length
        result = isinstance(value, str) and predicate(len(value), number)
        return Validators._return(name, result, value, number)
    
    @staticmethod
    def is_string_length_equal_of(value: Any, number: int) -> bool:
        return Validators._string_len_check(
            value, lambda a, b: a == b, number, "is_string_length_equal_of"
        )

    @staticmethod
    def is_string_length_not_equal_of(value: Any, number: int) -> bool:
        return Validators._string_len_check(
            value, lambda a, b: a != b, number, "is_string_length_not_equal_of"
        )

    @staticmethod
    def is_string_length_greater_than(value: Any, number: int) -> bool:
        return Validators._string_len_check(
            value, lambda a, b: a > b, number, "is_string_length_greater_than"
        )

    @staticmethod
    def is_string_length_greater_equal_than(value: Any, number: int) -> bool:
        return Validators._string_len_check(
            value, lambda a, b: a >= b, number, "is_string_length_greater_equal_than"
        )

    @staticmethod
    def is_string_length_lower_than(value: Any, number: int) -> bool:
        return Validators._string_len_check(
            value, lambda a, b: a < b, number, "is_string_length_lower_than"
        )

    @staticmethod
    def is_string_length_lower_equal_than(value: Any, number: int) -> bool:
        return Validators._string_len_check(
            value, lambda a, b: a <= b, number, "is_string_length_lower_equal_than"
        )
    
    @staticmethod
    def is_int(value: Any) -> bool:
        return Validators._return(
            "is_int", isinstance(value, int) and not isinstance(value, bool), value
        )

    @staticmethod
    def is_float(value: Any) -> bool:
        return Validators._return("is_float", isinstance(value, float), value)

    @staticmethod
    def is_bool(value: Any) -> bool:
        return Validators._return("is_bool", isinstance(value, bool), value)

    @staticmethod
    def is_list(value: Any) -> bool:
        return Validators._return("is_list", isinstance(value, list), value)

    @staticmethod
    def is_dict(value: Any) -> bool:
        return Validators._return("is_dict", isinstance(value, dict), value)

    # list len() helper
    @staticmethod
    def _list_len_check(value: Any, predicate, number: int, name: str) -> bool:
        # number -> expected length

        result = isinstance(value, list) and predicate(len(value), number)
        return Validators._return(name, result, value, number)

    @staticmethod
    def is_list_length_equal_of(value: Any, number: int) -> bool:
        return Validators._list_len_check(
            value, lambda a, b: a == b, number, "is_list_length_equal_of"
        )

    @staticmethod
    def is_list_length_not_equal_of(value: Any, number: int) -> bool:
        return Validators._list_len_check(
            value, lambda a, b: a != b, number, "is_list_length_not_equal_of"
        )

    @staticmethod
    def is_list_length_greater_than(value: Any, number: int) -> bool:
        return Validators._list_len_check(
            value, lambda a, b: a > b, number, "is_list_length_greater_than"
        )

    @staticmethod
    def is_list_length_greater_equal_than(value: Any, number: int) -> bool:
        return Validators._list_len_check(
            value, lambda a, b: a >= b, number, "is_list_length_greater_equal_than"
        )

    @staticmethod
    def is_list_length_lower_than(value: Any, number: int) -> bool:
        return Validators._list_len_check(
            value, lambda a, b: a < b, number, "is_list_length_lower_than"
        )

    @staticmethod
    def is_list_length_lower_equal_than(value: Any, number: int) -> bool:
        return Validators._list_len_check(
            value, lambda a, b: a <= b, number, "is_list_length_lower_equal_than"
        )

    @staticmethod
    def is_list_not_empty(value: Any) -> bool:
        return Validators._return(
            "is_list_not_empty", isinstance(value, list) and bool(value), value
        )

    @staticmethod
    def is_dict_not_empty(value: Any) -> bool:
        return Validators._log(
            "is_dict_not_empty", isinstance(value, dict) and bool(value), value
        )

    @staticmethod
    def is_string_not_empty(value: Any) -> bool:
        return Validators._return(
            "is_string_not_empty", isinstance(value, str) and bool(value), value
        )

    @staticmethod
    def is_positive_int(value: Any) -> bool:
        return Validators._return(
            "is_positive_int",
            isinstance(value, int) and not isinstance(value, bool) and value > 0,
            value,
        )

    @staticmethod
    def is_non_negative_int(value: Any) -> bool:
        return Validators._return(
            "is_non_negative_int",
            isinstance(value, int) and not isinstance(value, bool) and value >= 0,
            value,
        )

    @staticmethod
    def is_datetime(value: Any) -> bool:
        return Validators._return("is_datetime", isinstance(value, datetime), value)

    @staticmethod
    def is_future_datetime(value: Any) -> bool:
        return Validators._return(
            "is_future_datetime",
            isinstance(value, datetime) and value > datetime.now(),
            value,
        )

    @staticmethod
    def is_past_datetime(value: Any) -> bool:
        return Validators._return(
            "is_past_datetime",
            isinstance(value, datetime) and value < datetime.now(),
            value,
        )
