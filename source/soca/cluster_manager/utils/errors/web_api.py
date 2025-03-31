# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Optional
import inspect
from utils.error import SocaError


def HTTP_ERROR(
    endpoint: str,
    method: Optional[str] = str,
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
):
    if method is None:
        method = ""
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"HTTP {method} request error for {endpoint}: ",
        helper=helper,
        status_code=status_code,
    )


def CLIENT_MISSING_PARAMETER(
    parameter: str,
    helper: Optional[str] = None,
    status_code: Optional[int] = 400,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"{parameter} parameter is missing in the request.",
        helper=helper,
        status_code=status_code,
    )


def CLIENT_MISSING_HEADER(
    header: str,
    helper: Optional[str] = None,
    status_code: Optional[int] = 400,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"HTTP header {header} is missing.",
        helper=helper,
        status_code=status_code,
    )


def API_KEY_ERROR(
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"Error managing API Key for user: ",
        helper=helper,
        status_code=status_code,
    )
