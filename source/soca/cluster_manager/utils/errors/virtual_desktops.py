# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Optional, Union
import inspect
from utils.error import SocaError


def VIRTUAL_DESKTOP_LAUNCH_ERROR(
    session_number: int,
    session_owner: str,
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
    error_doc_url: Optional[str] = None,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"Unable to Launch Desktop {session_number} (owner: {session_owner}): ",
        error_doc_url=error_doc_url,
        helper=helper,
        status_code=status_code,
    )


def VIRTUAL_DESKTOP_MODIFY_ERROR(
    session_number: int,
    session_owner: str,
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
    error_doc_url: Optional[str] = None,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"Unable to Modify Desktop {session_number} (owner: {session_owner}): ",
        error_doc_url=error_doc_url,
        helper=helper,
        status_code=status_code,
    )


def VIRTUAL_DESKTOP_RESTART_ERROR(
    session_number: int,
    session_owner: str,
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
    error_doc_url: Optional[str] = None,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"Unable to Restart Desktop {session_number} (owner: {session_owner}): ",
        error_doc_url=error_doc_url,
        helper=helper,
        status_code=status_code,
    )


def VIRTUAL_DESKTOP_STOP_ERROR(
    session_number: int,
    session_owner: str,
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
    error_doc_url: Optional[str] = None,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"Unable to Stop Desktop {session_number} (owner: {session_owner}): ",
        error_doc_url=error_doc_url,
        helper=helper,
        status_code=status_code,
    )


def VIRTUAL_DESKTOP_SCHEDULE_ERROR(
    session_number: str,
    session_owner: str,
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
    error_doc_url: Optional[str] = None,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"Unable to update Schedule for Desktop {session_number} (owner: {session_owner}): ",
        error_doc_url=error_doc_url,
        helper=helper,
        status_code=status_code,
    )


def VIRTUAL_DESKTOP_AUTHENTICATION_ERROR(
    helper: Optional[str] = None,
    status_code: Optional[int] = 401,
    error_doc_url: Optional[str] = None,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"Unable to authenticate DCV session: ",
        error_doc_url=error_doc_url,
        helper=helper,
        status_code=status_code,
    )


def IMAGE_REGISTER_ERROR(
    image_id: str,
    image_label: str,
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
    error_doc_url: Optional[str] = None,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"Unable to register {image_id} - {image_label}: ",
        error_doc_url=error_doc_url,
        helper=helper,
        status_code=status_code,
    )


def IMAGE_DEREGISTER_ERROR(
    image_label: str,
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
    error_doc_url: Optional[str] = None,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"Unable to de-register {image_label}: ",
        error_doc_url=error_doc_url,
        helper=helper,
        status_code=status_code,
    )
