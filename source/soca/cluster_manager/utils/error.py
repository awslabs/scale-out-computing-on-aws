# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import ast
import importlib
import inspect
import sys
import uuid
from typing import Optional, Union
import logging
from flask import Flask, jsonify, request, flash, redirect, has_request_context
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


def is_flask_context():
    try:
        if has_request_context():
            return True
    except RuntimeError:
        return False
    return False


# SOCA Errors are defined in these modules within cluster_manager/utils/errors folder
modules = [
    "aws_api",
    "db",
    "cache",
    "cast",
    "identity_provider",
    "virtual_desktops",
    "web_api",
    "pbs",
    "shell",
]


class SocaError:
    @staticmethod
    def return_error(
        error_id: str,
        error_message: str,
        error_doc_url: Optional[str] = None,
        helper: Optional[str] = None,
        status_code: Optional[int] = 500,
    ) -> [dict, tuple]:
        _error_message = f"{error_message} {helper if helper else ''}"

        # Get the caller's frame
        _inspect_trace = []
        frame = inspect.currentframe().f_back
        while frame:
            frame_info = inspect.getframeinfo(frame)
            # keep trace pointing back to actual filename only
            if not frame_info.filename.startswith("<"):
                _inspect_trace.append(
                    f">> File: {frame_info.filename}, Line: {frame_info.lineno}, Function: {frame_info.function}, Frame ID {id(frame)}"
                )
            frame = frame.f_back

        _trace_log = "\n".join(sorted(_inspect_trace, reverse=False))

        _request_uuid = uuid.uuid4()
        logger.error(
            f"Error ID: {error_id} | Error Message: {_error_message} | Status Code: {status_code} | Error RequestId {_request_uuid} | Error Trace: \n{_trace_log}"
        )

        # These returns are displayed to the user via web interface or CLI
        # We omit technical details such as system trace only available on the relevant log file

        _full_message = f"{error_message} "

        # Handle case where response is dict (e.g: SocaSubprocessClient)
        # we can't append Request ID otherwise it will break the dictionary
        # instead we add a new request_id key and cast back as str
        _error_message_to_str = str(_error_message)
        try:
            _error_dict = ast.literal_eval(_error_message_to_str)
            if isinstance(_error_dict, dict):
                _error_dict["request_id"] = f"Request ID: {_request_uuid}"
                _error_dict["error_documentation_url"] = f"{error_doc_url}"
                message = str(_error_dict)
            else:
                if error_doc_url is not None:
                    message = f"{_error_message}. For troubleshooting, please visit: {error_doc_url}. (Request ID: {_request_uuid})"
                else:
                    message = f"{_error_message} (Request ID: {_request_uuid})"

        except Exception as err:
            # handle case with str breaking literal_eval such as "Unable to search due to NotFoundError(404, 'index_not_found_exception', 'no such index [soca_jobs]', soca_jobs, index_or_alias)" c
            logger.info(f"Unable to literal_eval {_error_message_to_str} due to {err}, defaulting to str")

            if error_doc_url is not None:
                message = f"{_error_message_to_str}. For troubleshooting, please visit: {error_doc_url}. (Request ID: {_request_uuid})"
            else:
                message = f"{_error_message_to_str}  (Request ID: {_request_uuid})"

        _soca_response = SocaResponse(
            success=False,
            message=message,
            status_code=status_code,
            request=request if is_flask_context() else None,
            trace=_trace_log,
        )
        logger.debug(f"SocaError -> returning SocaResponse: {_soca_response}")
        return _soca_response

    @staticmethod
    def GENERIC_ERROR(
        helper: Optional[str] = None,
        status_code: Optional[int] = 500,
        error_doc_url: Optional[str] = None,
    ):
        return SocaError.return_error(
            error_id=inspect.currentframe().f_code.co_name,
            error_message=f"",
            error_doc_url=error_doc_url,
            helper=helper,
            status_code=status_code,
        )

    @staticmethod
    def SOCA_CONFIG_KEY_VERIFIER(
            helper: Optional[str] = None,
            status_code: Optional[int] = 500,
            error_doc_url: Optional[str] = None,
    ):
        return SocaError.return_error(
            error_id=inspect.currentframe().f_code.co_name,
            error_message=f"",
            error_doc_url=error_doc_url,
            helper=helper,
            status_code=status_code,
        )
    @staticmethod
    def JINJA_GENERATOR_ERROR(
            helper: Optional[str] = None,
            status_code: Optional[int] = 500,
            error_doc_url: Optional[str] = None,
    ):
        return SocaError.return_error(
            error_id=inspect.currentframe().f_code.co_name,
            error_message=f"",
            error_doc_url=error_doc_url,
            helper=helper,
            status_code=status_code,
        )

    @staticmethod
    def ANALYTICS_ERROR(
            helper: Optional[str] = None,
            status_code: Optional[int] = 500,
            error_doc_url: Optional[str] = None,
    ):
        return SocaError.return_error(
            error_id=inspect.currentframe().f_code.co_name,
            error_message=f"",
            error_doc_url=error_doc_url,
            helper=helper,
            status_code=status_code,
        )


_all_errors = {}
for module_name in modules:
    _all_errors[module_name] = []
    module = importlib.import_module(f"utils.errors.{module_name}")
    for name, obj in inspect.getmembers(module, inspect.isfunction):
        _all_errors[module_name].append(name)
        # Check if the function doesn't already exist in SocaError
        if not hasattr(SocaError, name):
            setattr(SocaError, name, staticmethod(obj))
        else:
            logger.fatal(
                f"Function {name} already exists in SocaError. You cannot have the same error declared twice, pick a different name:  {_all_errors}"
            )
            sys.exit(1)
