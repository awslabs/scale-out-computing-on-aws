# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Optional
import logging
from flask import has_app_context, has_request_context

logger = logging.getLogger("soca_logger")


def is_flask_context() -> bool:
    return has_app_context() or has_request_context()


class SocaResponse:
    """
    Attributes:
        success (bool): Indicates whether the operation was successful or not.
        message (Any): Message providing additional information about the response.
        status_code (int): Status code associated with the response. If not set, default to 200 if request is successful, 500 otherwise
        request (str or None): Details of the request that was made.
        trace (str or None): Trace information for debugging purposes.
    """

    DEFAULT_SUCCESS_STATUS_CODE = 200
    DEFAULT_ERROR_STATUS_CODE = 500

    def __init__(
        self,
        success: bool,
        message: Any,
        status_code: Optional[int] = None,
        request: Optional[str] = None,
        trace: Optional[str] = None,
    ):
        logger.debug(f"Creating SocaResponse with attr: {locals()}")
        # Init attributes
        self.success = success
        self.message = message
        self.status_code = status_code
        self.request = request
        self.trace = trace

        if not isinstance(success, bool):
            self.message = f"success must be a bool in SocaResponse, detected {success}"
            self.success = False
        else:
            self.success = success

        if status_code is None:
            if self.success:
                self.status_code = SocaResponse.DEFAULT_SUCCESS_STATUS_CODE
            else:
                self.status_code = SocaResponse.DEFAULT_ERROR_STATUS_CODE
        else:
            if not isinstance(status_code, int):
                self.message = f"status_code must be an int in SocaResponse, detected {status_code}"
                self.success = False
            elif not (100 <= status_code <= 599):
                self.message = f"status_code must be between 100 and 599 in SocaResponse, detected {status_code}"
                self.success = False
            else:
                self.status_code = status_code

        logger.debug(f"Returning SocaResponse: {self}")

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}: {self.__dict__}>"

    def __str__(self) -> str:
        return self.__repr__()

    def get(self, attribute, default_if_false=None):
        # Return a specific attribute.
        # Specify a default value if success is False
        if self.success:
            return getattr(self, attribute)
        else:
            if default_if_false:
                return default_if_false
            else:
                return getattr(self, attribute)

    def as_flask(self):
        # simple wrapper for as_tuple(keys=[{"success","message"},"status_code"]
        # that's the wrapper we use for SOCA web app
        return self.as_tuple(keys=[{"success", "message"}, "status_code"])

    def as_tuple(self, keys: Optional[list] = None) -> tuple:
        """
        Return a tuple based on the keys format:

        attr_list = ["message", "success", "status_code"]
            -> instance.message, instance.success, instance.status_code

        attr_list = [{"message", "success"}, "status_code"]
            -> {"message": instance.message, "success:" instance.success}, instance.status_code

        There is no tuple length condition (you can return 1, 2, 3+ ... attribute).
        Attribute must exist in SocaResponse (e.g: ["custom_attr"] will AttributeError:
        """
        logger.debug("Returning SocaResponse as_tuple()")
        if keys is None:
            logger.debug("keys not set, returning all SocaResponse keys")
            keys = ["success", "message", "status_code", "request", "trace"]

        if not isinstance(keys, list):
            raise TypeError("keys must be a list")

        _result = []
        for item in keys:
            if isinstance(item, set):
                # Handle the dictionary case (set)
                _result.append({key: getattr(self, key) for key in item})
            else:
                _result.append(getattr(self, item))
        return tuple(_result)

    def as_dict(self, keys: Optional[list] = None) -> dict:
        """
        Return a dict based on the the keys format:

        attr_list = ["message", "success", "status_code"]
        -> {
            "message": instance.message,
            "success": instance.success,
            "status_code: instance.status_code
        }

        There is no length condition (you can return 1, 2, 3+ ... attributes).
        Attribute must exist in SocaResponse (e.g: ["custom_attr"] will AttributeError:
        """
        logger.debug("Returning SocaResponse as_dict()")
        if keys is None:
            logger.debug("keys not set, returning all SocaResponse keys")
            keys = ["success", "message", "status_code", "request", "trace"]

        if not isinstance(keys, list):
            raise TypeError("keys must be a list")

        return {attr: getattr(self, attr) for attr in keys}
