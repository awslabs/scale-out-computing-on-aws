# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Optional, Any
import logging
import config
from requests import get, post, put, delete
from utils.response import SocaResponse


logger = logging.getLogger("soca_logger")


class SocaHttpClient:
    def __init__(
        self,
        endpoint: str,
        headers: Optional[dict] = None,
        verify: Optional[
            bool
        ] = False,  # set to True if the SSL certificate is trusted for your endpoint
        expected_return_codes: Optional[
            list
        ] = None,  # list of status code to consider the request as successful
    ):
        if expected_return_codes is None:
            expected_return_codes = [200]

        self._verify = verify
        if not endpoint.startswith(config.Config.FLASK_ENDPOINT):
            if endpoint.startswith("/"):
                self._url_endpoint = f"{config.Config.FLASK_ENDPOINT}{endpoint}"
            else:
                self._url_endpoint = f"{config.Config.FLASK_ENDPOINT}/{endpoint}"
        else:
            self._url_endpoint = endpoint
        self._expected_return_codes = expected_return_codes
        self._headers = headers

    def get(self, params: dict = None):
        return self.return_request("get", params=params)

    def post(self, data: dict = None):
        return self.return_request("post", params=data)

    def put(self, data: dict = None):
        return self.return_request(method="put", params=data)

    def delete(self, data: dict = None):
        return self.return_request(method="delete", params=data)

    def return_request(self, method, params):
        # Remove X-SOCA-TOKEN, password etc from log
        _sanitize_log = ["X-SOCA-TOKEN", "password", "passwd", "token", "auth", "csrf_token"]
        _req_header_to_log = {}
        _req_data_to_log = {}
        if self._headers is not None:
            for k, v in self._headers.items():
                if k in _sanitize_log:
                    _req_header_to_log[k] = "<REDACTED>"
        if params is not None:
            for k, v in params.items():
                if k in _sanitize_log:
                    _req_data_to_log[k] = "<REDACTED>"

        logger.debug(
            f"Received {method} request {self._url_endpoint} headers: {_req_header_to_log}, attrs {_req_data_to_log}"
        )

        if method == "get":
            _req = get(
                self._url_endpoint,
                headers=self._headers,
                params=params,
                verify=self._verify,
            )
        elif method == "post":
            _req = post(
                self._url_endpoint,
                headers=self._headers,
                data=params,
                verify=self._verify,
            )
        elif method == "put":
            _req = put(
                self._url_endpoint,
                headers=self._headers,
                data=params,
                verify=self._verify,
            )
        elif method == "delete":
            _req = delete(
                self._url_endpoint,
                headers=self._headers,
                data=params,
                verify=self._verify,
            )

        if _req.status_code in self._expected_return_codes:
            logger.debug(
                f"Success: True as request status code {_req.status_code} is in the expected return codes {self._expected_return_codes}"
            )
            _success = True
        else:
            logger.debug(
                f"Success: False as request status code {_req.status_code} is not in the expected return codes {self._expected_return_codes}"
            )
            _success = False

        try:
            # if response is dict, check if "message" & "success" are present which is usually the response we get from SOCA endpoint ({success: xx, message:yy)}
            # Otherwise, endpoint is probably not SOCA, return response as is
            _json_response = _req.json()
            _message = _json_response.get("message", _json_response)
            if "success" in _json_response.keys():
                if _json_response.get("success") != _success:
                    logger.warning(
                        f"SocaHttpClient detected possible mismatch between request status:  success is {_success} as the response status code {_req.status_code}, expected success cde {self._expected_return_codes} but success key is present in response and is set to the opposite {_json_response}"
                    )
        except ValueError:
            logger.debug(
                "Received request is not a valid JSON, fallback returning as text"
            )
            _message = _req.text

        logger.debug(
            f"Returning SocaResponse dict: success {_success}, message {_message}, status_code: {_req.status_code}, request: {_req} "
        )
        return SocaResponse(
            success=_success,
            message=_message,
            status_code=_req.status_code,
            request=_req,
        )
