# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import logging
from typing import Type, Optional, Any
import utils.aws.boto3_wrapper as utils_boto3
from utils.cache import SocaCacheClient
from utils.cast import SocaCastEngine
from utils.error import SocaError
from utils.response import SocaResponse
from utils.config_checks import SocaConfigKeyVerifier

logger = logging.getLogger("soca_logger")


class SocaConfig:
    def __init__(
        self,
        key: str,
        parameter_name_prefix: Optional[
            str
        ] = f"/soca/{os.environ.get('SOCA_CONFIGURATION')}",
        cache_admin: bool = True
    ):
        self._parameter_name_prefix = parameter_name_prefix
        # Enforce "/" at the beginning of the parameter key name
        self._parameter_name = key if key.startswith("/") else f"/{key}"

        # _full_parameter_name is the parameter key name + specified prefix
        if self._parameter_name.startswith(self._parameter_name_prefix):
            self._full_parameter_name = self._parameter_name
        else:
            self._full_parameter_name = (
                f"{ self._parameter_name_prefix}{self._parameter_name}"
            )

        # _parameter_name_no_prefix is parameter key name without prefix
        self._parameter_name_no_prefix = self._full_parameter_name.split(
            self._parameter_name_prefix
        )[-1]

        # Return whether the parameter key is an entire hierarchy
        self._is_path = True if self._full_parameter_name.endswith("/") else False

        self.cache_admin = cache_admin

        # Init client
        self._cache_client = SocaCacheClient(is_admin=self.cache_admin)
        self._ssm_client = utils_boto3.get_boto(service_name="ssm").message

    def get_value(
        self,
        cache_result: Optional[bool] = True,  # choose whether to cache the value
        return_as: Optional[Type] = str,  # return result as specific type
        full_key_name: Optional[bool] = False,  # include parameter_name_prefix if True
        default: Optional[Any] = None,  # Return default value if not set
    ) -> [Any, None]:
        logger.debug(
            f"Trying to retrieve parameter {self._full_parameter_name}, is_path {self._is_path}"
        )
        _cache_enabled = self._cache_client.is_enabled()

        # First, we check if the key we are looking for does not already exist in our cache
        # This only works if they key is not a path
        if not self._is_path:
            if _cache_enabled.success:
                logger.debug(f"Checking if {self._full_parameter_name} exist in Cache")
                _key_in_redis = self._cache_client.get(key=self._full_parameter_name)
                if _key_in_redis.success:
                    logger.debug(
                        f"{self._full_parameter_name} exist in cache. Retrieving value"
                    )
                    _result = SocaCastEngine(_key_in_redis.message).cast_as(
                        expected_type=return_as
                    )
                    if not _result.success:
                        return SocaError.CAST_ERROR(
                            helper=f"Value retrieved on cache but could not cast {_key_in_redis.message} as {return_as}"
                        )
                    else:
                        return SocaResponse(success=True, message=_result.message)
                else:
                    logger.debug(f"{self._full_parameter_name} does NOT exist in cache")
            else:
                logger.info("Cache is not enabled, querying SSM directly")

        # If key is not in cache, query SSM
        try:
            if self._is_path:
                _output = {}
                _paginator = self._ssm_client.get_paginator("get_parameters_by_path")
                _response_paginator = _paginator.paginate(
                    Path=self._full_parameter_name, Recursive=True
                )
                if return_as:
                    logger.debug(
                        f"return_as is set but ignored as SSM key ({self._full_parameter_name}) is path and will always return a dict"
                    )

                if default is not None:
                    logger.debug(
                        f"default is set but ignored as SSM key ({self._full_parameter_name}) is path and will always return a dict"
                    )

                for _page in _response_paginator:
                    parameters = _page["Parameters"]
                    if not parameters:
                        logger.info(
                            f"{self._full_parameter_name} not found. Add '/' at the end if this key is a hierarchy tree"
                        )
                        if default is not None:
                            return SocaResponse(success=True, message=default)
                        else:
                            return SocaResponse(success=False, message={})

                    for _entry in parameters:
                        if cache_result is True:
                            if self.cache_admin is True:
                                logger.debug(f"Caching {_entry['Name']} ...  ")
                                self._cache_client.set(
                                    key=_entry["Name"], value=_entry["Value"]
                                )
                            else:
                                logger.warning("cache_result is True but cache_admin is False, data won't be cached")

                        _output[
                            _entry["Name"]
                            if full_key_name
                            else _entry["Name"].split(self._parameter_name_prefix)[-1]
                        ] = _entry["Value"]

                return SocaResponse(success=True, message=_output)
            else:
                _response = self._ssm_client.get_parameter(
                    Name=self._full_parameter_name
                )
                _key_name = _response.get("Parameter").get("Name")
                _key_value = _response.get("Parameter").get("Value")
                if cache_result is True:
                    if self.cache_admin is True:
                        logger.debug(f"Caching {_key_name} ...  ")
                        self._cache_client.set(
                            key=_key_name,
                            value=_key_value,
                        )
                    else:
                        logger.warning("cache_result is True but cache_admin is False, data won't be cached")

                _result = SocaCastEngine(_key_value).cast_as(expected_type=return_as)
                if not _result.success:
                    return SocaError.CAST_ERROR(
                        helper=f"Value retrieved on cache but could not cast {_key_value} as {return_as}"
                    )
                else:
                    return SocaResponse(success=True, message=_result.message)

        except self._ssm_client.exceptions.ParameterNotFound:
            if default is not None:
                return SocaResponse(success=True, message=default)
            else:
                return SocaError.AWS_API_ERROR(
                    service_name="ssm_parameterstore",
                    helper=f"{self._full_parameter_name} not found. Add '/' at the end if this key is a hierarchy tree",
                )

        except Exception as e:
            if default is not None:
                return SocaResponse(success=True, message=default)
            else:
                return SocaError.AWS_API_ERROR(
                    service_name="ssm_parameterstore",
                    helper=f"Unknown error while trying to retrieve parameter {self._full_parameter_name} due to {e}",
                )

    def get_value_history(self, sort: Optional[str] = "desc") -> dict:
        _history = {}
        _sort = sort if sort in ["desc", "asc"] else "desc"  # Desc = newest first

        try:
            _current_parameter_key_value = self.get_value()
            if _current_parameter_key_value.success:
                _get_parameter_history = self._ssm_client.get_parameter_history(
                    Name=self._full_parameter_name
                )
                if _get_parameter_history.get("Parameters"):
                    for _version in _get_parameter_history.get("Parameters"):
                        _history[_version["Version"]] = {
                            "Version": _version["Version"],
                            "Value": _version["Value"],
                            "LastModifiedDate": _version["LastModifiedDate"],
                        }

                if (
                    _get_parameter_history.get("ResponseMetadata").get("HTTPStatusCode")
                    == 200
                ):
                    if _sort == "asc":
                        return SocaResponse(
                            success=True,
                            message={k: _history[k] for k in sorted(_history)},
                        )
                    else:
                        # desc
                        return SocaResponse(
                            success=True,
                            message={
                                k: _history[k] for k in sorted(_history, reverse=True)
                            },
                        )
                else:
                    return SocaError.AWS_API_ERROR(
                        service_name="ssm_parameterstore",
                        helper=f"Unknown error while trying to retrieve parameter {self._full_parameter_name} due to {_get_parameter_history}",
                    )
            else:
                return SocaResponse(
                    success=False, message=_current_parameter_key_value.message
                )

        except Exception as e:
            return SocaError.AWS_API_ERROR(
                service_name="ssm_parameterstore",
                helper=f"Unknown error while trying to retrieve parameter {self._full_parameter_name} due to {e}",
            )

    def set_value(self, value: str) -> [str, bool]:
        _is_valid_value = SocaConfigKeyVerifier(
            key=self._parameter_name_no_prefix
        ).check(value=value)
        if not _is_valid_value.success:
            return _is_valid_value
        try:
            _current_parameter_key_value = self.get_value().get("message")
            if _current_parameter_key_value == value:
                return SocaResponse(
                    success=False,
                    message=f"Value of {self._full_parameter_name} is already {value}",
                )
            else:
                _update_key = self._ssm_client.put_parameter(
                    Name=self._full_parameter_name,
                    Value=value,
                    Type="String",
                    Overwrite=True,
                )
                if _update_key.get("ResponseMetadata").get("HTTPStatusCode") == 200:
                    return SocaResponse(success=True, message="Key update successfully")
                else:
                    return SocaError.AWS_API_ERROR(
                        service_name="ssm_parameterstore",
                        helper=f"Unknown error while trying to update parameter {_update_key}",
                    )

        except Exception as e:
            logger.error(
                f"Error: Unknown error while trying to retrieve parameter {self._full_parameter_name}. Trace: {e}"
            )
            return SocaError.AWS_API_ERROR(
                service_name="ssm_parameterstore",
                helper=f"Unknown error while trying to retrieve parameter {self._full_parameter_name} due to {e}",
            )
