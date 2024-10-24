# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import boto3
import botocore
import logging
from typing import Optional
from utils.error import SocaError
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


def get_boto_session_credentials():
    try:
        return SocaResponse(success=True, message=boto3.Session().get_credentials())
    except Exception as err:
        return SocaError.AWS_API_ERROR(
            service_name="boto3",
            helper=f"Unable to get boto3 credentials because of {err}",
        )


def get_boto_session_region():
    try:
        return SocaResponse(success=True, message=boto3.Session().region_name)
    except Exception as err:
        return SocaError.AWS_API_ERROR(
            service_name="boto3",
            helper=f"Unable to get boto3 region because of {err}",
        )


def get_boto(
    service_name: str,
    region_name: Optional[str] = None,
    extra_config: Optional[bool] = True,
    resource: Optional[bool] = False,
    endpoint_url: Optional[str] = None,
) -> boto3.session:
    if extra_config:
        _extra_parameters = {"user_agent_extra": "AwsSolution/SO0072/24.10"}
        _config = botocore.config.Config(**_extra_parameters)
    else:
        _config = None

    if not region_name:
        region_name = boto3.Session().region_name

    _boto3_params = {
        "service_name": service_name,
        "region_name": region_name,
        "endpoint_url": endpoint_url,
        "config": _config,
    }

    logger.debug(f"Building boto3 {service_name} with params {_boto3_params}")

    try:
        if not resource:
            return SocaResponse(success=True, message=boto3.client(**_boto3_params))
        else:
            return SocaResponse(success=True, message=boto3.resource(**_boto3_params))
    except Exception as err:
        return SocaError.AWS_API_ERROR(
            service_name="boto3",
            helper=f"Unable to create boto3 {'resource' if resource else 'client'} for {service_name} because of {err}",
        )
