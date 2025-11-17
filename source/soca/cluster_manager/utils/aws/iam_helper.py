# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

import botocore
import utils.aws.boto3_wrapper as utils_boto3
from utils.cache.decorator import soca_cache
from utils.error import SocaError
from utils.response import SocaResponse


client_iam = utils_boto3.get_boto(service_name="iam").message
logger = logging.getLogger("soca_logger")


@soca_cache(prefix="soca:webui:aws:iam:describe_instance_type")
def get_instance_profile(instance_profile_name: str) -> SocaResponse:
    logger.info(f"Get Instance Profile: {instance_profile_name}")
    try:
        _get_instance_profile = client_iam.get_instance_profile(
            InstanceProfileName=instance_profile_name
        )
        logger.debug(f"get_instance_profile Results: {_get_instance_profile}")
        return SocaResponse(success=True, message=_get_instance_profile)
    except botocore.exceptions.ClientError as e:
        return SocaError.GENERIC_ERROR(
            helper=f"ClientError: Unable to get_instance_profile for {instance_profile_name} due to {e}"
        )

    except Exception as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to run get_instance_profile due to {e}"
        )
