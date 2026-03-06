# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

import botocore
from typing import Literal
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.ec2_helper import describe_images
from utils.cache.decorator import soca_cache
from utils.error import SocaError
from utils.response import SocaResponse


client_ssm = utils_boto3.get_boto(service_name="ssm").message
logger = logging.getLogger("soca_logger")


@soca_cache(prefix="soca:webui:aws:ssm:get_ami_id_from_alias", ttl=86400)
def get_ami_id_from_alias(
    alias_name: str,
) -> SocaResponse:
    """

    This helper will automatically fetch the latest version of a specific AMI. This is particularly useful for Windows as
    Windows AMI are now expired automatically every 3 months:

    AWS Windows AMIs are publicly available for three months after they are released.
    Within 10 days after the release of new AMIs, AWS changes access for AMIs that are more than three months old to make them private.

    Source: https://docs.aws.amazon.com/ec2/latest/windows-ami-reference/windows-ami-versions.html

    Because of that, we cannot hardcode AMI ID anymore, and launching Windows VDI will need to call this function to get the most recent Windows AMI

    eg: Instead of registering a Software Stack with `ami-xxxx`, you will register it with `/aws/service/ami-windows-latest/Windows_Server-2025-English-Full-Base`"
    """

    logger.info(f"Get AMI ID for {alias_name=}")

    try:
        _fetch_ami_id = client_ssm.get_parameter(
            Name=alias_name,
        )

        logger.debug(f"get_ami_alias for {alias_name}: {_fetch_ami_id}")
        _ami_id = _fetch_ami_id["Parameter"]["Value"]
        # Received results for this alias, we just validate this is a correct AMI ID
        if _ami_id.startswith("ami-"):
            # check if AMI is correct
            _validate_ami = describe_images(image_ids=[_ami_id])
            if _validate_ami.get("success") is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to get AMI ID for {alias_name}. Received Result: {_ami_id}"
                )
            else:
                return SocaResponse(success=True, message=_ami_id)
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to get AMI ID for {alias_name}. Received Result: {_ami_id}"
            )

    except botocore.exceptions.ClientError as e:
        return SocaError.GENERIC_ERROR(
            helper=f"ClientError: Unable to get_parameter for {alias_name} due to {e}"
        )

    except Exception as e:
        return SocaError.GENERIC_ERROR(helper=f"Unable to run get_parameter due to {e}")
