# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
This hook reject the job if the user specify invalid security group or IAM roles
Doc:
> https://awslabs.github.io/engineering-development-hub-documentation/documentation/security/use-custom-sgs-roles/
"""

from __future__ import annotations


import logging
from utils.response import SocaResponse
from utils.error import SocaError
from utils.aws.iam_helper import get_instance_profile

logger = logging.getLogger("soca_logger")


def main(
    obj: "SocaHpcHooksValidator", instance_profile_name: str
) -> SocaResponse | SocaError:

    logger.debug(f"Validating IAM Instance Profile {instance_profile_name=}")

    _allowed_instances_profiles = (
        []
        if "allowed_instance_profiles" not in obj.queue_config.keys()
        else obj.queue_config.get("allowed_instance_profiles")
    )

    if isinstance(_allowed_instances_profiles, list) is not True:
        return SocaError.GENERIC_ERROR(
            helper=f"allowed_instance_profiles on {obj.queue_settings_file} must be a list. Detected: {str(type(_allowed_instances_profiles))}"
        )

    if instance_profile_name not in _allowed_instances_profiles:
        return SocaError.GENERIC_ERROR(
            helper=f"IAM Instance Profile group {instance_profile_name} is not authorized for this queue. Approved instance profiles: {_allowed_instances_profiles}.  Contact your SOCA administrator and update {obj.queue_settings_file} if needed."
        )

    # Finally we validate if IAM role exist on AWS
    if (
        get_instance_profile(instance_profile_name=instance_profile_name).success
        is False
    ):
        return SocaError.GENERIC_ERROR(
            helper=f"{instance_profile_name} is not a valid IAM Instance Profile"
        )

    return SocaResponse(success=True, message="Validated IAM instance profile")
