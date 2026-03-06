# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
This hook reject the job if the user specify invalid security group or IAM roles
Doc:
> https://awslabs.github.io/scale-out-computing-on-aws-documentation/documentation/security/use-custom-sgs-roles/
"""

from __future__ import annotations
import logging
from utils.response import SocaResponse
from utils.error import SocaError
from utils.aws.ec2_helper import describe_security_groups

logger = logging.getLogger("soca_logger")


def main(
    obj: "SocaHpcHooksValidator", security_groups: list[str]
) -> SocaResponse | SocaError:

    logger.debug(f"Validating Security groups {security_groups=}")
    if len(security_groups) > 4:
        return SocaError.GENERIC_ERROR(
            helper=f"You can specify a maximum of 4 additional security groups, detected {security_groups}."
        )
    allowed_security_group_ids = (
        []
        if "allowed_security_group_ids" not in obj.queue_config
        else obj.queue_config["allowed_security_group_ids"]
    )

    if isinstance(allowed_security_group_ids, list) is not True:
        return SocaError.GENERIC_ERROR(
            helper=f"allowed_security_group_ids on {obj.queue_settings_file} must be a list. Detected: {allowed_security_group_ids}"
        )

    for sg_id in security_groups:
        if sg_id not in allowed_security_group_ids:
            return SocaError.GENERIC_ERROR(
                helper=f"Security group {sg_id} is not authorized for this queue. Approved security groups: {allowed_security_group_ids}.  Contact your SOCA administrator and update {obj.queue_settings_file} if needed."
            )

    # Finally we validate if the security group IDs specified exist in AWS
    if (
        describe_security_groups(security_groups_ids=security_groups).get("success")
        is False
    ):
        return SocaError.GENERIC_ERROR(
            helper=f"Invalid Security Groups detected in {security_groups}"
        )

    return SocaResponse(success=True, message="Validated security groups")
