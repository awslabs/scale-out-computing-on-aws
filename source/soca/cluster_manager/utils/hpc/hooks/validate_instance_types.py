# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations


import logging
from typing import Collection
from utils.response import SocaResponse
from utils.error import SocaError
from utils.aws.ec2_helper import describe_instance_types

logger = logging.getLogger("soca_logger")


def is_allowed_instance_type(
    instance_type: str,
    allowed_instance_types: Collection[str],
    excluded_instance_types: Collection[str],
) -> bool:

    # Sanity check
    if "." not in instance_type:
        return False

    family = instance_type.split(".", 1)[0]

    # Global exclusion
    if "*" in excluded_instance_types:
        return False

    # Exact exclusions
    if instance_type in excluded_instance_types:
        return False

    if family in excluded_instance_types:
        return False

    # Global allow
    if "*" in allowed_instance_types:
        return True

    # Exact allows
    if instance_type in allowed_instance_types:
        return True

    if family in allowed_instance_types:
        return True

    # Default False
    return False


def main(
    obj: "SocaHpcHooksValidator", instance_types: list[str]
) -> SocaResponse | SocaError:
    """
    Validate if instance type is valid
    """
    logger.debug(f"Validating Instance Type {instance_types=}")

    allowed_instance_types = (
        []
        if not obj.queue_config.get("allowed_instance_types")
        else obj.queue_config.get("allowed_instance_types")
    )
    excluded_instance_types = (
        []
        if not obj.queue_config.get("excluded_instance_types")
        else obj.queue_config.get("excluded_instance_types")
    )

    # ensure expected keys are valid lists
    if isinstance(allowed_instance_types, list) is not True:
        return SocaError.GENERIC_ERROR(
            helper=f"allowed_instance_types on {obj.queue_settings_file} must be a list. Detected: {allowed_instance_types}"
        )
    if isinstance(excluded_instance_types, list) is not True:
        return SocaError.GENERIC_ERROR(
            helper=f"excluded_instance_types on {obj.queue_settings_file} must be a list. Detected: {excluded_instance_types}"
        )

    for instance in instance_types:
        logger.debug(f"Validating {instance}")
        if (
            is_allowed_instance_type(
                instance_type=instance,
                allowed_instance_types=allowed_instance_types,
                excluded_instance_types=excluded_instance_types,
            )
            is False
        ):
            if not "." in instance:
                return SocaError.GENERIC_ERROR(
                    helper=f"{instance} is not a valid instance type."
                )
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"{instance} is not allowed for {obj.job_queue}. Allowed instance types/families {allowed_instance_types}, Excluded instance types/families {excluded_instance_types}.  Contact your SOCA administrator and update {obj.queue_settings_file} if needed."
                )

    # Instance Types is valid per queue_settings_file, now verifying if they are real instance type
    # We keep this check at the end to avoid unnecessary AWS API calls
    if describe_instance_types(instance_types=instance_types).get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"{instance_types} is not a valid instance type."
        )
    return SocaResponse(success=True, message="Validated Instance Type")
