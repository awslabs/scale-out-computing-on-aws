# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations


import logging
import yaml
from utils.response import SocaResponse
from utils.error import SocaError
from utils.aws.iam_helper import get_instance_profile

logger = logging.getLogger("soca_logger")


def main(
    obj: "SocaHpcHooksValidator", licenses_requested: list[str]
) -> SocaResponse:

    logger.debug(f"Validating Licenses {licenses_requested=}")
    try:
        _queue_reader = open(obj.license_settings_file, "r")
        license_data = yaml.safe_load(_queue_reader)
    except Exception as err:
        raise ValueError(f"Unable to read {obj.license_settings_file} due to {err}")

    for doc in obj.queue_data.values():
        for k, v in doc.items():
            queues = v["queues"]
            if obj.job_queue in queues:
                if "allowed_instance_profiles" not in v.keys():
                    return SocaError.GENERIC_ERROR(
                        helper=f"allowed_instance_profiles is not specified on {obj.queue_settings_file}. See https://awslabs.github.io/scale-out-computing-on-aws-documentation/documentation/security/manage-queue-restricted-parameters/ for examples"
                    )

                if isinstance(v["allowed_instance_profiles"], list) is not True:
                    return SocaError.GENERIC_ERROR(
                        helper=f"allowed_instance_profiles on {obj.queue_settings_file} must be a list. Detected: {str(type(v['allowed_instance_profiles']))}"
                    )

                if instance_profile_name not in v["allowed_instance_profiles"]:
                    return SocaError.GENERIC_ERROR(
                        helper=f"IAM Instance Profile group {instance_profile_name} is not authorized for this queue. Please enable it on {obj.queue_settings_file}. List of valid IAM profile for this queue: {str(v['allowed_instance_profiles'])}"
                    )

    # Finally we validate if all SG exist on AWS
    if (
        get_instance_profile(instance_profile_name=instance_profile_name).success
        is False
    ):
        return SocaError.GENERIC_ERROR(
            helper=f"{instance_profile_name} is not a alid IAM Instance Profile"
        )

    return SocaResponse(success=True, message="Validated IAM instance profile")
