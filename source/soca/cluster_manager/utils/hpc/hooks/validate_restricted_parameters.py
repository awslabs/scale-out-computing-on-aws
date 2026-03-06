# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


"""
This hook reject the job if the user is not allowed to use the queue
Doc:
> https://awslabs.github.io/scale-out-computing-on-aws-documentation/documentation/security/manage-queue-restricted-parameters/
"""

from __future__ import annotations
import logging
from utils.response import SocaResponse
from utils.error import SocaError

logger = logging.getLogger("soca_logger")


def main(
    obj: "SocaHpcHooksValidator", job_parameters: dict
) -> SocaResponse | SocaError:
    """
    job_parameters: List of job resources associated to the given job (key: value)
    """
    logger.debug(f"Validating Restricted Parameters {job_parameters=}")
    restricted_parameters = (
        []
        if "restricted_parameters" not in obj.queue_config
        else obj.queue_config["restricted_parameters"]
    )

    if isinstance(restricted_parameters, list) is not True:
        return SocaError.GENERIC_ERROR(
            helper=f"restricted_parameters on {obj.queue_settings_file} must be a list. Detected: {restricted_parameters}"
        )

    # Ensure restricted resources configure by cluster admins can't be replaced by users
    for resource_requested in job_parameters:
        if resource_requested in restricted_parameters:
            return SocaError.GENERIC_ERROR(
                helper=f"{resource_requested} is a restricted parameter and can't be configured by the user. Parameters restricted for this queue: {restricted_parameters}"
            )

    return SocaResponse(success=True, message="Validated restricted parameters")
