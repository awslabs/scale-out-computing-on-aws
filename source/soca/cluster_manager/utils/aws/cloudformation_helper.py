# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
import utils.aws.boto3_wrapper as utils_boto3
from botocore.exceptions import ClientError
from utils.error import SocaError
from utils.response import SocaResponse
from utils.aws.odcr_helper import cancel_capacity_reservation
import botocore


client_cfn = utils_boto3.get_boto(service_name="cloudformation").message
logger = logging.getLogger("soca_logger")


def delete_stack(stack_name: str) -> SocaResponse:
    """
    Helper for CloudFormation delete_stack API
    Also remove associated ODCR if any
    """
    logger.info(f"Received CloudFormation Stack {stack_name=} delete request")

    try:
        client_cfn.delete_stack(StackName=stack_name)
        return SocaResponse(
            success=True, message=f"Stack {stack_name} deleted successfully"
        )
    except ClientError as e:
        if e.response["Error"]["Code"] == "ValidationError":
            return SocaResponse(
                success=True,
                message=f"Stack {stack_name} does not exist. Please check the stack name and try again.",
            )
        else:
            return SocaError.AWS_API_ERROR(
                service_name="cloudformation",
                helper=f"Error while trying to delete {stack_name} because of ClientError {e}",
            )
    except Exception as err:
        return SocaError.AWS_API_ERROR(
            service_name="cloudformation",
            helper=f"Error while trying to delete {stack_name} because of {err}",
        )


def create_stack(
    stack_name: str, template_body: str, tags: dict, on_failure: str = "DO_NOTHING"
) -> SocaResponse:

    logger.info(
        f"Received CloudFormation Stack {stack_name=}, {tags=}, {on_failure=} create request. Enable SOCA_DEBUG to see the template body"
    )
    logger.debug(f"Template Body {template_body=}")

    if on_failure not in ["DELETE", "ROLLBACK", "DO_NOTHING"]:
        return SocaError.GENERIC_ERROR(
            "on_failure for create_stack must be either DELETE, ROLLBACK or DO_NOTHING"
        )

    _capacity_reservation_id = None
    for tag in tags:
        if tag.get("Key") == "soca:CapacityReservationId":
            _capacity_reservation_id = tag.get("Value")

    if _capacity_reservation_id is None:
        logger.info("No ODCR found for this stack")
    else:
        logger.info(f"ODCR for this stack: {_capacity_reservation_id}")

    try:
        client_cfn.create_stack(
            StackName=stack_name,
            TemplateBody=template_body,
            Tags=tags,
            OnFailure=on_failure,
        )
        return SocaResponse(
            success=True, message=f"Stack {stack_name} created successfully"
        )
    except botocore.exceptions.ClientError as e:
        logger.info("Error when trying to create stack in CloudFormation")

        if _capacity_reservation_id is not None:
            cancel_capacity_reservation(reservation_id=_capacity_reservation_id)

        if e.response["Error"]["Code"] == "AlreadyExistsException":
            return SocaError.AWS_API_ERROR(
                service_name="cloudformation",
                helper=f"{stack_name} already exist. Please use a different name of wait a little longer if you just delete a stack with the same name.",
            )

        else:
            return SocaError.AWS_API_ERROR(
                service_name="cloudformation",
                helper=f"Error while trying to provision {stack_name} because of {e}",
            )

    except Exception as e:
        # if _capacity_reservation_id:
        #    for _capacity_reservation_id in _capacity_reservation_ids:
        #        cancel_capacity_reservation(reservation_id=_capacity_reservation_id)

        return SocaError.AWS_API_ERROR(
            service_name="cloudformation",
            helper=f"Error while trying to provision {stack_name} because of {e}",
        )
