# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0  

import os
import sys
from botocore.exceptions import ClientError
import boto3
import logging

cfn_client = boto3.client("cloudformation")
ec2_client = boto3.client("ec2")

logging.getLogger().setLevel(logging.INFO)


def cancel_reservation(reservation_id: str) -> None:
    try:
        logging.info(f"Canceling Capacity Reservation {reservation_id}")
        ec2_client.cancel_capacity_reservation(
            CapacityReservationId=reservation_id,
        )
        logging.info(f"Capacity Reservation {reservation_id} cancelled successfully.")
    except ClientError as e:
        if e.response["Error"]["Code"] == "CapacityReservationNotFound":
            logging.info(f"Capacity Reservation {reservation_id} not found.")
        else:
            logging.fatal(f"Unable to cancel capacity reservation: {e}")


def clean_odcr_assigned_to_stack(stack_name: str) -> None:
    try:
        logging.info(
            f"Cleaning SOCA ODCRs associated to tag:soca:AssociatedCloudformationStackName = {stack_name}..."
        )

        reservations = ec2_client.describe_capacity_reservations(
            Filters=[
                {"Name": "state", "Values": ["active"]},
                {
                    "Name": "tag:soca:AssociatedCloudformationStackName",
                    "Values": [stack_name],
                },
            ]
        )
        logging.info(
            f"Found {len(reservations.get('CapacityReservations'))} ODCRs with tag:soca:AssociatedCloudformationStackName = {stack_name}"
        )

        for res in reservations.get("CapacityReservations", []):
            logging.info(f"Processing {res} ... ")
            _reservation_id = res.get("CapacityReservationId")
            cancel_reservation(reservation_id=_reservation_id)

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logging.fatal(f"Error: {e}, {exc_type}, {fname}, {exc_tb.tb_lineno}")


def clean_orphaned_odcr_on_schedule() -> None:
    try:
        logging.info("Retrieving all ODCR and deleting inactive reservations")
        reservations = ec2_client.describe_capacity_reservations(
            Filters=[{"Name": "state", "Values": ["active"]}]
        )
        logging.info(
            f"Found {len(reservations.get('CapacityReservations'))} reservation in active state"
        )

        for res in reservations.get("CapacityReservations", []):
            _reservation_id = res.get("CapacityReservationId")
            _tags = res.get("Tags", [])
            _stack_name_tag = next(
                (
                    tag["Value"]
                    for tag in _tags
                    if tag["Key"] == "soca:AssociatedCloudformationStackName"
                ),
                None,
            )

            _available_instance_count = res.get("AvailableInstanceCount")
            _total_instance_count = res.get("TotalInstanceCount")

            if _stack_name_tag:
                logging.info(
                    f"ODCR {_reservation_id} has tag soca:AssociatedCloudformationStackName set to {_stack_name_tag}"
                )
                try:
                    _check_stack = cfn_client.describe_stacks(StackName=_stack_name_tag)
                    logging.debug(f"{_check_stack=}")
                    _stack_status = _check_stack["Stacks"][0]["StackStatus"]
                    logging.debug(f"Stack Status; {_stack_status}")
                    if _stack_status == "CREATE_IN_PROGRESS":
                        # we do not cancel reservation is the associated cloudformation stack is active/being provisioned
                        logging.info(
                            f"Associated CloudFormation stack state being created, waiting ... "
                        )
                        continue
                    elif _stack_status == ["CREATE_COMPLETE"]:
                        if _available_instance_count == _total_instance_count:
                            logging.info(
                                f"Associated CloudFormation stack is active and all capacity is provisioned: {_available_instance_count=} / {_total_instance_count=}, we can cancel the reservation ID as it's no longer needed"
                            )
                            cancel_reservation(reservation_id=_reservation_id)
                        else:
                            logging.info(
                                f"Associated CloudFormation stack is active but capacity is not yet fully provisioned: {_available_instance_count=} / {_total_instance_count=}, we can cancel the reservation ID as it's no longer needed, skipping ..."
                            )
                    else:
                        logging.info(
                            f"Associated CloudFormation stack is not active {_stack_status=}, cancelling reservation "
                        )
                        cancel_reservation(reservation_id=_reservation_id)

                except ClientError as e:
                    if "does not exist" in str(e):
                        logging.info(
                            f"{_stack_name_tag} does NOT exist. Cancelling ODCR {_reservation_id}..."
                        )
                        cancel_reservation(reservation_id=_reservation_id)

                    else:
                        logging.fatal(f"Error checking stack: {e}")
                        continue
            else:
                logging.info(
                    f"ODCR {_reservation_id} does NOT have the tag 'soca:AssociatedCloudformationStackName', skipping"
                )
                continue

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logging.fatal(f"Error: {e}, {exc_type}, {fname}, {exc_tb.tb_lineno}")


def lambda_handler(event, context):
    """
    This function cancel orphaned ODCR requested via SOCA if the capacity is manually deleted directly from the AWS console.
    - called via AWS EventBridge when a CloudFormation Stack change state (event stack_name) will be received
    - also called via Schedule to recycle all orphaned ODCR
    """
    _stack_id = event.get(
        "stack_id", None
    )  # EventBridge return the entire ARN e.g: arn:aws:cloudformation:us-west-1:123456789012:stack/stack_name/stack_uuid
    if _stack_id is not None:
        _stack_name = _stack_id.split("/")[-2]  # get stack_name, not stack_uuid
        logging.info(f"Stack name is {_stack_name}")
    else:
        _stack_name = None

    _status = event.get("status", None)
    logging.info(f"Received event Stack name: {_stack_name}, Status: {_status}")

    if _status in ["CREATE_COMPLETE", "CREATE_IN_PROGRESS"]:
        # EventBridge EventPattern is anything-but CREATE_COMPLETE / CREATE_IN_PROGRESS.
        # We add this extra check to ensure we don't cancel the ODCR if there any mis-configuration post-deployent to the EventBridge event
        # if the stack is in active state.
        logging.info(f"Received CloudFormation Stack is in active state, skipping ...")
    else:
        if _stack_name is not None:
            logging.info(
                f"Stack name is not empty, lambda triggered from EventBridge EventPattern, checking ODCR for {_stack_name=}"
            )
            clean_odcr_assigned_to_stack(stack_name=_stack_name)
        else:
            logging.info(
                "Stack name not provisioned, lambda triggered from EventBridge Schedule, iterating through all ODCR and cancelling orphaned ones"
            )
            clean_orphaned_odcr_on_schedule()

    logging.info("Lambda execution completed")
