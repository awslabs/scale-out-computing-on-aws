# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import Optional, Literal
from datetime import datetime, timedelta, timezone
from utils.config import SocaConfig
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.ec2_helper import (
    describe_images,
    describe_subnets,
    describe_capacity_reservations,
)
from utils.error import SocaError
from utils.response import SocaResponse
from utils.validators import Validators
from botocore.exceptions import ClientError
from utils.datamodels.hpc.shared.job_resources import (
    SocaCapacityReservation,
)


client_ec2 = utils_boto3.get_boto(service_name="ec2").message
logger = logging.getLogger("soca_logger")


def get_reservation_info_soca_capacity_reservation(
    capacity_reservation_id: str,
) -> SocaCapacityReservation:
    logger.info(
        f"Trying to cast {capacity_reservation_id=} to SocaCapacityReservation format"
    )
    _get_capacity_reservation = describe_capacity_reservations(
        capacity_reservation_ids=[capacity_reservation_id]
    )
    if _get_capacity_reservation.get("success"):
        _reservation_info = _get_capacity_reservation.get("message")[
            "CapacityReservations"
        ][0]
        _soca_response = SocaCapacityReservation(
            reservation_exist=True,
            reservation_id=capacity_reservation_id,
            instance_type=_reservation_info.get("InstanceType"),
            availability_zone=_reservation_info.get("AvailabilityZone"),
            availability_zone_id=_reservation_info.get("AvailabilityZoneId"),
            state=_reservation_info.get("State"),
            total_instance_count=_reservation_info.get("TotalInstanceCount"),
            available_instance_count=_reservation_info.get("AvailableInstanceCount"),
            instance_platform=_reservation_info.get("InstancePlatform"),
            reservation_type=_reservation_info.get(
                "ReservationType", "odcr"
            ),  # note: empty if odcr, otherwise capacity-block
        )
    else:
        logger.error(
            f"Unable to get {capacity_reservation_id=} because of {_get_capacity_reservation}"
        )
        _soca_response = SocaCapacityReservation(
            reservation_exist=False,
            reservation_id=capacity_reservation_id,
        )

    logger.info(f"Capacity Reservation Info: {_soca_response}")
    return _soca_response

def validate_existing_capacity_reservation(
    capacity_reservation: SocaCapacityReservation,
    instance_type: str,
    desired_capacity: int,
    instance_ami: str,
    subnet_id: str,
) -> SocaResponse:
    """
    Validate request desired capacity/instance platform/subnet/instance type and ensure it match an existing capacity reservation ID
    """
    _reservation_info = capacity_reservation
    if _reservation_info.reservation_exist is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Capacity reservation {_reservation_info.reservation_id} does not exist"
        )

    _get_subnet_info = describe_subnets(subnet_ids=[subnet_id])
    if _get_subnet_info.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to retrieve subnet information: {_get_subnet_info.get('message')}"
        )
    else:
        _subnet_az = (
            _get_subnet_info.get("message")
            .get("Subnets", [])[0]
            .get("AvailabilityZone")
        )
        logger.info(f"Detected subnet AZ: {_subnet_az}")

    _check_ami_platform = describe_images(image_ids=[instance_ami])
    if _check_ami_platform.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to retrieve instance information: {_check_ami_platform.get('message')}"
        )
    else:
        logger.info(f"Detected AMI: {_check_ami_platform.get('message')}")
        instance_platform = (
            _check_ami_platform.get("message")
            .get("Images", [])[0]
            .get("PlatformDetails", "Linux/UNIX")
        )
        logger.info(f"Detected Platform: {instance_platform}")

    _reservation_type = _reservation_info.reservation_type
    _reservation_id = _reservation_info.reservation_id
    _reservation_az = _reservation_info.availability_zone
    _reservation_available_instance_count = _reservation_info.available_instance_count
    _reservation_instance_type = _reservation_info.instance_type
    _reservation_state = _reservation_info.state
    _reservation_instance_platform = _reservation_info.instance_platform

    if (
        _reservation_type is None
        or _reservation_id is None
        or _reservation_az is None
        or _reservation_available_instance_count is None
        or _reservation_instance_type is None
        or _reservation_state is None
    ):
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to retrieve all required information from capacity reservation: {_reservation_info}. Capacity exist but at least one require entry is None"
        )
    if _reservation_state != "active":
        return SocaError.GENERIC_ERROR(
            helper=f"Capacity reservation {_reservation_id} is not active. Detected {_reservation_state}"
        )
    if instance_type != _reservation_instance_type:
        return SocaError.GENERIC_ERROR(
            helper=f"Instance type {instance_type} does not match allowed instances on for {_reservation_id}: {_reservation_instance_type}"
        )

    if desired_capacity > _reservation_available_instance_count:
        return SocaError.GENERIC_ERROR(
            helper=f"Desired capacity {desired_capacity} is greater than available capacity on {_reservation_id}: {_reservation_available_instance_count}"
        )

    if instance_platform != _reservation_instance_platform:
        return SocaError.GENERIC_ERROR(
            helper=f"Instance platform {instance_platform} does not match allowed instance platform on {_reservation_id}: {_reservation_instance_platform}"
        )

    if _subnet_az != _reservation_az:
        return SocaError.GENERIC_ERROR(
            helper=f"Capacity reservation {_reservation_id} was created in a different AZ than the requested subnet: {_subnet_az} != {_reservation_az}"
        )

    logger.info(
        f"Capacity reservation {_reservation_id} is valid, {_reservation_type=}"
    )

    return SocaResponse(
        success=True,
        message=_reservation_info,
    )


def cancel_reservation(reservation_id: str) -> SocaResponse:
    try:
        logging.info(f"Canceling Capacity Reservation {reservation_id}")
        client_ec2.cancel_capacity_reservation(
            CapacityReservationId=reservation_id,
        )
        logging.info(f"Capacity Reservation {reservation_id} cancelled successfully.")

    except ClientError as e:
        if e.response["Error"]["Code"] == "CapacityReservationNotFound":
            logging.info(
                f"Capacity Reservation {reservation_id} not found, ignoring ...."
            )
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to cancel capacity reservation: {e}"
            )
    return SocaResponse(
        success=True,
        message=f"Capacity Reservation {reservation_id} not found, ignoring ....",
    )


def create_capacity_reservation(
    instance_type: str,
    desired_capacity: int,
    subnet_id: str,
    capacity_reservation_name: str,
    probe_capacity_only: bool,  # if true, only validate capacity and cancel the reservation right away
    end_date_type: Literal["limited", "unlimited"] = "limited",
    end_date: Optional[datetime] = None,
    tenancy: Literal["dedicated", "default"] = "default",
    instance_platform: Optional[
        str
    ] = None,  # This can be an Literal/Enum - but the list is long
    instance_ami: Optional[str] = None,
    instance_match_criteria: Literal["open", "targeted"] = "open",
    placement_group_arn: Optional[str] = None,
) -> SocaResponse:
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-capacity-reservations.html
    # Note: You can use SocaConfig(key="/configuration/FeatureFlags/EnableCapacityReservation").get_value(return_as=bool) to check if EnableCapacityReservation is enabled/disabled (default)

    logger.info(
        f"Checking for available ODCR capacity: {instance_type=}, {desired_capacity=}, {subnet_id=}, {tenancy=}, {instance_platform=}, {instance_ami=},{instance_match_criteria=}, {end_date_type=}, {end_date=}, {probe_capacity_only=}, {placement_group_arn=}"
    )
    _subnet_az = None
    _get_subnet_info = describe_subnets(subnet_ids=[subnet_id])
    _default_capacity_probing_cr_duration = 2  # For how many minutes will the CR be valid before AWS automatically cancels it when doing a simple capacity probing. Note that SOCA will try to cancel it right after submitting the request. This delay is just an safety measure in case in case the first cancel attempt fail for any reason.
    _default_capacity_cr_duration = 5  # For how many minutes will the CR be valid before AWS automatically cancels it. Note that SOCA may cancel it sooner if possible.

    if _get_subnet_info.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to retrieve subnet information: {_get_subnet_info.get('message')}"
        )
    else:
        _subnet_az = _get_subnet_info.get("message")["Subnets"][0]["AvailabilityZone"]

    logger.info(f"{subnet_id=} AZ is {_subnet_az}")

    if instance_platform is None:
        logger.info("Instance platform not specified, retrieving it via instance AMI")
        if instance_ami:
            _check_ami_platform = describe_images(image_ids=[instance_ami])
            if _check_ami_platform.get("success") is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to retrieve instance information: {_check_ami_platform.get('message')}"
                )
            else:
                logger.info(f"Detected AMI: {_check_ami_platform.get('message')}")
                instance_platform = _check_ami_platform.get("message")["Images"][0].get(
                    "PlatformDetails", "Linux/UNIX"
                )
            logger.info(f"Detected Platform: {instance_platform}")
        else:
            return SocaError.GENERIC_ERROR(
                helper="Either instance_platform or instance_ami must be specified"
            )

    _soca_cluster_id = (
        SocaConfig(key="/configuration/ClusterId").get_value().get("message")
    )

    _odcr_tags = [
        {"Key": "Name", "Value": capacity_reservation_name},
        {"Key": "soca:ClusterId", "Value": _soca_cluster_id},
        {
            "Key": "soca:CapacityReservationAZ",
            "Value": str(_subnet_az),
        },
        {
            "Key": "soca:ValidatedSubnetId",
            "Value": str(subnet_id),
        },
        {
            "Key": "soca:CapacityReservationCount",
            "Value": str(desired_capacity),
        },
        {
            "Key": "soca:CapacityReservationInstanceType",
            "Value": str(instance_type),
        },
        {"Key": "soca:AssociatedStackId", "Value": capacity_reservation_name},
    ]

    # Provide an expiration date for the ODCR
    # This can be controlled via the kwargs
    if not end_date:
        _now = datetime.now(timezone.utc)
        if probe_capacity_only is True:
            # short TTL as we don't actually need to keep the reservation active
            # note: we submit a cancel_capacity_reservation()
            logger.info(
                f"end_date is not specified, but probe_capacity_only is True. CR expirate date will be set to now + 2 minute: {end_date}"
            )
            end_date = _now + timedelta(minutes=_default_capacity_probing_cr_duration)
        else:
            # Longer TTL as we need the capacity reservation to be active until the capacity/fleet is provisioned as the CR ID will be mapped to the CloudFormation request
            logger.info(
                f"end_date is not specified, but probe_capacity_only is False. CR expirate date will be set to now + 5 minutes to ensure capacity has the time to be provisioned: {end_date}"
            )
            end_date = _now + timedelta(minutes=_default_capacity_cr_duration)
    else:
        # end_date is provided
        if Validators.is_datetime(end_date) is False:
            return SocaError.GENERIC_ERROR(
                helper=f"end_date must be a datetime object, detected {end_date} of type {type(end_date)}"
            )

        if Validators.is_future_datetime(end_date) is False:
            return SocaError.GENERIC_ERROR(
                helper=f"end_date must be a future datetime, detected {end_date}"
            )

    try:
        if placement_group_arn is not None:
            _request_capacity = client_ec2.create_capacity_reservation(
                InstanceType=instance_type,
                InstancePlatform=instance_platform,
                AvailabilityZone=_subnet_az,
                InstanceCount=desired_capacity,
                Tenancy=tenancy,
                InstanceMatchCriteria=instance_match_criteria,
                EndDateType=end_date_type,
                EndDate=end_date,  # Errors on None
                TagSpecifications=[
                    {"ResourceType": "capacity-reservation", "Tags": _odcr_tags}
                ],
                PlacementGroupArn=placement_group_arn,  # Errors on None
            )
        else:
            _request_capacity = client_ec2.create_capacity_reservation(
                InstanceType=instance_type,
                InstancePlatform=instance_platform,
                AvailabilityZone=_subnet_az,
                InstanceCount=desired_capacity,
                Tenancy=tenancy,
                InstanceMatchCriteria=instance_match_criteria,
                EndDateType=end_date_type,
                EndDate=end_date,  # Errors on None
                TagSpecifications=[
                    {"ResourceType": "capacity-reservation", "Tags": _odcr_tags}
                ],
            )
        _reservation_id = _request_capacity.get("CapacityReservation").get(
            "CapacityReservationId"
        )
        logger.info(
            f"Capacity Reservation ID success: {_reservation_id=}, capacity is available"
        )
        if probe_capacity_only is True:
            logger.info("probe_capacity_only is True, cancelling capacity reservation")
            try:
                client_ec2.cancel_capacity_reservation(
                    CapacityReservationId=_reservation_id,
                )

            except Exception as err:
                logger.error(
                    f"Unable to cancel capacity reservation {_reservation_id} because of {err}, but Capacity Reservation will be automatically expired at {end_date}"
                )

            # capacity probing only, CR ID no longer exist
            return SocaResponse(
                success=True,
                message=SocaCapacityReservation(
                    reservation_id=_reservation_id,
                    reservation_exist=False,
                    instance_type=instance_type,
                    availability_zone=_subnet_az,
                    state="cancelled",
                    total_instance_count=desired_capacity,
                    available_instance_count=desired_capacity,
                    instance_platform=instance_platform,
                ),
            )

        else:
            logger.info(
                f"Capacity available. {probe_capacity_only=} so {_reservation_id=} is not cancelled, returning reservation ID"
            )
            return SocaResponse(
                success=True,
                message=SocaCapacityReservation(
                    reservation_id=_reservation_id,
                    reservation_exist=True,
                    instance_type=instance_type,
                    availability_zone=_subnet_az,
                    state="active",
                    total_instance_count=desired_capacity,
                    available_instance_count=desired_capacity,
                    instance_platform=instance_platform,
                ),
            )

    except Exception as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to create capacity reservation due to {e}"
        )
