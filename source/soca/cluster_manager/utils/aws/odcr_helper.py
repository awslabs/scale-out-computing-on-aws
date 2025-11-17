# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import Optional, Literal
from datetime import datetime, timedelta
from utils.aws.ssm_parameter_store import SocaConfig
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.ec2_helper import describe_images, describe_subnets
from utils.error import SocaError
from utils.response import SocaResponse
from botocore.exceptions import ClientError


client_ec2 = utils_boto3.get_boto(service_name="ec2").message
logger = logging.getLogger("soca_logger")

def create_capacity_reservation(
    instance_type: str,
    desired_capacity: int,
    subnet_id: str,
    capacity_reservation_name: str,
    end_date_type: Literal["limited", "unlimited"] = "limited",
    end_date: Optional[datetime] = None,
    tenancy: Literal["dedicated", "default"] = "default",
    instance_platform: Optional[str] = None,  # This can be an Literal/Enum - but the list is long
    instance_ami: Optional[str] = None,
    instance_match_criteria: Literal["open", "targeted"] = "open",
) -> SocaResponse:
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-capacity-reservations.html
    # Note: You can use SocaConfig(key="/configuration/FeatureFlags/EnableCapacityReservation").get_value(return_as=bool) to check if EnableCapacityReservation is enabled/disabled (default)

    # Wrapper for non HPC instances.
    logger.info(
        f"Probing ODCR capacity: instance_type={instance_type}, "
        f"desired_capacity={desired_capacity}, subnet_id={subnet_id}, "
        f"tenancy={tenancy}, instance_platform={instance_platform}, instance_ami={instance_ami},"
        f"instance_match_criteria={instance_match_criteria}, end_date_type={end_date_type}, end_date={end_date}"
    )
    _subnet_az = None
    _get_subnet_info = describe_subnets(subnet_ids=[subnet_id])
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

    logger.info(
        f"Requesting capacity reservation for {desired_capacity=} * {instance_type=} in {_subnet_az=}"
    )

    _odcr_tags = [
        {"Key": "Name", "Value": capacity_reservation_name},
        {
            "Key": "soca:ClusterId",
            "Value": SocaConfig(key="/configuration/ClusterId")
            .get_value()
            .get("message"),
        },
        {
            "Key": "soca:CapacityReservationAZ",
            "Value": str(_subnet_az),
        },
        {
            "Key": "soca:CapacityReservationCount",
            "Value": str(desired_capacity),
        },
        {
            "Key": "soca:CapacityReservationInstanceType",
            "Value": str(instance_type),
        },
    ]

    #
    # Provide an expiration date for the ODCR
    # This can be controlled via the kwargs
    # or fallback to defaults of 5min after the request
    #
    _now: datetime = datetime.now()
    _end_date = _now + timedelta(minutes=5)

    if not end_date:
        _end_date = _now + timedelta(minutes=5)
    else:
        if isinstance(end_date, datetime):
            if end_date > _now:
                _end_date = end_date
            else:
                # We got a date in the past - default to now()+5
                _end_date = _now + timedelta(minutes=5)
        else:
            _end_date = _now + timedelta(minutes=5)


    try:
        _request_capacity = client_ec2.create_capacity_reservation(
            InstanceType=instance_type,
            InstancePlatform=instance_platform,
            AvailabilityZone=_subnet_az,
            InstanceCount=desired_capacity,
            Tenancy=tenancy,
            InstanceMatchCriteria=instance_match_criteria,
            EndDateType=end_date_type,
            EndDate=_end_date,  # Errors on None
            TagSpecifications=[
                {"ResourceType": "capacity-reservation", "Tags": _odcr_tags}
            ],
        )
        _reservation_id = _request_capacity.get("CapacityReservation").get(
            "CapacityReservationId"
        )
        logger.info(
            f"Capacity Reservation ID success: {_reservation_id=}, capacity is available, deleting ODCR as we have validated capacity"
        )
        try:
            client_ec2.cancel_capacity_reservation(
                CapacityReservationId=_reservation_id,
            )
            return SocaResponse(
                success=True,
                message="Capacity is available.",
            )
        except Exception as err:
            logger.error(
                f"Unable to cancel capacity reservation {_reservation_id} because of {err} "
            )
            return SocaResponse(
                success=False,
                message=f"Capacity probed successfully with reservation {_reservation_id}, but unable to cancel reservation. You will need to cancel the capacity manually",
            )

    except Exception as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to create capacity reservation due to {e}"
        )
