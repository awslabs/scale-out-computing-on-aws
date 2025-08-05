# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import Optional, Literal
from utils.aws.ssm_parameter_store import SocaConfig
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.response import SocaResponse

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
logger = logging.getLogger("soca_logger")


def check_existing_capacity_reservation(
    stack_name: str,
    instance_type: str,
    availability_zone: str,
    instance_platform: str,
    instance_count: int,
) -> SocaResponse:
    """
    Checks for an existing active EC2 On-Demand Capacity Reservation (ODCR) that matches
    the specified parameters and has enough available capacity.

    This function queries EC2 capacity reservations filtered by state, instance type,
    availability zone, platform, and a CloudFormation stack tag. If an active reservation
    exists with sufficient capacity, it returns the reservation ID. Otherwise, it returns
    None in the message field of the SocaResponse, indicating that a new reservation
    should be created.

    Args:
        stack_name (str): Name of the CloudFormation stack associated with the capacity reservation.
        instance_type (str): The EC2 instance type (e.g., 'c5.large').
        availability_zone (str): The target Availability Zone for the reservation.
        instance_platform (str): The platform type of the EC2 instances
                                 (e.g., 'Linux/UNIX', 'Windows').
        instance_count (int): The number of EC2 instances required.

    Returns:
        SocaResponse: An object containing:
            - success (bool): Always True for this function.
            - message (str or None): The ID of the valid capacity reservation if found,
              otherwise None.
    """
    logger.info(
        f"Checking if an already active reservation ID exist for {locals()} with available capacity"
    )
    _check_existing_reservation = client_ec2.describe_capacity_reservations(
        Filters=[
            {"Name": "state", "Values": ["active"]},
            {"Name": "instance-type", "Values": [instance_type]},
            {"Name": "availability-zone", "Values": [availability_zone]},
            {"Name": "instance-platform", "Values": [instance_platform]},
            {
                "Name": "tag:soca:AssociatedCloudFormationStackName",
                "Values": [stack_name],
            },
        ]
    )
    _reservation_id = None
    if len(_check_existing_reservation.get("CapacityReservations")) > 0:
        _available_instance_count = _check_existing_reservation.get(
            "CapacityReservations"
        )[0].get("AvailableInstanceCount")

        if _available_instance_count < instance_count:
            logger.info(
                f"Capacity Reservation found for the given stack, however it only has {_available_instance_count} available instance but we need {instance_count}"
            )
        else:
            _reservation_id = _check_existing_reservation.get("CapacityReservations")[
                0
            ].get("CapacityReservationId")
            logger.info(
                f"A valid ODCR reservation already exist for {stack_name} with info {_check_existing_reservation=}"
            )
    else:
        logger.info(
            f"No Active ODCR reservation found for {stack_name}. Will create a new one"
        )

    return SocaResponse(success=True, message=_reservation_id)


def modify_instance_capacity_reservation_attributes(
    instance_id: str, reservation_id: str
) -> SocaResponse:
    """
    Re-allocates an EC2 instance to a specific On-Demand Capacity Reservation (ODCR).

    This function modifies the capacity reservation attributes of the specified EC2 instance,
    directing it to target a given ODCR by ID. It sets the instance's reservation preference
    to use only specified capacity reservations.

    Args:
        instance_id (str): The ID of the EC2 instance to be re-allocated.
        reservation_id (str): The ID of the target capacity reservation.

    Returns:
        SocaResponse: An object indicating the result of the reallocation:
            - success (bool): True if the modification succeeded, False otherwise.
            - message (str): Success message or error description.
    """
    logger.info(
        f"Receive ODCR re-allocation request for {instance_id=} to {reservation_id=}"
    )
    try:
        client_ec2.modify_instance_capacity_reservation_attributes(
            InstanceId=instance_id,
            CapacityReservationSpecification={
                "CapacityReservationPreference": "capacity-reservations-only",
                "CapacityReservationTarget": {
                    "CapacityReservationId": reservation_id,
                },
            },
        )
        return SocaResponse(
            success=True,
            message=f"Successfully re-allocated {instance_id=} to {reservation_id=}",
        )
    except Exception as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to re-allocate {reservation_id=} to {instance_id=}  due to {e}"
        )


def cancel_capacity_reservation(reservation_id: str) -> SocaResponse:
    """
    Cancels an existing EC2 On-Demand Capacity Reservation (ODCR) by reservation ID.

    This function submits a cancellation request to AWS for the specified capacity reservation.
    If successful, it returns a confirmation message; otherwise, it returns an error.

    Args:
        reservation_id (str): The ID of the capacity reservation to cancel.

    Returns:
        SocaResponse: An object indicating the result of the cancellation:
            - success (bool): True if the cancellation succeeded, False otherwise.
            - message (str): Success message or error description.
    """
    logger.info(f"Receive ODCR cancellation request for {reservation_id=}")
    try:
        client_ec2.cancel_capacity_reservation(
            CapacityReservationId=reservation_id,
        )
        return SocaResponse(
            success=True, message="Submitted ODCR have been cancelled successfully"
        )

    except Exception as e:
        return SocaError.GENERIC_ERROR(helper=f"Unable to cancel ODCR due to {e}")


def cancel_capacity_reservation_by_stack(stack_name: str) -> SocaResponse:
    """
    Cancels active EC2 On-Demand Capacity Reservations (ODCRs) associated with a given CloudFormation stack.

    This function searches for active capacity reservations that are tagged with the specified
    CloudFormation stack name. If found, it attempts to cancel the reservations. This is typically
    used when an associated resource, like a VDI desktop, is stopped.

    Args:
        stack_name (str): The name of the CloudFormation stack associated with the capacity reservations.

    Returns:
        SocaResponse: An object indicating the result of the cancellation:
            - success (bool): True if a reservation was successfully cancelled, False otherwise.
            - message (str): Success message or error description.
    """
    logger.info(
        f"Receive ODCR cancellation request for cloudformation stack {stack_name=}"
    )
    try:
        reservations = client_ec2.describe_capacity_reservations(
            Filters=[
                {"Name": "state", "Values": ["active"]},
                {
                    "Name": "tag:soca:AssociatedCloudFormationStackName",
                    "Values": [stack_name],
                },
            ]
        )

        logging.info(
            f"Found {len(reservations.get('CapacityReservations'))} ODCRs with tag:soca:AssociatedCloudFormationStackName = {stack_name}"
        )

        for res in reservations.get("CapacityReservations", []):
            logging.info(f"Processing {res} ... ")
            _reservation_id = res.get("CapacityReservationId")
            try:
                client_ec2.cancel_capacity_reservation(
                    CapacityReservationId=_reservation_id,
                )
                return SocaResponse(
                    success=True,
                    message="Submitted ODCR have been cancelled successfully",
                )

            except Exception as e:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to cancel_capacity_reservation_by_stack ODCR due to {e}"
                )
    except Exception as e:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to cancel_capacity_reservation_by_stack due to {e}"
        )


def create_capacity_reservation_vdi(
    instance_type: str,
    capacity_reservation_name: str,
    subnet_id: str,
    tenancy: Literal["dedicated", "default"],
    instance_platform: Optional[str] = None,
    instance_ami: Optional[str] = None,
) -> SocaResponse:
    # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-capacity-reservations.html
    # Note: You can use SocaConfig(key="/configuration/FeatureFlags/EnableCapacityReservation").get_value(return_as=bool) to check if EnableCapacityReservation is enabled/disabled (default)
    """
    Creates an EC2 On-Demand Capacity Reservation (ODCR) for a single instance in the
    specified availability zone, based on subnet and instance attributes.

    This function is primarily used for reserving capacity for VDI (Virtual Desktop
    Infrastructure) use cases. It resolves the availability zone from the subnet, determines
    the platform (either provided directly or inferred from the AMI), checks for existing
    reservations, and creates a new reservation if necessary.

    Args:
        instance_type (str): The EC2 instance type to reserve (e.g., 't3.large').
        capacity_reservation_name (str): The name (used as a tag) associated with the capacity reservation.
        subnet_id (str): The ID of the subnet used to derive the availability zone.
        tenancy (Literal["dedicated", "default"]): The tenancy model for the reservation.
        instance_platform (Optional[str]): The platform (e.g., 'Linux/UNIX'). Optional if `instance_ami` is provided.
        instance_ami (Optional[str]): The AMI ID used to infer the platform if `instance_platform` is not provided.

    Returns:
        SocaResponse: An object indicating the result of the reservation request:
            - success (bool): True if the reservation was created or an existing one was found.
            - message (str): The reservation ID, or an error message if creation failed.
    """

    logger.info(f"Received ODCR create_capacity_reservation_vdi request for {locals()}")

    _subnet_az = None
    try:
        _get_az = client_ec2.describe_subnets(SubnetIds=[subnet_id])
        for _subnet in _get_az["Subnets"]:
            _subnet_az = _subnet["AvailabilityZone"]
        if _subnet_az is None:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve AZ for subnet {subnet_id=}"
            )
    except Exception as err:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to retrieve AZ for subnet {subnet_id=} due to {err}"
        )

    logger.info(f"ODCR {subnet_id=} AZ is {_subnet_az}")

    if instance_platform is None:
        logger.info("Instance platform not specified, retrieving it via instance mi")
        if instance_ami:
            _get_platform = client_ec2.describe_images(ImageIds=[instance_ami])
            instance_platform = _get_platform["Images"][0].get(
                "PlatformDetails", "Linux/UNIX"
            )
            logger.info(f"Detected Platform: {instance_platform}")
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Either instance_platform or instance_ami must be specified"
            )

    logger.info(
        f"Requesting capacity reservation for 1 * {instance_type=} in {_subnet_az=}"
    )
    _odcr_tags = [
        {
            "Key": "Name",
            "Value": str(
                capacity_reservation_name
            ),  # e.g: soca-<cluster>-compute-node-xxx / soca-cluster-desktop-xxx
        },
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
            "Value": "1",
        },
        {
            "Key": "soca:CapacityReservationInstanceType",
            "Value": str(instance_type),
        },
        {
            "Key": "soca:AssociatedCloudFormationStackName",
            "Value": str(capacity_reservation_name),
        },
    ]

    # As a security measure, we first check if an un-used reservation ID does not already exist:
    _check_existing_capacity_reservation = check_existing_capacity_reservation(
        stack_name=capacity_reservation_name,
        instance_type=instance_type,
        instance_platform=instance_platform,
        availability_zone=_subnet_az,
        instance_count=1,
    )
    if _check_existing_capacity_reservation.get("message") is not None:
        return SocaResponse(
            success=True, message=_check_existing_capacity_reservation.get("message")
        )
    else:
        try:
            _request_capacity = client_ec2.create_capacity_reservation(
                InstanceType=instance_type,
                InstancePlatform=instance_platform,
                AvailabilityZone=_subnet_az,
                InstanceCount=1,
                Tenancy=tenancy,
                InstanceMatchCriteria="targeted",
                EndDateType="unlimited",
                TagSpecifications=[
                    {"ResourceType": "capacity-reservation", "Tags": _odcr_tags}
                ],
            )
            _reservation_id = _request_capacity.get("CapacityReservation").get(
                "CapacityReservationId"
            )
            logger.info(f"Capacity Reservation ID: {_reservation_id=}")
            return SocaResponse(
                success=True,
                message=_reservation_id,
            )

        except Exception as e:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to create capacity reservation due to {e}"
            )


def create_capacity_reservation_hpc(
    instance_type: str,
    instance_count: int,
    capacity_reservation_name: str,
    subnet_ids: list,
    tenancy: Literal["dedicated", "default"],
    instance_platform: Optional[str] = None,
    instance_ami: Optional[str] = None,
    placement_group_arn: Optional[str] = None,
) -> SocaResponse:

    logger.info(f"Received ODCR create_capacity_reservation_hpc request for {locals()}")
    _capacity_reservation_ids = []
    _subnets_az_mapping = {}
    _errors = []
    if placement_group_arn is not None:
        # placement_group_arn is not none, checking if the placement group exist/is valid
        try:
            client_ec2.describe_placement_groups(
                GroupNames=[placement_group_arn.split("/")[-1]]
            )
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Invalid placement_group_arn {placement_group_arn}. {err}"
            )

    # Ideally, cache this on Redis
    for subnet in subnet_ids:
        _get_az = client_ec2.describe_subnets(SubnetIds=subnet_ids)
        for _subnet in _get_az["Subnets"]:
            if subnet in _subnets_az_mapping.keys():
                pass
            else:
                _subnets_az_mapping[subnet] = _subnet["AvailabilityZone"]

    logger.info(f"ODCR SubnetAZ Mapping: {_subnets_az_mapping}")

    if not instance_platform:
        logger.info("Instance platform not specified, retrieving it via instance mi")
        if instance_ami:
            _get_platform = client_ec2.describe_images(ImageIds=[instance_ami])
            instance_platform = _get_platform["Images"][0].get(
                "PlatformDetails", "Linux/UNIX"
            )
            logger.info(f"Detected Platform: {instance_platform}")
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Either instance_platform or instance_ami must be specified"
            )

    try:
        # Instance Distribution per AZ
        # eg: 100 instances for 3 subnets, distribution will be 34 33 33
        _instance_per_az = instance_count // len(_subnets_az_mapping.keys())
        _remainder = instance_count % len(_subnets_az_mapping.keys())

        for index, (subnet_id, subnet_az) in enumerate(_subnets_az_mapping.items()):
            _instance_count = (
                _instance_per_az + 1 if index < _remainder else _instance_per_az
            )
            logger.info(
                f"Requesting capacity reservation for {_instance_count=} * {instance_type=} in {subnet_az=} for {subnet_id=}"
            )

            try:
                _odcr_tags = [
                    {
                        "Key": "Name",
                        "Value": str(
                            capacity_reservation_name
                        ),  # e.g: soca-<cluster>-compute-node-xxx / soca-cluster-desktop-xxx
                    },
                    {
                        "Key": "soca:ClusterId",
                        "Value": SocaConfig(key="/configuration/ClusterId")
                        .get_value()
                        .get("message"),
                    },
                    {
                        "Key": "soca:CapacityReservationAZ",
                        "Value": str(subnet_az),
                    },
                    {
                        "Key": "soca:CapacityReservationCount",
                        "Value": str(_instance_count),
                    },
                    {
                        "Key": "soca:CapacityReservationInstanceType",
                        "Value": str(instance_type),
                    },
                    {
                        "Key": "soca:AssociatedCloudFormationStackName",
                        "Value": str(capacity_reservation_name),
                    },
                ]

                if placement_group_arn is None:
                    _request_capacity = client_ec2.create_capacity_reservation(
                        InstanceType=instance_type,
                        InstancePlatform=instance_platform,
                        AvailabilityZone=subnet_az,
                        InstanceCount=_instance_count,
                        Tenancy=tenancy,
                        InstanceMatchCriteria="targeted",
                        EndDateType="unlimited",
                        TagSpecifications=[
                            {"ResourceType": "capacity-reservation", "Tags": _odcr_tags}
                        ],
                    )
                else:
                    _request_capacity = client_ec2.create_capacity_reservation(
                        InstanceType=instance_type,
                        InstancePlatform=instance_platform,
                        AvailabilityZone=subnet_az,
                        InstanceCount=_instance_count,
                        Tenancy=tenancy,
                        InstanceMatchCriteria="targeted",
                        PlacementGroupArn=placement_group_arn,
                        EndDateType="unlimited",
                        TagSpecifications=[
                            {"ResourceType": "capacity-reservation", "Tags": _odcr_tags}
                        ],
                    )
                _capacity_reservation_ids.append(
                    _request_capacity.get("CapacityReservation").get(
                        "CapacityReservationId"
                    )
                )

                logger.info(f"Capacity Reservation: {_capacity_reservation_ids}")

            except Exception as e:
                _errors.append(
                    f"create_capacity_reservation API returned an error: {e}"
                )

    except Exception as e:
        _errors.append(f"Error creating capacity reservation: {e}")

    if _errors:
        logger.info(
            f"on-demand capacity reservation errors Detected: {_errors}, deleting pre-created reservation if any: {_capacity_reservation_ids=}"
        )
        for res in _capacity_reservation_ids:
            cancel_capacity_reservation(reservation_id=res)

        return SocaError.GENERIC_ERROR(helper=f"{_errors}")

    else:
        return SocaResponse(
            success=True,
            message=_capacity_reservation_ids,
        )
