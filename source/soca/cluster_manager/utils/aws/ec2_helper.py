# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from typing import Optional
import random
from utils.aws.ssm_parameter_store import SocaConfig
import utils.aws.boto3_wrapper as utils_boto3
from botocore.exceptions import ClientError
from utils.error import SocaError
from utils.response import SocaResponse
from utils.cast import SocaCastEngine
import boto3
import botocore

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
logger = logging.getLogger("soca_logger")


def get_instance_types_by_architecture(instance_type_pattern: list) -> dict:
    """
    This function take a list of EC2 pattern such as c5.large, c6i.* and generate the relevant list of associated instance type
    grouped by architecture:
    {"x86_64": ["instance1", ...], "arm64": [...]}
    """
    logger.info(
        f"Building all supported EC2 instance type based on {instance_type_pattern}"
    )

    if (_is_list := SocaCastEngine(data=instance_type_pattern).cast_as(list)).get(
        "success"
    ):
        _instance_type_pattern = SocaCastEngine(data=_is_list.get("message"))
    else:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to cast {instance_type_pattern} to list"
        )

    _matching_instances = {"x86_64": [], "arm64": []}

    try:
        paginator = client_ec2.get_paginator("describe_instance_types")
        for page in paginator.paginate(
            MaxResults=100,
            Filters=[
                {
                    "Name": "instance-type",
                    "Values": sorted(set(instance_type_pattern)),
                },
            ],
        ):
            for instance_type in page["InstanceTypes"]:
                _instance_type = instance_type["InstanceType"]
                _instance_arch = instance_type["ProcessorInfo"][
                    "SupportedArchitectures"
                ][0]
                _matching_instances[_instance_arch].append(_instance_type)

    except botocore.exceptions.ClientError as e:
        return SocaResponse(
            success=False,
            message=f"Error fetching instance types: {e}. Verify if the instance type and if there is any newer version of boto {boto3.__version__}",
        )

    except Exception as e:
        return SocaResponse(
            success=False,
            message=f"Unexpected error querying describe_instance_types: {e}",
        )

    return SocaResponse(success=True, message=_matching_instances)


def create_capacity_dry_run(launch_parameters: dict) -> SocaResponse:
    """
    Run EC2 RunInstance DryRun to validate basic parameter config
    """
    try:
        logger.debug(f"Trying to perform DryRun with {launch_parameters}")
        if launch_parameters["base_os"] in {"amazonlinux2", "amazonlinux2023"}:
            _ebs_device_name = "/dev/xvda"
        else:
            _ebs_device_name = "/dev/sda1"

        client_ec2.run_instances(
            BlockDeviceMappings=[
                {
                    "DeviceName": _ebs_device_name,
                    "Ebs": {
                        "DeleteOnTermination": True,
                        "VolumeSize": launch_parameters.get("disk_size"),
                        "VolumeType": launch_parameters.get("VolumeType", "gp3"),
                        "Encrypted": True,
                    },
                },
            ],
            MaxCount=1,
            MinCount=1,
            SecurityGroupIds=[launch_parameters["security_group_id"]],
            InstanceType=launch_parameters["instance_type"],
            IamInstanceProfile={"Arn": launch_parameters["instance_profile"]},
            SubnetId=(
                random.choice(launch_parameters["soca_private_subnets"])
                if not launch_parameters["subnet_id"]
                else launch_parameters["subnet_id"]
            ),
            Placement={"Tenancy": launch_parameters["tenancy"]},
            UserData=launch_parameters["user_data"],
            ImageId=launch_parameters["image_id"],
            DryRun=True,
            HibernationOptions={"Configured": launch_parameters["hibernate"]},
        )

    except ClientError as err:
        if err.response["Error"].get("Code") == "DryRunOperation":
            SocaResponse(success=True, message=None)
        else:
            return SocaError.AWS_API_ERROR(
                service_name="ec2",
                helper=f"Unable to launch capacity: {err.response['Error']}",
            )
