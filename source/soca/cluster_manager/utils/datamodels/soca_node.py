# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from typing import Literal, List, Optional, Dict
from datetime import datetime
from pydantic import BaseModel, ConfigDict
from utils.datamodels.hpc.scheduler import (
    SocaHpcScheduler,
)
import logging
from enum import Enum

logger = logging.getLogger("soca_logger")


class SocaNodeType(str, Enum):
    COMPUTE_NODE = "compute_node"
    LOGIN_NODE = "login_node"
    DCV_NODE = "dcv_node"
    UNKNOWN = "unknown"


class SocaNode(BaseModel):
    ### Important ###
    # SocaNode does not contains ALL elements from https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeInstances.html -> https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_Instance.html
    # If you need all elements (aka: raw API response)
    #  > utils.aws.ec2_helper.describe_instances(...) or utils.aws.ec2_helper.describe_instances_paginate(...)
    # If you are ok with SocaNode
    #  > utils.aws.ec2_helper.describe_instances_as_soca_nodes(...)

    # SOCA Specific helpers
    job_id: Optional[str] = None
    job_queue: Optional[str] = None
    stack_id: Optional[str] = None
    cluster_id: Optional[str] = None
    scheduler_info: Optional[SocaHpcScheduler] = None
    keep_forever: Optional[bool] = False
    terminate_when_idle: Optional[int] = 0

    # Some Attributes from AWS response
    architecture: Literal["i386", "x86_64", "arm64", "x86_64_mac", "arm64_mac"]
    availability_zone: str
    iam_instance_profile_arn: str
    image_id: str
    instance_id: str
    instance_state_name: Literal[
        "pending", "running", "stopping", "stopped", "shutting-down", "terminated"
    ]
    instance_type: str
    launch_time: datetime
    private_dns_name: str
    private_ip_address: str
    subnet_id: str
    vpc_id: str
    tags: Optional[List[Dict[str, str]]] = None
    platform: Optional[Literal["Windows", "Linux"]] = None
    root_device_name: Optional[str] = None
    root_device_type: Optional[Literal["ebs", "instance-store"]] = None
    block_device_mappings: Optional[List[dict]] = None
    cpu_options: Optional[dict] = None  # ThreadsPerCore, CoreCount
    ebs_optimized: Optional[bool] = None
    encryption_in_transit_supported: Optional[bool] = None
    hibernation_options: Optional[dict] = None
    instance_lifecycle: Optional[Literal["spot", "scheduled", "capacity-block"]] = None
    metadata_options: Optional[dict] = None  # HTTP tokens, tags, endpoint settings
    monitoring: Optional[dict] = None  # CloudWatch monitoring status
    network_interfaces: Optional[List[dict]] = None
    outpost_arn: Optional[str] = None
    placement_group_name: Optional[str] = None
    public_ip_address: Optional[str] = None
    public_dns_name: Optional[str] = None
    security_groups: Optional[List[dict]] = None
    state_reason: Optional[dict] = None
    state_transition_reason: Optional[str] = None
    capacity_reservation_id: Optional[str] = None
    key_name: Optional[str] = None
    capacity_block_id: Optional[str] = None

    @classmethod
    def from_ec2_instance(
        cls, instance: dict, scheduler_info: Optional[SocaHpcScheduler] = None
    ):
        """
        Create a SocaNode from a boto3 describe_instances response dict (Reservations.Instances)
        See utils.aws.ec2_helper.describe_instances_as_soca_nodes function or more details
        """

        logger.debug(
            f"Creating SocaNode from EC2 describe_instance response: {instance}"
        )

        _soca_specific_attributes = {}
        _tags_to_retrieve = [
            "soca:JobId",
            "soca:JobQueue",
            "soca:StackId",
            "soca:NodeType",
            "soca:ClusterId",
            "soca:KeepForever",
            "soca:TerminateWhenIdle",
        ]
        for tag in instance.get("Tags", []):
            if tag.get("Key") in _tags_to_retrieve:
                _soca_specific_attributes[tag.get("Key")] = tag.get("Value")

        if "soca:NodeType" in _soca_specific_attributes:
            if _soca_specific_attributes.get("soca:NodeType") == "compute_node":
                _node_type = SocaNodeType.COMPUTE_NODE
            elif _soca_specific_attributes.get("soca:NodeType") == "login_node":
                _node_type = SocaNodeType.LOGIN_NODE
            elif _soca_specific_attributes.get("soca:NodeType") == "dcv_node":
                _node_type = SocaNodeType.DCV_NODE
            else:
                _node_type = SocaNodeType.UNKNOWN

        logger.debug(f"Found Soca Custom Attributes: {_soca_specific_attributes}")

        _keep_forever = _soca_specific_attributes.get("soca:KeepForever", None)
        _job_id = _soca_specific_attributes.get("soca:JobId", None)

        if not _keep_forever and not _job_id:
            raise ValueError(
                f"Instance {instance.get('InstanceId')} is not tagged with soca:KeepForever or soca:JobId"
            )

        return cls(
            job_id=_job_id,
            job_queue=_soca_specific_attributes.get("soca:JobQueue", None),
            stack_id=_soca_specific_attributes.get("soca:StackId", None),
            cluster_id=_soca_specific_attributes.get("soca:ClusterId", None),
            node_type=_node_type,
            scheduler_info=scheduler_info,
            keep_forever=_keep_forever,
            terminate_when_idle=_soca_specific_attributes.get(
                "soca:TerminateWhenIdle", 0
            ),
            architecture=instance.get("Architecture"),
            availability_zone=instance.get("Placement", {}).get("AvailabilityZone"),
            iam_instance_profile_arn=instance.get("IamInstanceProfile", {}).get("Arn"),
            image_id=instance.get("ImageId"),
            instance_id=instance.get("InstanceId"),
            instance_state_name=instance.get("State", {}).get("Name"),
            instance_type=instance.get("InstanceType"),
            launch_time=instance.get("LaunchTime"),
            private_dns_name=instance.get("PrivateDnsName"),
            private_ip_address=instance.get("PrivateIpAddress"),
            public_dns_name=instance.get("PublicDnsName"),
            subnet_id=instance.get("SubnetId"),
            vpc_id=instance.get("VpcId"),
            tags=instance.get("Tags", []),
            platform=instance.get("Platform"),
            root_device_name=instance.get("RootDeviceName"),
            root_device_type=instance.get("RootDeviceType"),
            block_device_mappings=instance.get("BlockDeviceMappings"),
            cpu_options=instance.get("CpuOptions"),
            ebs_optimized=instance.get("EbsOptimized"),
            encryption_in_transit_supported=instance.get(
                "EncryptionInTransitSupported"
            ),
            hibernation_options=instance.get("HibernationOptions"),
            instance_lifecycle=instance.get("InstanceLifecycle"),
            metadata_options=instance.get("MetadataOptions"),
            monitoring=instance.get("Monitoring"),
            outpost_arn=instance.get("OutpostArn"),
            network_interfaces=instance.get("NetworkInterfaces"),
            placement_group_name=instance.get("Placement", {}).get("GroupName"),
            public_ip_address=instance.get("PublicIpAddress"),
            security_groups=instance.get("SecurityGroups"),
            state_reason=instance.get("StateReason"),
            state_transition_reason=instance.get("StateTransitionReason"),
            capacity_reservation_id=instance.get("CapacityReservationId"),
            key_name=instance.get("KeyName"),
            capacity_block_id=instance.get("CapacityBlockId"),
        )
