# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pydantic import BaseModel
from typing import Optional, Union, Literal, List
from enum import Enum
from utils.datamodels.constants import SocaLinuxBaseOS


class SocaHpcJobProvisioningState(str, Enum):
    PENDING = "PENDING"  # Job is queued and no capacity is associated
    MAX_RETRY_ATTEMPTS_REACHED = "MAX_RETRY_ATTEMPTS_REACHED"  # Job reached max retry attempts and will be ignored
    COMPUTE_PROVISIONING_IN_PROGRESS = "COMPUTE_PROVISIONING_IN_PROGRESS"  # Job is queued and capacity is being provisioned (CREATE_IN_PROGRESS)
    COMPUTE_PROVISIONING_COMPLETE = "COMPUTE_PROVISIONING_COMPLETE"  # Job is queued, capacity is associated and stack is CREATE_COMPLETE
    COMPUTE_PROVISIONING_BLOCKED = "COMPUTE_PROVISIONING_BLOCKED"  # Job has errors and capacity cannot be provisioned
    COMPUTE_PROVISIONING_ERROR = "COMPUTE_PROVISIONING_ERROR"  # Associated CloudFormation stack is created but not in CREATE_IN_PROGRESS OR CREATE_COMPLETE
    COMPUTE_PROVISIONING_DELETE = "COMPUTE_PROVISIONING_DELETE"  # Associated CloudFormation stack is being deleted
    RUNNING = "RUNNING"  # Job is running
    STOPPED = "STOPPED"  # Job is stopped / suspended
    UNKNOWN = "UNKNOWN_STATE"


class SocaHpcJobState(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    STOPPED = "STOPPED"  # Use this for Suspended
    EXITING = "EXITING"
    FINISHED = "FINISHED"
    OTHER = "OTHER"
    UNKNOWN = "UNKNOWN_STATE"


class SocaHpcJobLicense(BaseModel):
    name: Optional[str] = None
    count: Optional[int] = None


class SocaCapacityReservation(BaseModel):
    reservation_id: str
    reservation_exist: bool  # whether the specified capacity reservation exists

    # Note: Optional parameters only if reservation_exist is False
    instance_type: Optional[str] = None
    availability_zone: Optional[str] = None
    availability_zone_id: Optional[str] = None
    state: Optional[
        Literal[
            "active",
            "expired",
            "cancelled",
            "pending",
            "failed",
            "scheduled",
            "assessing",
            "delayed",
            "unsupported",
        ]
    ] = None  # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/capacity-reservations-view.html
    total_instance_count: Optional[int] = None
    available_instance_count: Optional[int] = None
    instance_platform: Optional[str] = None
    reservation_type: Optional[Literal["odcr", "capacity-block"]] = None


class SocaHpcJobOrchestrationMethod(str, Enum):
    FLEET = "fleet"  # Default - capacity will be provisioned via EC2 Fleet
    ASG = "asg"  # Legacy - Capacity will be provisioned via EC2 Auto Scaling Group (recommended to use EC2 Fleet instead unless specific use case)


class SocaHpcJobResourceModel(BaseModel):
    """
    List of all custom EC2 resources supported by a SocaHpcJob that can be applied for each job
    https://awslabs.github.io/engineering-development-hub-documentation/tutorials/integration-ec2-job-parameters/

    # This class is inherited by all SocaHpcJob[PBS|LSF|Slurm] as well as SocaHpcQueue
    """

    # SOCA Custom Job Resources  - Validator SocaHpcJob.validate()

    # Must be explicitly set if SocaHpcScheduler.soca_managed_nodes_provisioning is True
    instance_types: Optional[List[str]] = (
        None  # Instance Type or List of Instance Type to provision for this job
    )
    root_size: Optional[int] = None  # Size of the root EBS disk
    base_os: Optional[SocaLinuxBaseOS] = (
        None  # Operating system of the nodes provisioned
    )

    # Will use default value if not set
    instance_ami: Optional[str] = None  # EC2 Image ID assigned to the node(s)
    instance_profile: Optional[str] = None  # IAM role assigned to the node(s)
    security_groups: Optional[list] = None  # Security Group(s) assigned to the node(s)
    subnet_ids: Optional[list[str]] = None  # Subnet(s) to deploy the capacity on

    # Optional
    capacity_reservation_id: Optional[SocaCapacityReservation] = (
        None  # Capacity Reservation ID to use for the job
    )
    anonymous_metrics: Optional[bool] = True  # Enable Anonymous Data tracking
    fsx_lustre: Optional[str | bool] = (
        None  # FSx for Lustre association to the job. If True, SOCA will generate a brand new FSxL, otherwise it will try to connect to the fs-id specified
    )
    fsx_lustre_size: Optional[int] = None  # FSxL capacity if selected
    fsx_lustre_deployment_type: Optional[str] = None  # FSxL deployment_type if selected
    fsx_lustre_per_unit_throughput: Optional[int] = None  # FsxL throughput if selected
    fsx_lustre_storage_type: Optional[str] = None  # FSxL storage_type if selected
    scratch_iops: Optional[int] = None  # Use EBS io2 instead of gp3 is selected
    scratch_size: Optional[int] = (
        None  # Will deploy a custom /scratch partition with the desired size
    )
    spot_price: Optional[Union[int, float, Literal["auto"]]] = (
        None  # Enable Spot instance
    )
    spot_allocation_count: Optional[int] = (
        None  # Spot allocation count (on-demand vs spot) if using spot instance
    )
    spot_allocation_strategy: Optional[
        Literal["capacity-optimized", "lowest-price", "diversified"]
    ] = None  # Spot Allocation strategy if using spot instance
    keep_ebs: Optional[bool] = (
        False  # Preserve EBS after a job is deleted and capacity is removed
    )
    placement_group: Optional[bool] = (
        False  # Whether you want to use a placement group for the node(s)
    )
    efa_support: Optional[bool] = False  # Whether Elastic Fabric Adapter is enabled
    force_ri: Optional[bool] = (
        False  # Whether the job can only run on Reserved Instance
    )
    ht_support: Optional[bool] = False  # Choose to enable to disable Hyper Threading
    nested_virtualization: Optional[bool] = False  # Enable nested virtualization (CpuOptions.NestedVirtualization)
    error_message: Optional[list] = []
    licenses: Optional[list[SocaHpcJobLicense]] = []
