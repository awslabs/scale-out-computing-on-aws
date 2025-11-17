# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pydantic import BaseModel
from typing import Optional, Union, Literal, List
from enum import Enum
import logging
from utils.datamodels.hpc.scheduler import SocaHpcSchedulerProvider

from utils.hpc.job_controller import SocaHpcJobController

logger = logging.getLogger("soca_logger")


class SocaHpcJobProvisioningState(str, Enum):
    PENDING = "PENDING"  # Job is queued and no capacity is associated
    COMPUTE_PROVISIONING_IN_PROGRESS = "COMPUTE_PROVISIONING_IN_PROGRESS"  # Job is queued and capacity is being created
    COMPUTE_PROVISIONING_COMPLETE = (
        "COMPUTE_PROVISIONING_COMPLETE"  # Job is queued and capacity is associated
    )
    COMPUTE_PROVISIONING_BLOCKED = "COMPUTE_PROVISIONING_BLOCKED"  # Job has errors and capacity cannot be provisioned
    COMPUTE_PROVISIONING_ERROR = "COMPUTE_PROVISIONING_ERROR"  # CloudFormation is created and associated but not in CREATE_IN_PROGRESS OR CREATE_COMPLETE
    COMPUTE_PROVISIONING_DELETE = "COMPUTE_PROVISIONING_DELETE"
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


class SocaHpcJobBaseOS(str, Enum):
    AMAZON_LINUX_2 = "amazonlinux2"
    AMAZON_LINUX_2023 = "amazonlinux2023"
    CENTOS_7 = "centos7"
    RHEL_7 = "rhel7"
    RHEL_8 = "rhel8"
    RHEL_9 = "rhel9"
    ROCKY_8 = "rocky8"
    ROCKY_9 = "rocky9"
    UBUNTU_2204 = "ubuntu2204"
    UBUNTU_2404 = "ubuntu2404"


class SocaHpcJobResourceModel(BaseModel):
    """
    List of all custom EC2 resources supported by a SocaHpcJob that can be applied for each job
    https://awslabs.github.io/scale-out-computing-on-aws-documentation/tutorials/integration-ec2-job-parameters/

    # This class is inherited by all SocaHpcJob*** as well as SocaHpcQueue
    """

    class Config:
        arbitrary_types_allowed = (
            True  # Allow Pydantic to use Custom types (e.g. FsxLustreConfig)
        )

    # SOCA Custom Job Resources  - Validator SocaHpcJob.__normalize

    # Must be explicity set if not using SocaHpcScheduler.soca_managed_nodes_provisioning is True
    instance_type: Optional[Union[str, List[str]]] = (
        None  # Isntance Type or List of Instance Type to provision for this job
    )
    root_size: Optional[int] = None  # Size of the root EBS disk
    base_os: Optional[
        Literal[
            "amazonlinux2",
            "amazonlinux2023",
            "centos7",
            "rhel7",
            "rhel8",
            "rhel9",
            "rocky8",
            "rocky9",
            "ubuntu2204",
            "ubuntu2404",
        ]
    ] = None  # Operating system of the nodes provisioned

    # Will use default value if not set
    instance_ami: Optional[str] = None  # EC2 Image ID assigned to the node(s)
    instance_profile: Optional[str] = None  # IAM role assigned to the node(s)
    security_groups: Optional[list] = None  # Security Group(s) assigned to the node(s)
    subnet_id: Optional[list[str]] = None  # Subnet(s) to deploy the capacity on

    # Optional
    capacity_reservation_id: Optional[str] = None  # Capacity Reservation ID to use for the job
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
    efa_support: Optional[bool] = False  # Wheter Elastic Fabric Adapter is enabled
    force_ri: Optional[bool] = (
        False  # Whether the job can only run on Reserved Instance
    )
    ht_support: Optional[bool] = False  # Choose to enable to disable Hyper Threading
    error_message: Optional[list] = []
    licenses: Optional[list[SocaHpcJobLicense]] = None

    def apply_default_queue_values(
        self, queue_configuration: SocaHpcQueue, scheduler_info: SocaHpcScheduler
    ) -> SocaHpcJobLSF | SocaHpcJobPBS:
        logger.info(
            "Checking all unset job attributes and replacing them with default value found in queue_mapping if available"
        )
        _excluded_fields = ["error_message", "licenses"]
        _fields_to_process = [
            field_name
            for field_name in self.__pydantic_fields__
            if field_name not in _excluded_fields
        ]
        for _field_name in _fields_to_process:
            if getattr(self, _field_name, None) is None:
                logger.debug(
                    f"Checking if {_field_name=} has a default value in the queue config"
                )
                if hasattr(queue_configuration, _field_name):
                    value = getattr(queue_configuration, _field_name)
                    if value is not None:
                        logger.info(
                            f"Default value for {_field_name} found in queue configuration: {getattr(queue_configuration, _field_name)} "
                        )

                        # Update current SocaHpcJob instance
                        setattr(self, _field_name, value)

                        # Update resource on the job for analytics tracking
                        if scheduler_info.provider == SocaHpcSchedulerProvider.LSF:
                            SocaHpcJobController(job=self).lsf_update_job_description(
                                resource_name=_field_name, resource_value=value
                            )
                        elif scheduler_info.provider in [
                            SocaHpcSchedulerProvider.PBSPRO,
                            SocaHpcSchedulerProvider.OPENPBS,
                        ]:
                            SocaHpcJobController(job=self).pbs_update_resource(
                                resource_name=_field_name, resource_value=value
                            )

        return self
