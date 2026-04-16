# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from functools import wraps
from typing import (
    Optional,
    Callable,
    List,
    Literal,
    TypeVar,
)
from botocore.exceptions import ClientError

from utils.aws.boto3_wrapper import get_boto
from utils.aws.iam_helper import get_instance_profile
from utils.subprocess_client import SocaSubprocessClient
from utils.error import SocaError
from utils.hpc.scheduler_command_builder import SocaHpcSlurmJobCommandBuilder
from utils.response import SocaResponse
from utils.datamodels.hpc.scheduler import SocaHpcSchedulerProvider, get_schedulers


logger = logging.getLogger("soca_logger")

F = TypeVar("F", bound=Callable)


def cluster_must_be_active() -> Callable[[F], F]:
    def decorator(func: F) -> F:
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if getattr(self, "_cluster_state", None) != "ACTIVE":
                return SocaError.GENERIC_ERROR(
                    helper=(
                        f"Cluster {getattr(self, '_cluster_name', 'UNKNOWN')} must be in ACTIVE state (current: {getattr(self, '_cluster_state', 'UNKNOWN')}) Run get_cluster() to refresh the cluster state."
                    )
                )

            return func(self, *args, **kwargs)

        return wrapper

    return decorator


class SocaAWSPCSClient:
    """
    AWS PCS Client for SOCA

    Requirements (for now - this is an alpha client)

    For PCS cluster (if not using existing): VPC ID + Subnet IDs + Security Group
    For PCS Compute Node:  IAM instance profile + Launch Template
    """

    def __init__(self, cluster_name: str, region_name: Optional[str] = None):
        self._pcs_client = get_boto(service_name="pcs", region_name=region_name).message
        self._cluster_name = cluster_name

        # _cluster_identifier / _cluster_state will be automatically populated after a create_cluster() or a successfull get_cluster()
        self._cluster_identifier = None
        self._cluster_slurmctld_endpoint = None
        self._cluster_state = None
        self._cluster_subnet_ids = None
        self._cluster_security_group_ids = None
        self._soca_scheduler_info = None

    @property
    def cluster_slurmctld_endpoint(self) -> Optional[str]:
        if not self._cluster_slurmctld_endpoint:
            self.get_cluster()
        return self._cluster_slurmctld_endpoint

    @property
    def cluster_identifier(self) -> Optional[str]:
        return self._cluster_identifier

    @property
    def cluster_name(self) -> Optional[str]:
        return self._cluster_name

    @property
    def cluster_state(self) -> Optional[str]:
        return self._cluster_state

    @property
    def cluster_security_group_ids(self) -> Optional[str]:
        return self._cluster_security_group_ids

    @property
    def soca_scheduler_info(self) -> Optional[str]:
        return self._soca_scheduler_info

    def send_job_to_cluster(self, script_path: str) -> SocaResponse | SocaError:

        if self._soca_scheduler_info is None:
            for _registered_soca_scheduler in get_schedulers():
                logger.debug(
                    f"Found Registered Scheduler on SOCA: {_registered_soca_scheduler}"
                )
                if _registered_soca_scheduler.identifier == self._cluster_name:
                    if (
                        _registered_soca_scheduler.provider
                        != SocaHpcSchedulerProvider.SLURM
                    ):
                        return SocaError.GENERIC_ERROR(
                            helper=f"PCS only support SLURM but {self._cluster_name} provider is {_registered_soca_scheduler.provider}"
                        )
                    self._soca_scheduler_info = _registered_soca_scheduler
                    break

        if self._soca_scheduler_info is None:
            return SocaError.GENERIC_ERROR(
                helper=f"No scheduler registered on SOCA with identifier {self._cluster_name}. Refer to https://awslabs.github.io/engineering-development-hub-documentation/documentation/architecture/edhctl/schedulers/ to register a client for {self._cluster_name}"
            )

        logger.debug("Retrieving sbatch path")
        _sbatch_bin = SocaHpcSlurmJobCommandBuilder(
            scheduler_info=self._soca_scheduler_info
        ).sbatch()

        _submit_job_command = f"{_sbatch_bin} {script_path}"
        logger.debug(f"sbatch command to be executed: {_submit_job_command=}")

        _submit_job = SocaSubprocessClient(run_command=_submit_job_command)
        logger.info(f"Job Submission Command to {self._cluster_name}: {_submit_job}")
        if _submit_job.get("success") is True:
            return SocaResponse(success=True, message=_submit_job.get("message"))
        else:
            return SocaError.GENERIC_ERROR(helper=_submit_job.get("message"))

    def create_cluster(
        self,
        subnet_ids: List[str],
        security_group_ids: List[str],
        size: Literal["SMALL", "MEDIUM", "LARGE"] = "SMALL",
        scheduler: Optional[dict] = None,
    ) -> SocaResponse | SocaError:

        if scheduler is None:
            scheduler = {"type": "SLURM", "version": "25.05"}
        try:
            # Simple wrapper for now
            _create_pcs = self._pcs_client.create_cluster(
                clusterName=self._cluster_name,
                scheduler=scheduler,
                size=size,
                networking={
                    "subnetIds": subnet_ids,
                    "securityGroupIds": security_group_ids,
                    "networkType": "IPV4",
                },
            )
            self._cluster_identifier = _create_pcs.get("cluster", {}).get("id", None)
            if self._cluster_identifier is None:
                return SocaError.GENERIC_ERROR(
                    helper="Unable to retrieve cluster ID from create_cluster()"
                )
            else:
                self._cluster_state = "CREATING"
                self._cluster_security_group_ids = security_group_ids
                self._cluster_subnet_ids = subnet_ids
                return SocaResponse(success=True, message=self._cluster_identifier)

        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to create PCS cluster {self._cluster_name} because of {err}",
            )

    def delete_cluster(self) -> SocaResponse | SocaError:
        try:
            self._pcs_client.delete_cluster(clusterIdentifier=self._cluster_name)
            return SocaResponse(
                success=True,
                message=f"Delete initiated for {self._cluster_name}, your PCS cluster will be removed shortly",
            )
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to delete {self._cluster_name} due to {err}"
            )

    def get_cluster(
        self, list_queues: bool = True, list_compute_node_groups: bool = True
    ) -> SocaResponse | SocaError:
        try:
            logger.info(
                f"Retrieve {self._cluster_name} info with {list_queues} and {list_compute_node_groups}"
            )
            _queues = []
            _compute_node_groups = []
            _cluster_info = self._pcs_client.get_cluster(
                clusterIdentifier=self._cluster_name
            )
            self._cluster_state = _cluster_info.get("cluster", {}).get("status", "")
            if self._cluster_identifier is None:
                self._cluster_identifier = _cluster_info.get("cluster", {}).get(
                    "id", None
                )

            if self._cluster_security_group_ids is None:
                self._cluster_security_group_ids = (
                    _cluster_info.get("cluster", {})
                    .get("networking", {})
                    .get("securityGroupIds", None)
                )
            if self._cluster_subnet_ids is None:
                self._cluster_subnet_ids = (
                    _cluster_info.get("cluster", {})
                    .get("networking", {})
                    .get("subnetIds", None)
                )
            logger.debug(f"{self._cluster_name} is in {self._cluster_state} state.")

            _cluster_endpoints = _cluster_info.get("cluster", {}).get("endpoints", [])
            if self._cluster_slurmctld_endpoint is None:
                logger.debug(f"Found cluster endpoints: {_cluster_endpoints}")
                for _endpoint in _cluster_endpoints:
                    if _endpoint.get("type", "") == "SLURMCTLD":
                        self._cluster_slurmctld_endpoint = _endpoint

            if list_queues is True:
                if self._cluster_state == "ACTIVE":
                    _get_queues = self.list_queues()
                    if _get_queues.get("success") is True:
                        _queues = _get_queues.get("message")
                    else:
                        return SocaError.GENERIC_ERROR(
                            helper=_get_queues.get("message")
                        )
                else:
                    logger.warning(
                        f"list_queues is set to True but {self._cluster_state=} is not ACTIVE. Ignoring call and returning empty list"
                    )

            if list_compute_node_groups:
                if self._cluster_state == "ACTIVE":
                    _get_compute_node_groups = self.list_compute_node_groups()
                    if _get_compute_node_groups.get("success") is True:
                        _compute_node_groups = _get_compute_node_groups.get("message")
                    else:
                        return SocaError.GENERIC_ERROR(
                            helper=_get_compute_node_groups.get("message")
                        )
                else:
                    logger.warning(
                        f"list_compute_node_groups is set to True but {self._cluster_state=} is not ACTIVE. Ignoring call and returning empty list"
                    )

            _pcs_cluster_info = {
                "cluster": _cluster_info.get("cluster", {}),
                "queues": _queues,
                "compute_node_groups": _compute_node_groups,
            }
            logger.debug(f"{self._cluster_name} result: {_pcs_cluster_info} ")

            return SocaResponse(
                success=True,
                message=_pcs_cluster_info,
            )

        except ClientError as err:
            _error_code = err.response["Error"]["Code"]
            if _error_code == "ResourceNotFoundException":
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to find a PCS cluster named {self._cluster_name}. Call create_cluster() to first create this cluster"
                )
            elif _error_code == "AccessDeniedException":
                return SocaError.GENERIC_ERROR(
                    helper=f"Access denied when retrieving PCS cluster {self._cluster_name}. Verify IAM permissions."
                )
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to retrieve cluster information for {self._cluster_name} because of {err}",
                )

        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve cluster information for {self._cluster_name} because of {err}",
            )

    # -- Queues --
    @cluster_must_be_active()
    def list_queues(self) -> SocaResponse | SocaError:
        logger.debug(f"About to list queue for {self._cluster_name}")
        _queues = []
        try:
            _queues_paginator = self._pcs_client.get_paginator("list_queues")
            for page in _queues_paginator.paginate(
                clusterIdentifier=self._cluster_name
            ):
                _queues.extend(page.get("queues", []))

            logger.debug(
                f"Found PCS queues associated to {self._cluster_name}: {_queues}"
            )
            return SocaResponse(success=True, message=_queues)
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to list PCS queues due to {err}"
            )

    @cluster_must_be_active()
    def create_queue(
        self, queue_name: str, compute_node_group_ids: list[str]
    ) -> SocaResponse | SocaError:
        logger.info(f"Creating {queue_name=} with {compute_node_group_ids=}")
        try:
            _create_queue = self._pcs_client.create_queue(
                clusterIdentifier=self.cluster_name,
                queueName=queue_name,
                computeNodeGroupConfigurations=[
                    {"computeNodeGroupId": t} for t in compute_node_group_ids
                ],
            )
            _queue_id = _create_queue.get("queue", {}).get("id", None)
            return SocaResponse(
                success=True,
                message=f"Queue {queue_name} created successfully with id {_queue_id}",
            )
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to create queue {queue_name} because of {err}"
            )

    def delete_queue(self, queue_identifier: str) -> SocaResponse | SocaError:
        logger.info(
            f"About to delete Queue {queue_identifier} for {self._cluster_name}"
        )
        try:
            self._pcs_client.delete_queue(
                clusterIdentifier=self._cluster_name,
                queueIdentifier=queue_identifier,
            )
            return SocaResponse(
                success=True,
                message=f"Delete initiated for {queue_identifier} for {self._cluster_name}, your queue  will be removed shortly",
            )
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to delete {queue_identifier=} for {self._cluster_name} due to {err}"
            )

    # -- Compute Node Groups --
    @cluster_must_be_active()
    def list_compute_node_groups(self) -> SocaResponse | SocaError:
        logger.debug(f"About to list compute node groups for {self._cluster_name}")
        _compute_node_groups = []
        try:
            _compute_node_group_paginator = self._pcs_client.get_paginator(
                "list_compute_node_groups"
            )

            for page in _compute_node_group_paginator.paginate(
                clusterIdentifier=self._cluster_name,
            ):
                _compute_node_groups.extend(page.get("computeNodeGroups", []))

            logger.debug(
                f"Found PCS Compute Node Groups associated to {self._cluster_name}: {_compute_node_groups}"
            )
            return SocaResponse(success=True, message=_compute_node_groups)
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to list PCS compute node groups due to {err}"
            )

    @cluster_must_be_active()
    def create_compute_node_group(
        self,
        group_name: str,
        launch_template_id: str,
        launch_template_version: str,
        instance_types: list[str],
        desired_capacity: int,
        ami_id: str,
        instance_profile_arn: str,
        subnet_ids: Optional[list] = None,
        purchase_option: Optional[
            Literal["ONDEMAND", "SPOT", "CAPACITY_BLOCK"]
        ] = "ONDEMAND",
    ) -> SocaResponse | SocaError:

        logger.info(
            f"Creating PCS compute node group {group_name=} with {launch_template_id=} {launch_template_version=} / {instance_types=} / {desired_capacity=} / {ami_id} / {instance_profile_arn=} / {subnet_ids=} / {purchase_option=}"
        )
        # Need to use the SOCA utils.aws helpers to validate AMI ID / Subnets ID .. current SOCA helper works with the current region whre SOCA is deployed to
        # need to have a way to override the boto3 wrapper
        # for now I only validate instance AMI as this is not regional bound

        if len(group_name) > 25:
            return SocaError.GENERIC_ERROR(
                helper=f"Compute Node Group name must be less than 25 characters. Current length is {len(group_name)}"
            )

        _validate_iam_instance_profile = get_instance_profile(
            instance_profile_name=instance_profile_arn.split("/")[-1]
        )
        if _validate_iam_instance_profile.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to validate IAM Instance Profile {instance_profile_arn} because {_validate_iam_instance_profile.get('message')}"
            )

        try:
            _create_compute_node = self._pcs_client.create_compute_node_group(
                clusterIdentifier=self._cluster_name,
                computeNodeGroupName=group_name,
                amiId=ami_id,
                subnetIds=subnet_ids if subnet_ids else self._cluster_subnet_ids,
                purchaseOption=purchase_option,
                customLaunchTemplate={
                    "id": launch_template_id,
                    "version": launch_template_version,
                },
                iamInstanceProfileArn=instance_profile_arn,
                scalingConfiguration={
                    "minInstanceCount": desired_capacity,
                    "maxInstanceCount": desired_capacity,
                },
                instanceConfigs=[{"instanceType": t} for t in instance_types],
            )

            return SocaResponse(
                success=True,
                message={
                    "id": _create_compute_node.get("computeNodeGroup", {}).get("id"),
                    "name": _create_compute_node.get("computeNodeGroup", {}).get(
                        "name"
                    ),
                },
            )

        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to create compute node group {group_name} because of {err} "
            )

    def delete_compute_node_group(
        self, compute_node_group_identifier
    ) -> SocaResponse | SocaError:
        logger.info(
            f"About to delete Compute Node Group ID {compute_node_group_identifier} for {self._cluster_name}"
        )
        try:
            self._pcs_client.delete_compute_node_group(
                clusterIdentifier=self._cluster_name,
                computeNodeGroupIdentifier=compute_node_group_identifier,
            )
            return SocaResponse(
                success=True,
                message=f"Delete initiated for {compute_node_group_identifier} for {self._cluster_name}, your compute node group will be removed shortly",
            )
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to delete {compute_node_group_identifier=} for {self._cluster_name} due to {err}"
            )
