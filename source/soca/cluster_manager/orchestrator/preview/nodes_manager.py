# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from utils.response import SocaResponse
from utils.error import SocaError
from utils.logger import SocaLogger

from utils.datamodels.hpc.scheduler import (
    get_schedulers,
    SocaHpcScheduler,
    SocaHpcSchedulerProvider,
)

from utils.aws.ec2_helper import describe_instances_as_soca_nodes
from utils.aws.ssm_parameter_store import SocaConfig

from utils.hpc.schedulers_managers.pbs import SocaSchedulerPBSNodesManager
from utils.hpc.schedulers_managers.lsf import SocaSchedulerLSFNodesManager
from utils.hpc.schedulers_managers.slurm import SocaSchedulerSlurmNodesManager

from utils.hpc.job_fetcher import SocaHpcJobFetcher


def get_provisioned_ec2_nodes_assigned_to_scheduler(
    scheduler_info: SocaHpcScheduler,
) -> SocaResponse[list[SocaNode]]:
    logger.info(f"Retrieving all provisioned EC2 Nodes assigned to {scheduler_info=}")
    # Notes
    #  - Additional Scheduler Specific filters will be automatically added to the _filters as we pass a SocaHpcScheduler object on describe_instances_as_soca_nodes
    #  - We must retrieve KeepForever nodes as well
    _filters = [
        {
            "Name": "instance-state-name",
            "Values": ["running", "pending"],
        },
        {"Name": "tag:soca:NodeType", "Values": ["compute_node"]},
        {
            "Name": "tag:soca:KeepForever",
            "Values": ["false", "False", "true", "True"],
        },
        {"Name": "tag:soca:ClusterId", "Values": [_cluster_id]},
    ]
    logger.debug(f"Fetching EC2 instances using {_filters=}")
    _fetch_all_ec2_nodes_for_scheduler = describe_instances_as_soca_nodes(
        filters=_filters, scheduler_info=scheduler_info
    )
    if _fetch_all_ec2_nodes_for_scheduler.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to fetch EC2 nodes due to {_fetch_all_ec2_nodes_for_scheduler.get('message')}"
        )
    else:
        # Note: this is a list of SocaNode as we use describe_instances_as_soca_nodes
        _provisioned_ec2_nodes = _fetch_all_ec2_nodes_for_scheduler.get("message")

        logger.debug(
            f"List of EC2 Node associated to {scheduler_info.identifier}: {_provisioned_ec2_nodes}"
        )
        return SocaResponse(success=True, message=_provisioned_ec2_nodes)


if __name__ == "__main__":
    _cluster_id = SocaConfig(key="/configuration/ClusterId").get_value().message

    logger = SocaLogger(name="soca_logger").timed_rotating_file_handler(
        file_path=f"/opt/soca/{_cluster_id}/cluster_manager/orchestrator/logs/nodes_manager.log"
    )

    _all_schedulers = get_schedulers()
    logger.debug(f"About to fetch nodes for {_all_schedulers=} with {_cluster_id=}")

    for _scheduler in _all_schedulers:
        logger.debug(f"Processing {_scheduler}")
        # List of SocaHpcJob found in all queues assigned to the scheduler
        _jobs_in_queues: list[SocaHpcJobLSF | SocaHpcJobPBS | SocaHpcJobSlurm] = []

        # List of SocaNode provisionined on EC2 and attached to this scheduler
        _provisioned_ec2_nodes: list[SocaNode] = []

        if _scheduler.soca_managed_nodes_provisioning is False:
            logger.info(
                f"Skipping scheduler {_scheduler.identifier} as soca_managed_nodes_provisioning is set to False"
            )
            continue

        # 1 - Get the list of EC2 Provisioned nodes assigned to the scheduler
        logger.info(f"Syncing provisioned EC2 nodes for {_scheduler.identifier}")
        if not (
            _get_provisioned_nodes := get_provisioned_ec2_nodes_assigned_to_scheduler(
                scheduler_info=_scheduler
            )
        ).get("success"):
            logger.error(
                f"Unable to fetch EC2 nodes due to {_get_provisioned_nodes.get('message')}"
            )
            continue
        else:
            _provisioned_ec2_nodes = _get_provisioned_nodes.get("message")

        # 2 - Get all jobs submitted
        logger.info(f"Syncing jobs in queue for {_scheduler.identifier}")
        if not (
            _get_submitted_jobs := SocaHpcJobFetcher(_scheduler).get_all_jobs()
        ).get("success"):
            logger.error(
                f"Unable to fetch jobs in queues due to {_get_submitted_jobs.get('message')}"
            )
            continue
        else:
            _jobs_in_queues = _get_submitted_jobs.get("message")

        logger.debug(f"{_scheduler.provider}: Found {_provisioned_ec2_nodes=}")
        logger.debug(f"{_scheduler.provider}: Found {_jobs_in_queues=}")

        # 3 - Sync configuration with respective scheduler information
        if _scheduler.provider in [
            SocaHpcSchedulerProvider.OPENPBS,
            SocaHpcSchedulerProvider.PBSPRO,
        ]:
            # errors/warnings are automatically forwarded to nodes_manager.log
            SocaSchedulerPBSNodesManager(scheduler_info=_scheduler).sync_config(
                provisioned_ec2_nodes=_provisioned_ec2_nodes,
                jobs_in_queues=_jobs_in_queues,
            )
        elif _scheduler.provider == SocaHpcSchedulerProvider.LSF:
            # errors/warnings are automatically forwarded to nodes_manager.log
            SocaSchedulerLSFNodesManager(scheduler_info=_scheduler).sync_config(
                provisioned_ec2_nodes=_provisioned_ec2_nodes,
                jobs_in_queues=_jobs_in_queues,
            )

        elif _scheduler.provider == SocaHpcSchedulerProvider.SLURM:
            # errors/warnings are automatically forwarded to nodes_manager.log
            SocaSchedulerSlurmNodesManager(scheduler_info=_scheduler).sync_config(
                provisioned_ec2_nodes=_provisioned_ec2_nodes,
                jobs_in_queues=_jobs_in_queues,
            )

        else:
            logger.error(f"{_scheduler.provider} is not supported yet")
