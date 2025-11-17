# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import logging
import sys
from datetime import datetime, timedelta
from datetime import timezone

from utils.datamodels.soca_node import (
    SocaNode,
)
from utils.datamodels.hpc.shared.scheduler_node_resources import SocaSchedulerNodeState

logger = logging.getLogger("soca_logger")


def sync_scheduler_config(
    scheduler_registered_nodes: list[SocaHpcPBSNode],
    provisioned_ec2_nodes: list[SocaNode],
    jobs_in_queues: list[SocaHpcJobPBS | SocaHpcJobLSF],
) -> dict:
    # This functions must be called from the relevant utils.hpc.schedulers_managers scheduler class:
    # - SocaSchedulerPBSNodesManager

    logger.debug(f"Registered nodes on scheduler {scheduler_registered_nodes}")
    logger.debug(f"Jobs in Queues: {jobs_in_queues}")
    logger.debug(
        f"Provisioned EC2 Nodes including KeepForever instances: {provisioned_ec2_nodes}"
    )

    _scheduler_sync_actions = {
        "register_soca_nodes_to_scheduler": [],
        "deregister_scheduler_nodes_no_associated_ec2_capacity": [],
        "deregister_scheduler_nodes_finished_jobs": [],
        "deregister_scheduler_nodes_terminate_when_idle": [],
    }

    if not provisioned_ec2_nodes:
        try:
            # Begin - De-register all nodes since there is no provisioned EC2 capacity
            logger.info("No EC2 nodes provisioned for this scheduler")
            if scheduler_registered_nodes:
                logger.debug(
                    "Removing all registered nodes since there is no associated EC2 capacity"
                )
                for _scheduler_node in scheduler_registered_nodes:
                    _scheduler_sync_actions.get(
                        "deregister_scheduler_nodes_no_associated_ec2_capacity"
                    ).append(_scheduler_node)
        except Exception as err:
            logger.error(
                f"Error while building deregister_scheduler_nodes_no_associated_ec2_capacity because of {err} on line {sys.exc_info()[2].tb_lineno}"
            )

        # End - De-register all nodes since there is no provisioned EC2 capacity
    else:

        # Begin: Find KeepForever host and output debug info message for troubleshooting purpose
        _keep_forever_scheduler_node = [
            _scheduler_node
            for _scheduler_node in scheduler_registered_nodes
            if _scheduler_node.keep_forever is True
        ]
        if _keep_forever_scheduler_node:
            logger.debug(
                f"KeepForever EC2 nodes: {_keep_forever_scheduler_node}. Those hosts can only be removed manually via socactl"
            )
        # End: Find keep_forever host and output debug info message for troubleshooting purpose

        # Begin: Register EC2 nodes to the scheduler
        try:
            _scheduler_nodes_registered_mapped_by_instance_id = {
                sched_node.instance_id: sched_node
                for sched_node in scheduler_registered_nodes
            }

            _missing_ec2_nodes_to_register = [
                soca_node
                for soca_node in provisioned_ec2_nodes
                if soca_node.instance_id
                not in _scheduler_nodes_registered_mapped_by_instance_id
            ]

            logger.debug(
                f"Missing EC2 nodes to register: {_missing_ec2_nodes_to_register}"
            )
            if _missing_ec2_nodes_to_register:
                for _ec2_node in _missing_ec2_nodes_to_register:
                    _scheduler_sync_actions.get(
                        "register_soca_nodes_to_scheduler"
                    ).append(_ec2_node)
            else:
                logger.debug("No missing EC2 nodes to register")
        except Exception as err:
            logger.error(
                f"Error while building register_soca_nodes_to_scheduler because of {err} on line {sys.exc_info()[2].tb_lineno}"
            )
        # End: Register EC2 nodes to PBS

        # Begin: De-register EC2 nodes assigned to finished jobs
        try:
            _active_job_ids = [job.job_id for job in jobs_in_queues]
            _scheduler_nodes_assigned_to_finished_jobs = [
                _scheduler_node
                for _scheduler_node in scheduler_registered_nodes
                if _scheduler_node.job_id not in _active_job_ids
                and _scheduler_node.keep_forever is False
            ]
            logger.debug(
                f"De-registering EC2 nodes with KeepForever set to False assigned to finished jobs: {_scheduler_nodes_assigned_to_finished_jobs}: {_active_job_ids=}"
            )
            for _scheduler_node in _scheduler_nodes_assigned_to_finished_jobs:
                _scheduler_sync_actions.get(
                    "deregister_scheduler_nodes_finished_jobs"
                ).append(_scheduler_node)
        except Exception as err:
            logger.error(
                f"Error while building deregister_scheduler_nodes_finished_jobs because of {err} on line {sys.exc_info()[2].tb_lineno}"
            )
        # End: De-register EC2 nodes assigned to finished jobs

        # Begin: De-Register PBS Nodes assigned to removed EC2 instance
        # example: If you remove the EC2 instance manually from the AWS console
        try:
            _scheduler_node_assigned_to_removed_ec2_instance = [
                _sched_node
                for _sched_node in scheduler_registered_nodes
                if _sched_node.instance_id
                not in [soca_node.instance_id for soca_node in provisioned_ec2_nodes]
                and _sched_node.keep_forever is False
            ]

            for _scheduler_node in _scheduler_node_assigned_to_removed_ec2_instance:
                logger.debug(
                    f"De-registering {_scheduler_node} since it is not associated to any EC2 instance"
                )
                _scheduler_sync_actions.get(
                    "deregister_scheduler_nodes_no_associated_ec2_capacity"
                ).append(_scheduler_node)
        except Exception as err:
            logger.error(
                f"Error while building deregister_scheduler_nodes_no_associated_ec2_capacity because of {err} on line {sys.exc_info()[2].tb_lineno}"
            )
        # End: De-Register PBS Nodes assigned to removed EC2 instance

        # Begin De-Register instance with an expired terminate_when_idle
        try:
            _scheduler_node_with_terminate_when_idle = [
                _sched_node
                for _sched_node in scheduler_registered_nodes
                if _sched_node.terminate_when_idle > 0
                and _sched_node.keep_forever is False
            ]

            logger.debug(
                "Checking Scheduler Nodes with TerminateWhenIdle > 0 and KeepForever is False"
            )
            for _scheduler_node in _scheduler_node_with_terminate_when_idle:
                if _scheduler_node.node_state == SocaSchedulerNodeState.IDLE:
                    _terminate_when_idle = _scheduler_node.terminate_when_idle
                    _last_state_change = _scheduler_node.last_state_change_utc_timestamp

                    _idle_threshold = timedelta(minutes=_terminate_when_idle)
                    _current_time = datetime.now(timezone.utc)

                    time_since_last_change = _current_time - _last_state_change

                    if time_since_last_change > _idle_threshold:
                        logger.debug(
                            f"De-registering {_scheduler_node} since it has been idle for "
                            f"{time_since_last_change.total_seconds()/60:.1f} minutes "
                            f"(threshold: {_scheduler_node.terminate_when_idle} minutes). "
                            f"Last state change: {_last_state_change.isoformat()}"
                        )
                        _scheduler_sync_actions.get(
                            "deregister_scheduler_nodes_terminate_when_idle"
                        ).append(_scheduler_node)
                else:
                    logger.debug(
                        f"{_scheduler_node.node_state} is not IDLE, skipping this node"
                    )
        except Exception as err:
            logger.error(
                f"Error while building deregister_scheduler_nodes_terminate_when_idle because of {err} on line {sys.exc_info()[2].tb_lineno}"
            )
        # End De-Register KeepForever instance with custom terminate_when_idle

    logger.debug(f"Sync actions: {_scheduler_sync_actions}")
    return _scheduler_sync_actions
