# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import argparse
import socket
import os
import sys
import yaml
import logging
import uuid

from typing import Union
from datetime import datetime, timedelta

from utils.logger import SocaLogger
from utils.aws.ssm_parameter_store import SocaConfig

from utils.hpc.job_fetcher import SocaHpcJobFetcher
from utils.hpc.job_controller import SocaHpcJobController
from utils.hpc.license_check import SocaLicenseQuery
from utils.datamodels.hpc.queue import SocaHpcQueue
from utils.datamodels.hpc.shared.job_resources import (
    SocaHpcJobState,
    SocaHpcJobProvisioningState,
)
from utils.datamodels.hpc.shared.job import SocaHpcJob
from utils.datamodels.hpc.scheduler import get_schedulers

from utils.aws.ec2_helper import validate_instance_ri_coverage

from utils.response import SocaResponse


def get_lock(process_name: str) -> Union[bool, str]:
    """
    Attempts to acquire a lock using a UNIX socket.

    This function ensures that only one instance of a process with the given name
    can run at a time by binding to an abstract namespace socket.
    """
    get_lock._lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    pid = os.getpid()
    try:
        get_lock._lock_socket.bind(f"\0{process_name}")
        return True
    except (OSError, socket.error) as e:
        sys.exit(
            f"Lock for {process_name} already exists. Exiting PID {pid}. Error: {str(e).replace('\n', ' ').replace('\r', ' ')}"
        )
    except Exception as err:
        sys.exit(f"Unknown error trying to get socket: {err}")


def load_queue_configuration(queue_config_file: str, queue_type: str) -> SocaHpcQueue:
    """
    Load and validate queue configuration from YAML file.
    Returns a SocaQueue object if successful, otherwise exits the program.
    """
    logger_dispatcher.debug(
        f"Getting Queue Information from {queue_config_file=} for {queue_type=}"
    )
    try:
        with open(queue_config_file, "r") as stream_resource_mapping:
            docs = yaml.safe_load_all(stream_resource_mapping)
            for doc in docs:
                for items in doc.values():
                    for _type, info in items.items():
                        if _type == queue_type:
                            queue_cfg = SocaHpcQueue.model_construct()
                            for key, value in info.items():
                                if hasattr(queue_cfg, key):
                                    logger_dispatcher.debug(
                                        f"Queue Value found {key=} with {value=}"
                                    )
                                    setattr(queue_cfg, key, value)

                            if (is_config_valid := queue_cfg.validate_queue()).get(
                                "success"
                            ) is False:
                                sys.exit(
                                    f"{queue_cfg} has config errors: {is_config_valid.get('message')}"
                                )
                            return queue_cfg
    except Exception as err:
        sys.exit(
            f"Unable to read queue settings file ({queue_config_file}) with error: {err}"
        )

    sys.exit(f"Unable to find queues information for queue type {queue_type}")


def load_license_mapping(license_mapping_file: str) -> dict:
    """
    Load license mapping from YAML file into a dictionary.
    """
    _license_mapping_resources = {}
    try:
        with open(license_mapping_file, "r") as stream_license_mapping:
            docs = yaml.safe_load_all(stream_license_mapping)
            for doc in docs:
                for _, v in doc.items():
                    for license_name, license_output in v.items():
                        _license_mapping_resources[license_name] = license_output
        return _license_mapping_resources
    except Exception as err:
        sys.exit(
            f"Unable to read license file ({license_mapping_file}) with error: {err}"
        )


def verify_job_licenses_requirements(
    job_info: SocaHpcJob,
    license_mapping: dict,
    override_license_count_for_pending_jobs: dict,
) -> SocaResponse:

    _license_error = False
    if job_info.licenses:
        for _license in job_info.licenses:
            if _license_error is True:
                break

            if _license.name in license_mapping.keys():
                _requested_license_name = _license.name
                _requested_license_count = _license.count
                _license_server = license_mapping[_license.name].get("server", None)
                _license_port = license_mapping[_license.name].get("port", None)
                _license_feature = license_mapping[_license.name].get("feature", None)
                _license_minus = license_mapping[_license.name].get("minus", None)
                _license_provider = license_mapping[_license.name].get("provider", None)
                _license_query = SocaLicenseQuery(
                    server=_license_server,
                    port=_license_port,
                    feature=_license_feature,
                    minus=_license_minus,
                )
                if _license_query.get("success") is True:
                    if (
                        _requested_license_name
                        in override_license_count_for_pending_jobs.keys()
                    ):
                        _license_available = override_license_count_for_pending_jobs[
                            _requested_license_name
                        ]
                        logger.info(
                            f"{_requested_license_name} already in override_license_count_for_pending_jobs, {_license_available=}"
                        )
                    else:
                        _license_available = _license_query.get("message")
                        logger.info(
                            f"{_license_available=} for {_requested_license_name=}"
                        )

                    if _license_available >= _requested_license_count:
                        logger.info(
                            f"License Ask OK for {_requested_license_name}. Requested {_requested_license_count}, available {_license_available}"
                        )
                        override_license_count_for_pending_jobs[
                            _requested_license_name
                        ] = (_license_available + _requested_license_count)
                    else:
                        logger.error(
                            f"Requested {_requested_license_count}*{_requested_license_name} but only {_license_available} available"
                        )
                        _license_error = True
                else:
                    logger.error(
                        f"Unable to query {_license_provider} for {_requested_license_name} due to {_license_query.get('message')}"
                    )
                    _license_error = True
            else:
                logger.warning(
                    f"Requested {_license} but this key has not been found on {license_mapping}"
                )

        if _license_error:
            return SocaResponse(
                success=False,
                message="Unable to validate License Requirements for this job. Will try again later",
            )
        else:
            return SocaResponse(
                success=True, message=override_license_count_for_pending_jobs
            )
    else:
        logger.info("No license needed, continuing with capacity provisioning")
        return SocaResponse(
            success=True, message=override_license_count_for_pending_jobs
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config", nargs="?", required=True, help="Path to a configuration file"
    )
    parser.add_argument(
        "-t",
        "--type",
        nargs="?",
        required=True,
        help="queue type - ex: compute .. Open YML file for more info",
    )
    arg = parser.parse_args()
    queue_config_file = arg.config
    queue_type = arg.type
    _cluster_id = SocaConfig(key="/configuration/ClusterId").get_value().message

    # Try to get a lock; if another dispatcher for the same queue is running, this instance will exit
    get_lock(process_name=f"{__file__} {queue_type}")

    # Create dispatcher logger, note a custom <queue_log> will be created for each queue
    # use soca_logger otherwise you may loose other utils logging
    logger_dispatcher = logging.getLogger("soca_logger")
    if logger_dispatcher.hasHandlers():
        logger_dispatcher.handlers.clear()

    logger_dispatcher = SocaLogger(name="soca_logger").timed_rotating_file_handler(
        file_path=f"/opt/soca/{_cluster_id}/cluster_manager/orchestrator/logs/dispatcher.log"
    )

    # Retrieve Default parameters for the queues
    _queues_configuration = load_queue_configuration(
        queue_config_file=queue_config_file, queue_type=queue_type
    )

    # Retrieve License mapping
    _license_mapping = load_license_mapping(
        license_mapping_file=f"/opt/soca/{_cluster_id}/cluster_manager/orchestrator/settings/licenses_mapping.yml"
    )

    # Track Future EC2 quota usage across multiple jobs.
    # Example: If we plan to launch 2 c6i.24xlarge instances, the first one (96 vCPUs) may not be running yet,
    # but we still need to count its vCPUs when scheduling the second job. This ensures we don’t exceed
    # account quotas by ignoring pending (yet-to-be-provisioned) capacity.
    _override_vcpus_quotas_for_pending_instances = {}

    # Track FUTURE EC2 RI usage across multiple jobs.
    # Example: If we plan to launch 2 c6i.24xlarge instances the first one may not be running yet,
    # but we still need to count its capacity (2 nodes) when scheduling the second job. This ensures we don’t exceed
    # account RI by ignoring pending (yet-to-be-provisioned) capacity.
    _override_pending_instances_count = 0

    # Track Future License Usage across multiple jobs.
    # Example: If we plan to launch 2 jobs that will need mylic1=5, the first one may not be running yet,
    # but we still need to count the 5 licenses to be used when scheduling the second job. This ensures we don’t exceed
    # licenses count by ignoring pending (yet-to-be-provisioned) capacity.
    _override_license_count_for_pending_jobs = {}

    # Retrieve all configured/enabled schedulers
    _schedulers_to_query = get_schedulers()
    for _scheduler in _schedulers_to_query:
        if _scheduler.soca_managed_nodes_provisioning is False:
            logger.info(
                f"Skipping scheduler {_scheduler.identifier} as soca_managed_nodes_provisioning is set to False"
            )
            continue

        logger_dispatcher.info(f"Fetching jobs for {_scheduler.identifier}")

        # Process all queues
        for queue in _queues_configuration.queues:
            _log_file_location = f"/opt/soca/{_cluster_id}/cluster_manager/orchestrator/logs/{_scheduler.identifier}_{queue}.log"

            # use soca_logger otherwise you may loose other utils logging
            logger = logging.getLogger("soca_logger")

            # Remove existing handlers (prevents duplicates when a queue type has multiple queue)
            if logger.hasHandlers():
                logger.handlers.clear()

            # Create one logger per queue
            logger = SocaLogger(name="soca_logger").timed_rotating_file_handler(
                file_path=_log_file_location
            )

            logger.info(f"Retrieving jobs for {queue=}")
            logger.debug(f"Scheduler Configuration: {_scheduler}")
            logger.debug(f"Queues Configuration: {_queues_configuration}")

            if (
                get_jobs_response := SocaHpcJobFetcher(
                    scheduler_info=_scheduler
                ).by_queue(queue=queue)
            ).get("success"):
                get_jobs = get_jobs_response.get("message")
                if not get_jobs:
                    logger.info(f"No jobs found for {queue=}")
                    continue
                else:
                    logger.info(f"Retrieved jobs: {get_jobs=}")
            else:
                logger.error(
                    f"Unable to retrieve jobs for {queue=} due to {str(get_jobs_response.get('message', '')).replace('\n', ' ').replace('\r', ' ')}"
                )
                continue

            # Checking if we don't already have hit the queue limit in term of running jobs
            _current_running_jobs = sum(
                1 for job in get_jobs if job.job_state == SocaHpcJobState.RUNNING
            )
            logger.info(
                f"Detected {_current_running_jobs=} running jobs in {queue=}, max_running_job is {_queues_configuration.max_running_jobs=}"
            )
            if (
                _queues_configuration.max_running_jobs is not None
                and _current_running_jobs >= _queues_configuration.max_running_jobs
            ):
                logger.info(
                    f"Maximum number of running jobs reached for {queue=}, skipping queue ..."
                )
                continue

            # Checking if we don't already have hit the queue limit for concurrent provisioned nodes
            _current_provisioned_instances = sum(job.nodes for job in get_jobs)
            logger.info(
                f"Detected {_current_provisioned_instances=} provisioned nodes in {queue=}, max_provisioned_instances is {_queues_configuration.max_provisioned_instances=}"
            )
            if (
                _queues_configuration.max_provisioned_instances is not None
                and _current_provisioned_instances
                >= _queues_configuration.max_provisioned_instances
            ):
                logger.info(
                    f"Maximum number of instances reached for {queue=}, skipping queue ..."
                )
                continue

            # Process all queued jobs in this queue
            for job in get_jobs:
                if job.job_state == SocaHpcJobState.QUEUED:
                    logger.info(f"Processing queued {job.job_id=}")
                    logger.debug(f"{job.job_id=} Info: {job}")

                    # Check if job has unset resources
                    # If yes, we try to inherit them from the default value specified for the queue
                    logger.info(
                        f"Checking if {job.job_id=} has unset fields and replace them with default queue values if available"
                    )
                    if job.job_compute_node in ["tbd", "-1"]:
                        # only apply resource if the compute_node is not defined, otherwise it means the default_queue_values have already been applied
                        # tbd = OpenPBS/PBSPro
                        # -1 = LSF (as you cannot use String for RES_REQ)
                        job.apply_default_queue_values(
                            queue_configuration=_queues_configuration,
                            scheduler_info=job.job_scheduler_info,
                        )

                    if (
                        job.job_provisioning_state
                        != SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_BLOCKED
                    ):
                        # Continue provisioning logic
                        logger.info(
                            f"Checking if {job.job_id=} has license requirements {job.licenses=}"
                        )
                        _check_license = verify_job_licenses_requirements(
                            job_info=job,
                            license_mapping=_license_mapping,
                            override_license_count_for_pending_jobs=_override_license_count_for_pending_jobs,
                        )
                        if _check_license.get("success") is False:
                            SocaHpcJobController(job=job).set_error_message(
                                errors=[_check_license.get("message")]
                            )
                            logger.error(
                                f"License ask for job {job.job_id=} has been rejected"
                            )
                            continue
                        else:
                            logger.info(
                                f"License ask for job {job.job_id=} has been validated successfully"
                            )
                            _override_license_count_for_pending_jobs = (
                                _check_license.get("message")
                            )

                        logger.info(
                            f"Validating all resources associated to {job.job_id=}"
                        )
                        _is_job_config_valid = job.validate()
                        if _is_job_config_valid.get("success") is False:
                            # note: error_message is automatically updated via is_valid(), no need to call SocaHpcJobController here
                            logger.error(
                                f"Unable to validate job {job.job_id=}: {_is_job_config_valid.get('message')}"
                            )
                            continue
                        else:
                            logger.info(f"Validated Job Data: {job=}")

                        logger.info(
                            f"Queued Job {job.job_id=} has valid config, trying to see if we can provision compute for it. Provisioning state is {job.job_provisioning_state}"
                        )

                        if (
                            job.job_provisioning_state
                            == SocaHpcJobProvisioningState.PENDING
                        ):
                            logger.info(
                                f"{job.job_id=} is currently queued and no CloudFormation Stack is set, trying to provision compute for this job"
                            )
                            # Verify job provisioning won't hit the maximum number of concurrent running jobs allowed for the queue
                            if (
                                _queues_configuration.max_running_jobs is not None
                                and _current_running_jobs + 1
                                > _queues_configuration.max_running_jobs
                            ):
                                logger.info(
                                    f"{job.job_id} will provision {job.nodes} additional nodes. This will hit the aximum number of concurrent running jobs for this {queue=} which is {_queues_configuration.max_running_jobs=}, job won't be provisioned until other jobs finish"
                                )
                                break  # exit the loop entirely as no other jobs on this queue can be provisioned at this time
                            else:
                                _current_running_jobs + 1

                            # Verify job provisioning won't hit the maximum number of concurrent provisioned instances allowed for the queue
                            if (
                                _queues_configuration.max_provisioned_instances
                                is not None
                                and _current_provisioned_instances + job.nodes
                                > _queues_configuration.max_provisioned_instances
                            ):
                                logger.info(
                                    f"{job.job_id} will provision {job.nodes} additional nodes. This will hit the aximum number of instances reached for this {queue=} which is {_queues_configuration.max_provisioned_instances=}, job won't be provisioned until other jobs finish"
                                )
                                continue
                            else:
                                _current_provisioned_instances += job.nodes

                            if job.force_ri:
                                _ri_validated = True
                                for _instance_type in job.instance_type:
                                    logger.info(
                                        f"force_ri detected, validating current Reserved Instance coverage for {_instance_type}"
                                    )
                                    if (
                                        validate_instance_ri_coverage(
                                            instance_type=_instance_type,
                                            desired_capacity=job.nodes,
                                            override_pending_instances_count=_override_pending_instances_count,
                                        ).get("success")
                                        is False
                                    ):
                                        logger.error(
                                            f"Unable to get RI for {_instance_type}"
                                        )
                                        _ri_validated = False
                                        break
                                    else:
                                        _override_pending_instances_count += job.nodes

                                if _ri_validated is False:
                                    SocaHpcJobController(job=job).set_error_message(
                                        errors=["Unable to validate ReservedInstances"]
                                    )
                                    continue

                                logger.info(
                                    f"Reserved Instance coverage validated for {job.job_id=}"
                                )

                            logger.info(
                                "All check passed, provisioning capacity via CloudFormation"
                            )

                            _capacity_provisioning = job.provision_capacity(
                                cluster_id=_cluster_id,
                                stack_name=f"{_cluster_id}-job-{job.job_id}-{_scheduler.identifier}",
                                keep_forever=False,
                                terminate_when_idle=0,
                                override_vcpus_quotas_for_pending_instances=_override_vcpus_quotas_for_pending_instances,
                            )
                            if _capacity_provisioning.get("success") is False:
                                logger.error(
                                    f"Unable to provision capacity for {job.job_id=} due to {_capacity_provisioning.get('message')}"
                                )
                                continue
                            else:

                                _provisioning_result_message = (
                                    _capacity_provisioning.get("message")
                                )
                                _override_vcpus_quotas_for_pending_instances = (
                                    _provisioning_result_message.get(
                                        "override_vcpus_quotas_for_pending_instances"
                                    )
                                )
                                logger.info(
                                    f"Successfully provisioned capacity for {job.job_id=} via CloudFormation Stack {_provisioning_result_message.get('stack_name')}"
                                )

                        elif (
                            job.job_provisioning_state
                            == SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_COMPLETE
                        ):
                            logger.info(
                                f"{job.job_id=} is currently queued and SocaHpcJobProvisioningState is COMPUTE_PROVISIONING_COMPLETE, checking grace period"
                            )
                            logger.warning(
                                f"{job.job_id=} is currently Queued but has a valid cloudformation stack associated {job.stack_id=}"
                            )
                            _job_queued_at = datetime.fromtimestamp(job.job_queue_time)
                            _now = datetime.now()
                            if _now - _job_queued_at > timedelta(minutes=30):
                                logger.warning(
                                    f"{job.job_id=} has been queued since {_job_queued_at} ({(_now - _job_queued_at).seconds // 60} minutes ago and has a CREATE_COMPLETE CloudFormation stack, verify job log to  clear any potential bootstrap failure. SOCA will try to re-provision it"
                                )
                                _refresh_stack = SocaHpcJobController(
                                    job=job
                                ).refresh_cloudformation_stack()

                                if _refresh_stack.get("success") is False:
                                    logger.error(
                                        f"Unable to refresh stack for {job.job_id=} due to {_refresh_stack.get('message')}"
                                    )
                                    SocaHpcJobController(job=job).set_error_message(
                                        errors=[_refresh_stack.get("message")],
                                    )
                                    continue

                        elif (
                            job.job_provisioning_state
                            == SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_ERROR
                        ):
                            logger.info(
                                f"{job.job_id=} is currently queued and SocaHpcJobProvisioningState is in COMPUTE_PROVISIONING_ERROR, CloudFormation Stack is being deleted automatically and job will be re-processed shortly ..."
                            )

                        elif (
                            job.job_provisioning_state
                            == SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_IN_PROGRESS
                        ):
                            logger.info(
                                f"{job.job_id=} is currently queued and SocaHpcJobProvisioningState is still COMPUTE_PROVISIONING_IN_PROGRESS, waiting for all capacity to be provisioned which should happen shortly."
                            )
                            continue

                        elif (
                            job.job_provisioning_state
                            == SocaHpcJobProvisioningState.COMPUTE_PROVISIONING_DELETE
                        ):
                            logger.info(
                                f"{job.job_id} capacity is currently being deleted, skipping job ... "
                            )
                            continue

                        else:
                            logger.error(
                                f"Unsupported {job.job_provisioning_state} for {job.job_id=}, skipping job ... "
                            )
                            continue

                    else:
                        logger.info(
                            f"job {job.job_id=} is currently in {job.job_provisioning_state=}, skipping job ..."
                        )
                else:
                    logger.info(
                        f"job {job.job_id=} is not pending. Current State {job.job_state=}, skipping job ...."
                    )
