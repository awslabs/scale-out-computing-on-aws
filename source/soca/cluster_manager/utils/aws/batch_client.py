# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from functools import wraps
from typing import Optional, Dict, Any, Callable, Union, List

from utils.aws.boto3_wrapper import get_boto
from utils.response import SocaResponse
from utils.error import SocaError
from utils.config import SocaConfig

logger = logging.getLogger("soca_logger")


def aws_batch_api_wrapper(
    helper_message: str = "An error occurred while calling the AWS Batch API.",
) -> Callable:
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(self, *args: Any, **kwargs: Any) -> Union[SocaResponse, SocaError]:
            try:
                result = func(self, *args, **kwargs)
                return SocaResponse(success=True, message=result)
            except Exception as e:
                logger.error(f"AWS Batch error in {func.__name__}: {e}")
                return SocaError.GENERIC_ERROR(helper=helper_message)

        return wrapper

    return decorator


class SocaAWSBatchClient:
    """
    AWS Batch helper
    """

    def __init__(self, region: Optional[str] = None):
        self._soca_config = SocaConfig(key="/").get_value(return_as=dict).get("message")
        if region is None:
            region = self._soca_config.get("/configuration/Region")
            logger.debug(
                f"No region specified for SocaAWSBatchClient, default to {region}"
            )

        self._batch_client = get_boto(service_name="batch", region_name=region).get(
            "message"
        )

    # --- Jobs ---

    @aws_batch_api_wrapper("Unable to list AWS Batch jobs.")
    def list_jobs(
        self,
        job_queue: str,
        job_status: Optional[str] = None,
        max_results: int = 100,
        next_token: Optional[str] = None,
    ) -> Dict:
        params = {
            "jobQueue": job_queue,
            "maxResults": max_results,
        }
        if job_status:
            params["jobStatus"] = job_status
        if next_token:
            params["nextToken"] = next_token
        return self._batch_client.list_jobs(**params)

    @aws_batch_api_wrapper("Unable to describe AWS Batch jobs.")
    def describe_jobs(self, job_ids: List[str]) -> Dict:
        return self._batch_client.describe_jobs(jobs=job_ids)

    @aws_batch_api_wrapper("Unable to submit AWS Batch job.")
    def submit_job(
        self,
        job_name: str,
        job_queue: str,
        job_definition: str,
        timeout: Dict[str, Any],
        depends_on: Optional[List[Dict[str, Any]]] = [],
        parameters: Optional[Dict[str, str]] = None,
        container_overrides: Optional[Dict[str, Any]] = None,
        array_properties: Optional[Dict[str, Any]] = None,
        retry_strategy: Optional[Dict[str, Any]] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> Dict:
        payload = {
            "jobName": job_name,
            "jobQueue": job_queue,
            "jobDefinition": job_definition,
        }

        if timeout:
            payload["timeout"] = timeout
        if depends_on:
            payload["dependsOn"] = depends_on
        if retry_strategy:
            payload["retryStrategy"] = retry_strategy
        if array_properties:
            payload["arrayProperties"] = array_properties
        if parameters:
            payload["parameters"] = parameters
        if container_overrides:
            payload["containerOverrides"] = container_overrides
        if tags:
            payload["tags"] = tags
            
        return self._batch_client.submit_job(**payload)

    @aws_batch_api_wrapper("Unable to terminate AWS Batch job.")
    def terminate_job(self, job_id: str, reason: str) -> Dict:
        return self._batch_client.terminate_job(
            jobId=job_id,
            reason=reason,
        )

    # --- Job Queues ---

    @aws_batch_api_wrapper("Unable to describe AWS Batch job queues.")
    def describe_job_queues(
        self,
        job_queues: Optional[List[str]] = None,
        next_token: Optional[str] = None,
    ) -> Dict:
        params = {}
        if job_queues:
            params["jobQueues"] = job_queues
        if next_token:
            params["nextToken"] = next_token
        return self._batch_client.describe_job_queues(**params)

    @aws_batch_api_wrapper("Unable to create AWS Batch job queue.")
    def create_job_queue(
        self,
        job_queue_name: str,
        priority: int,
        compute_environment_order: List[Dict[str, Any]],
        state: str = "ENABLED",
    ) -> Dict:
        return self._batch_client.create_job_queue(
            jobQueueName=job_queue_name,
            priority=priority,
            computeEnvironmentOrder=compute_environment_order,
            state=state,
        )

    @aws_batch_api_wrapper("Unable to update AWS Batch job queue.")
    def update_job_queue(
        self,
        job_queue: str,
        priority: Optional[int] = None,
        compute_environment_order: Optional[List[Dict[str, Any]]] = None,
        state: Optional[str] = None,
    ) -> Dict:
        params = {"jobQueue": job_queue}
        if priority is not None:
            params["priority"] = priority
        if compute_environment_order:
            params["computeEnvironmentOrder"] = compute_environment_order
        if state:
            params["state"] = state
        return self._batch_client.update_job_queue(**params)

    # --- Compute Environments ---

    @aws_batch_api_wrapper("Unable to describe AWS Batch compute environments.")
    def describe_compute_environments(
        self, compute_environments: Optional[List[str]] = None
    ) -> Dict:
        params = {}
        if compute_environments:
            params["computeEnvironments"] = compute_environments
        return self._batch_client.describe_compute_environments(**params)

    @aws_batch_api_wrapper("Unable to create AWS Batch compute environment.")
    def create_compute_environment(
        self,
        compute_environment_name: str,
        compute_resources: Dict[str, Any],
        type: str = "MANAGED",
        state: str = "ENABLED",
        service_role: Optional[str] = None,
    ) -> Dict:

        if service_role is None:
            service_role = self._soca_config.get("/configuration/ComputeNodeIamRole")
            logger.info("service_role not specified, defaulting to ")
        return self._batch_client.create_compute_environment(
            computeEnvironmentName=compute_environment_name,
            type=type,
            state=state,
            serviceRole=service_role,
            computeResources=compute_resources,
        )

    @aws_batch_api_wrapper("Unable to update AWS Batch compute environment.")
    def update_compute_environment(
        self,
        compute_environment: str,
        compute_resources: Optional[Dict[str, Any]] = None,
        state: Optional[str] = None,
    ) -> Dict:
        params = {"computeEnvironment": compute_environment}
        if compute_resources:
            params["computeResources"] = compute_resources
        if state:
            params["state"] = state
        return self._batch_client.update_compute_environment(**params)

    # --- Job Definitions ---

    @aws_batch_api_wrapper("Unable to describe AWS Batch job definitions.")
    def describe_job_definitions(
        self,
        job_definition_name: Optional[str] = None,
        status: Optional[str] = None,
        next_token: Optional[str] = None,
    ) -> Dict:
        params = {}
        if job_definition_name:
            params["jobDefinitionName"] = job_definition_name
        if status:
            params["status"] = status
        if next_token:
            params["nextToken"] = next_token
        return self._batch_client.describe_job_definitions(**params)

    @aws_batch_api_wrapper("Unable to register AWS Batch job definition.")
    def register_job_definition(
        self,
        job_definition_name: str,
        type: str,
        container_properties: Dict[str, Any],
        retry_strategy: Optional[Dict[str, Any]] = None,
        timeout: Optional[Dict[str, Any]] = None,
        parameters: Optional[Dict[str, str]] = None,
        platform_capabilities: Optional[List[str]] = None,
        tags: Optional[Dict[str, str]] = None,
    ) -> Dict:
        payload = {
            "jobDefinitionName": job_definition_name,
            "type": type,
            "containerProperties": container_properties,
        }

        if retry_strategy:
            payload["retryStrategy"] = retry_strategy
        if timeout:
            payload["timeout"] = timeout
        if parameters:
            payload["parameters"] = parameters
        if platform_capabilities:
            payload["platformCapabilities"] = platform_capabilities
        if tags:
            payload["tags"] = tags

        return self._batch_client.register_job_definition(**payload)

    @aws_batch_api_wrapper("Unable to deregister AWS Batch job definition.")
    def deregister_job_definition(self, job_definition: str) -> Dict:
        return self._batch_client.deregister_job_definition(
            jobDefinition=job_definition
        )
