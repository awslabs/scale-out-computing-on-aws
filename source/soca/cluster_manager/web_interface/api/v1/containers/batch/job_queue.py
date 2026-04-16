# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from flask_restful import Resource, reqparse
import logging
from decorators import private_api, feature_flag
from utils.config import SocaConfig
from utils.error import SocaError
from utils.aws.batch_client import SocaAWSBatchClient

from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


class BatchJobQueue(Resource):
    @private_api
    @feature_flag(flag_name="CONTAINERS_MANAGEMENT_BATCH", mode="api")
    def get(self):
        """
        List AWS Batch Job Queues
        ---
        openapi: 3.1.0
        operationId: listBatchJobQueues
        tags:
          - AWS Batch
        summary: List AWS Batch job queues visible to this EDH environment
        description: |
          Retrieves AWS Batch job queues that are tagged with the EDH visibility tag for this cluster.
          Only queues with status VALID and state ENABLED are returned.
          If a specific job queue name is provided, only that queue is returned (if it has the correct tag).
          Otherwise, all matching queues are returned with pagination handled automatically.
        parameters:
          - name: X-EDH-USER
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
            description: SOCA username for authentication
            example: "john.doe"
          - name: X-EDH-TOKEN
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 256
            description: SOCA authentication token
            example: "abc123token456"
          - name: job_queue
            in: query
            required: false
            schema:
              type: string
              maxLength: 256
            description: Name or ARN of a specific job queue to look up. If omitted, all visible job queues are returned.
            example: "my-job-queue"
        responses:
          '200':
            description: Job queues retrieved successfully
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: array
                      items:
                        type: object
                        properties:
                          jobQueueName:
                            type: string
                            example: "my-job-queue"
                          jobQueueArn:
                            type: string
                            example: "arn:aws:batch:us-east-1:123456789012:job-queue/my-job-queue"
                          jobQueueType:
                            type: string
                            example: "STANDARD"
                          state:
                            type: string
                            enum: ["ENABLED", "DISABLED"]
                            example: "ENABLED"
                          status:
                            type: string
                            enum: ["CREATING", "UPDATING", "DELETING", "DELETED", "VALID", "INVALID"]
                            example: "VALID"
                          priority:
                            type: integer
                            example: 1
                          computeEnvironmentOrder:
                            type: array
                            items:
                              type: object
                              properties:
                                order:
                                  type: integer
                                computeEnvironment:
                                  type: string
                          tags:
                            type: object
                            additionalProperties:
                              type: string
          '400':
            description: Bad request - feature disabled or invalid parameters
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Feature CONTAINERS_MANAGEMENT_BATCH is not enabled"
          '401':
            description: Unauthorized - invalid authentication
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Not authorized"
          '403':
            description: Forbidden - IAM permission error
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "IAM permission error: the role does not have sufficient permissions to call batch:DescribeJobQueues."
          '500':
            description: Internal server error
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Error retrieving job queues. See log for more details"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("job_queue", type=str, location="args")
        args = parser.parse_args()

        _soca_cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().get("message")
        )

        _job_queue = args.get("job_queue", "")
        _supported_job_queues = []
        _batch_client = SocaAWSBatchClient()

        if not _job_queue:
            logger.info(
                f"AWS Batch Job Queue not specified, listing all AWS Batch Job Queues that match edh:visibility:{_soca_cluster_id} = true"
            )
            next_token = None
            while True:
                _response = _batch_client.describe_job_queues(next_token=next_token)

                if _response.get("success") is False:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Unable to describe job queues: {_response.get('message')}"
                    ).as_flask()

                _result = _response.get("message", {})

                for queue in _result.get("jobQueues", []):
                    logger.debug(f"Found AWS Batch Job Queue {queue}")

                    if queue.get("status") != "VALID":
                        logger.warning(
                            f"Ignoring {queue.get('jobQueueName')} because status is not VALID"
                        )
                        continue

                    if queue.get("state") != "ENABLED":
                        logger.warning(
                            f"Ignoring {queue.get('jobQueueName')} because state is not ENABLED"
                        )
                        continue

                    tags = queue.get("tags", {})
                    if (
                        tags.get(f"edh:visibility:{_soca_cluster_id}", "").lower()
                        == "true"
                    ):
                        logger.info(
                            f"AWS Batch Queue {queue.get('jobQueueName')} matches edh:visibility:{_soca_cluster_id} tag"
                        )
                        _supported_job_queues.append(queue)
                    else:
                        logger.warning(
                            f"Ignoring {queue.get('jobQueueName')} because edh:visibility:{_soca_cluster_id} is not set to true"
                        )

                next_token = _result.get("nextToken")
                if not next_token:
                    break
        else:
            logger.info(f"Looking up specific AWS Batch Job Queue: {_job_queue}")

            _response = _batch_client.describe_job_queues(job_queues=[_job_queue])

            if _response.get("success") is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to describe job queue {_job_queue}: {_response.get('message')}"
                ).as_flask()

            _result = _response.get("message", {})
            for queue in _result.get("jobQueues", []):
                tags = queue.get("tags", {})
                if (
                    tags.get(f"edh:visibility:{_soca_cluster_id}", "").lower()
                    == "true"
                ):
                    logger.info(
                        f"AWS Batch Queue {queue.get('jobQueueName')} has edh:visibility:{_soca_cluster_id} tag"
                    )
                    _supported_job_queues.append(queue)
                else:
                    logger.warning(
                        f"Job Queue {_job_queue} exists but edh:visibility:{_soca_cluster_id} is not set to true"
                    )

        logger.debug(f"Returning supported job queues: {_supported_job_queues}")
        return SocaResponse(success=True, message=_supported_job_queues).as_flask()
