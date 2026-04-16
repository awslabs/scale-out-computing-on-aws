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


class BatchJobDefinition(Resource):
    @private_api
    @feature_flag(flag_name="CONTAINERS_MANAGEMENT_BATCH", mode="api")
    def get(self):
        """
        List AWS Batch Job Definitions
        ---
        openapi: 3.1.0
        operationId: listBatchJobDefinitions
        tags:
          - AWS Batch
        summary: List AWS Batch job definitions visible to this EDH environment
        description: |
          Retrieves AWS Batch job definitions that are tagged with the EDH visibility tag for this cluster.
          If a specific job definition name is provided, only that definition is returned (if it has the correct tag).
          Otherwise, all matching definitions are returned with pagination handled automatically.
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
          - name: job_definition
            in: query
            required: false
            schema:
              type: string
              maxLength: 256
            description: Name of a specific job definition to look up. If omitted, all visible job definitions are returned.
            example: "my-job-def"
          - name: status
            in: query
            required: false
            schema:
              type: string
              enum: ["ACTIVE", "INACTIVE"]
              default: "ACTIVE"
            description: Filter job definitions by status
            example: "ACTIVE"
        responses:
          '200':
            description: Job definitions retrieved successfully
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
                          jobDefinitionName:
                            type: string
                            example: "my-job-def"
                          jobDefinitionArn:
                            type: string
                            example: "arn:aws:batch:us-east-1:123456789012:job-definition/my-job-def:1"
                          revision:
                            type: integer
                            example: 1
                          status:
                            type: string
                            example: "ACTIVE"
                          type:
                            type: string
                            example: "container"
                          containerProperties:
                            type: object
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
                      example: "IAM permission error: the role does not have sufficient permissions to call batch:DescribeJobDefinitions."
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
                      example: "Error retrieving job definitions. See log for more details"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("job_definition", type=str, location="args")
        parser.add_argument("status", type=str, location="args")
        args = parser.parse_args()

        _soca_cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().get("message")
        )

        _job_definition = args.get("job_definition", "")
        _status = args.get("status") or "ACTIVE"
        _supported_job_definitions = []
        _batch_client = SocaAWSBatchClient()

        if not _job_definition:
            logger.info(
                f"AWS Batch Job Definition not specified, listing all AWS Batch Job Definitions with status {_status} that match edh:visibility:{_soca_cluster_id} = true"
            )
            next_token = None
            while True:
                _response = _batch_client.describe_job_definitions(
                    status=_status,
                    next_token=next_token,
                )

                if _response.get("success") is False:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Unable to describe job definitions: {_response.get('message')}"
                    ).as_flask()

                _result = _response.get("message", {})

                for job_def in _result.get("jobDefinitions", []):
                    logger.debug(f"Found AWS Batch Job Definition {job_def.get('jobDefinitionName')}")
                    tags = job_def.get("tags", {})
                    if (
                        tags.get(f"edh:visibility:{_soca_cluster_id}", "").lower()
                        == "true"
                    ):
                        logger.info(
                            f"AWS Batch Job Definition {job_def.get('jobDefinitionName')} matches edh:visibility:{_soca_cluster_id} tag"
                        )
                        _supported_job_definitions.append(job_def)
                    else:
                        logger.warning(
                            f"Ignoring {job_def.get('jobDefinitionName')} because edh:visibility:{_soca_cluster_id} is not set to true"
                        )

                next_token = _result.get("nextToken")
                if not next_token:
                    break
        else:
            logger.info(f"Looking up specific AWS Batch Job Definition: {_job_definition}")

            _response = _batch_client.describe_job_definitions(
                job_definition_name=_job_definition,
                status=_status,
            )

            if _response.get("success") is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to describe job definition {_job_definition}: {_response.get('message')}"
                ).as_flask()

            _result = _response.get("message", {})
            for job_def in _result.get("jobDefinitions", []):
                tags = job_def.get("tags", {})
                if (
                    tags.get(f"edh:visibility:{_soca_cluster_id}", "").lower()
                    == "true"
                ):
                    logger.info(
                        f"AWS Batch Job Definition {job_def.get('jobDefinitionName')} has edh:visibility:{_soca_cluster_id} tag"
                    )
                    _supported_job_definitions.append(job_def)
                else:
                    logger.warning(
                        f"Job Definition {_job_definition} exists but edh:visibility:{_soca_cluster_id} is not set to true"
                    )

        logger.debug(f"Returning supported job definitions: {_supported_job_definitions}")
        return SocaResponse(success=True, message=_supported_job_definitions).as_flask()
