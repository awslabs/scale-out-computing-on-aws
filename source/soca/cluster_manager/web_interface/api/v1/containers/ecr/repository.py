# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from flask_restful import Resource, reqparse
from flask import request
import logging
from flask import Response
from decorators import private_api, feature_flag
from utils.aws.ssm_parameter_store import SocaConfig
from utils.error import SocaError
import base64
import ast
from models import db, VirtualDesktopSessions
from utils.aws.boto3_wrapper import get_boto

from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")
_ecr_client = get_boto(service_name="ecr").message
_sts_client = get_boto(service_name="sts").message


class ECRRepository(Resource):
    @private_api
    @feature_flag(flag_name="CONTAINERS_MANAGEMENT", mode="api")
    def get(self):
        """
        List ECR Repository Images
        ---
        openapi: 3.1.0
        operationId: listEcrRepositoryImages
        tags:
          - Elastic Container Registry (ECR)
        summary: Retrieve ECR repository images
        description: Lists Amazon ECR images from repositories tagged with the current SOCA cluster ID
        parameters:
          - name: X-SOCA-USER
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
            description: SOCA username for authentication
            example: "john.doe"
          - name: X-SOCA-TOKEN
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 256
            description: SOCA authentication token
            example: "abc123token456"
          - name: repository
            in: query
            required: false
            schema:
              type: string
              pattern: '^[a-zA-Z0-9._-]+(,[a-zA-Z0-9._-]+)*$'
              maxLength: 1000
            description: Comma-separated list of ECR repository names to inspect
            example: "my-app,my-service"
        responses:
          '200':
            description: ECR images retrieved successfully
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
                      type: object
                      additionalProperties:
                        type: array
                        items:
                          type: object
                          required:
                            - imageDigest
                            - imageUri
                            - pushedAt
                            - imageSizeInMB
                          properties:
                            imageTag:
                              type: string
                              nullable: true
                              example: "latest"
                            imageDigest:
                              type: string
                              pattern: f'^sha256:[a-f0-9]{64}$'
                              example: "sha256:abc123def456"
                            imageUri:
                              type: string
                              format: uri
                              example: "123456789.dkr.ecr.us-east-1.amazonaws.com/my-app:latest"
                            pushedAt:
                              type: string
                              format: date-time
                              example: "2024-01-15 10:30:00"
                            imageSizeInMB:
                              type: number
                              minimum: 0
                              example: 125.5
                      example:
                        "my-app":
                          - imageTag: "latest"
                            imageDigest: "sha256:abc123def456"
                            imageUri: "123456789.dkr.ecr.us-east-1.amazonaws.com/my-app:latest"
                            pushedAt: "2024-01-15 10:30:00"
                            imageSizeInMB: 125.5
          '400':
            description: Bad request - invalid parameters
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
                      example: "Invalid repository name format"
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
                      example: "Authentication failed"
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
                      example: "Unable to list ECR images"
        """
        parser = reqparse.RequestParser()
        args = parser.parse_args()
        parser.add_argument(
            "repository", type=str, location="args"
        )  # accept csv of repository name (not arn)

        _soca_cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().get("message")
        )

        _region = _ecr_client.meta.region_name
        _sts_caller_identity = _sts_client.get_caller_identity()
        _account_id = _sts_caller_identity.get("Account")
        if _sts_caller_identity.get("Arn").startswith("arn:aws-cn"):
            _aws_domain_partition = "amazonaws.com.cn"
        else:
            # note: govcloud use the same name, the region will be different though
            _aws_domain_partition = "amazonaws.com"

        _repository = args.get("repository", "")
        _supported_ecr_repository = []
        try:
            if not _repository:
                logger.info(
                    f"List all ECR repository that match tag soca:visibility:{_soca_cluster_id} = true"
                )
                paginator = _ecr_client.get_paginator("describe_repositories")
                for page in paginator.paginate():
                    repositories = page["repositories"]
                    for repo in repositories:
                        _repo_arn = repo["repositoryArn"]
                        _repo_name = repo["repositoryName"]
                        tags_response = _ecr_client.list_tags_for_resource(
                            resourceArn=_repo_arn
                        )
                        tags = {
                            tag["Key"]: tag["Value"]
                            for tag in tags_response.get("tags", [])
                        }

                        # Filter by the desired tag
                        if (
                            tags.get(f"soca:visibility:{_soca_cluster_id}", "").lower()
                            != "true"
                        ):
                            continue  # Skip repositories not matching the tag
                        else:
                            _supported_ecr_repository.append(_repo_name)
            else:
                # Customer provided list of ECR.
                # Not in use for now, but we can imagine in the future adding a SSM key that list all allowed ECR
                # instead of relying on repository tag
                for repo in _repository.split(","):
                    logger.debug(f"Validating customer specified ECR repo {repo}")
                    try:
                        _ecr_client.describe_repositories(repositoryNames=[_repository])
                        _supported_ecr_repository.append(repo)
                    except Exception as err:
                        logger.error(
                            f"Error while listing ECR repository {repo}, (note: must use Name and not Arn): {err}"
                        )
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                f"Unable to Describe ECR Repository because of {err}"
            )

        # Get all images for each repository
        _all_images = {}

        try:
            for repo_name in _supported_ecr_repository:
                logger.info(f"List all images for repository {repo_name}")
                image_paginator = _ecr_client.get_paginator("list_images")
                _image_list = []
                for image_page in image_paginator.paginate(repositoryName=repo_name):
                    image_ids = image_page["imageIds"]
                    logger.debug(
                        f"Found {image_ids=} for repository {repo_name}, getting images metadatas"
                    )
                    # Now describe these images to get metadata
                    if image_ids:
                        response = _ecr_client.describe_images(
                            repositoryName=repo_name, imageIds=image_ids
                        )

                        for detail in response["imageDetails"]:
                            logger.debug(f"Image Details {detail=}")
                            image_tag = (
                                detail["imageTags"][0]
                                if "imageTags" in detail
                                else None
                            )
                            image_digest = detail["imageDigest"]

                            if image_tag:
                                image_uri = f"{_account_id}.dkr.ecr.{_region}.{_aws_domain_partition}/{repo_name}:{image_tag}"
                            else:
                                image_uri = f"{_account_id}.dkr.ecr.{_region}.{_aws_domain_partition}/{repo_name}@{image_digest}"

                            image_info = {
                                "imageTag": image_tag,
                                "imageDigest": image_digest,
                                "imageUri": image_uri,
                                "pushedAt": detail.get("imagePushedAt").strftime(
                                    "%Y-%m-%d %H:%M:%S"
                                ),
                                "imageSizeInMB": round(
                                    detail.get("imageSizeInBytes", 0) / (1024 * 1024), 2
                                ),
                            }

                            _image_list.append(image_info)

                _all_images[repo_name] = _image_list
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                f"Unable to list images on ECR because of {err}"
            )

        return SocaResponse(success=True, message=_all_images).as_flask()
