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
_eks_client = get_boto(service_name="eks").message


class EKSListClusters(Resource):
    @private_api
    @feature_flag(flag_name="CONTAINERS_MANAGEMENT", mode="api")
    def get(self):
        """
        List EKS Clusters
        ---
        openapi: 3.1.0
        operationId: listEksClusters
        tags:
          - Elastic Kubernetes Service (EKS)
        summary: List available EKS clusters
        description: Retrieves a list of EKS clusters that are tagged for visibility with the current SOCA cluster ID
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
          - name: cluster
            in: query
            required: false
            schema:
              type: string
              pattern: '^[a-zA-Z0-9._-]+(,[a-zA-Z0-9._-]+)*$'
              maxLength: 1000
            description: Comma-separated list of specific cluster names to validate (optional)
            example: "cluster1,cluster2"
        responses:
          '200':
            description: EKS clusters retrieved successfully
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
                        type: string
                        minLength: 1
                        maxLength: 100
                        pattern: '^[a-zA-Z0-9._-]+$'
                      description: List of available EKS cluster names
                      example: ["my-soca-cluster-1", "my-soca-cluster-2"]
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
          '403':
            description: Forbidden - insufficient permissions
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
                      example: "Access denied to EKS resources"
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
                      example: "Unable to list EKS clusters"
        """
        parser = reqparse.RequestParser()
        parser.add_argument(
            "cluster", type=str, location="args"
        )  # accept csv of repository name (not arn)
        args = parser.parse_args()

        _soca_cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().get("message")
        )

        _cluster = args.get("cluster", "")
        _supported_eks_clusters = []
        if not _cluster:
            logger.info(
                f"Cluster not specified, listing all EKS cluster that match soca:ClusterId = {_soca_cluster_id}"
            )
            next_token = None

            while True:
                if next_token:
                    response = _eks_client.list_clusters(nextToken=next_token)
                else:
                    response = _eks_client.list_clusters()

                cluster_names = response.get("clusters", [])

                for name in cluster_names:
                    cluster_info = _eks_client.describe_cluster(name=name)["cluster"]
                    cluster_arn = cluster_info["arn"]

                    tags_response = _eks_client.list_tags_for_resource(
                        resourceArn=cluster_arn
                    )
                    tags = tags_response.get("tags", {})
                    logging.info(f"Tags {tags} for cluster {name}")
                    if (
                        tags.get(f"soca:visibility:{_soca_cluster_id}", "").lower()
                        == "true"
                    ):
                        _supported_eks_clusters.append(name)

                next_token = response.get("nextToken")
                if not next_token:
                    break
        else:
            # Customer provided list of EKS.
            # Not in use for now, but we can imagine in the future adding a SSM key that list all allowed EKS
            # instead of relying on repository tag
            for cluster in _cluster.split(","):
                logger.debug(f"Validating customer specified EKS cluster {cluster}")
                try:
                    _eks_client.describe_cluster(name=_cluster)
                    _supported_eks_clusters.append(_cluster)
                except Exception as e:
                    logger.error(f"Error while validating {cluster}: {e}")
                    continue
        return SocaResponse(success=True, message=_supported_eks_clusters).as_flask()
