# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from flask_restful import Resource, reqparse
from flask import request
import logging
from kubernetes import client
from kubernetes.client.rest import ApiException
from decorators import private_api, feature_flag
from utils.aws.ssm_parameter_store import SocaConfig
from utils.aws.boto3_wrapper import get_boto
import json
from utils.response import SocaResponse
from utils.error import SocaError
from utils.aws.eks_client import SocaEKSClient


logger = logging.getLogger("soca_logger")


def full_serialize(obj):
    def default(o):
        try:
            return str(o)
        except Exception:
            return None

    return json.dumps(obj, default=default, indent=2)


class EKSJobs(Resource):
    @private_api
    @feature_flag(flag_name="CONTAINERS_MANAGEMENT", mode="api")
    def get(self):
        """
        List EKS Jobs
        ---
        openapi: 3.1.0
        operationId: listEksJobs
        tags:
          - Elastic Kubernetes Service (EKS)
        summary: List all EKS jobs owned by the current user
        description: Retrieves a list of all EKS jobs owned by the authenticated user across tagged EKS clusters
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
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 100
              pattern: '^[a-zA-Z0-9._-]+$'
            description: Name of the EKS cluster to query
            example: "my-soca-cluster"
          - name: namespace
            in: query
            required: false
            schema:
              type: string
              minLength: 1
              maxLength: 63
              pattern: '^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
              default: "default"
            description: Kubernetes namespace to search in
            example: "default"
        responses:
          '200':
            description: Jobs retrieved successfully
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
                        type: object
                        required:
                          - metadata
                          - status
                          - pod_ips
                          - images
                          - eks_cluster
                        properties:
                          metadata:
                            type: object
                            properties:
                              name:
                                type: string
                                example: "simulation-job-001"
                              namespace:
                                type: string
                                example: "default"
                          status:
                            type: object
                            properties:
                              active:
                                type: integer
                                minimum: 0
                                example: 1
                          pod_ips:
                            type: array
                            items:
                              type: string
                              format: ipv4
                            example: ["10.0.1.100"]
                          images:
                            type: array
                            items:
                              type: string
                            example: ["nginx:latest"]
                          eks_cluster:
                            type: string
                            example: "my-soca-cluster"
                      example:
                        "job-uid-123":
                          metadata:
                            name: "simulation-job-001"
                            namespace: "default"
                          status:
                            active: 1
                          pod_ips:
                            - "10.0.1.100"
                          images:
                            - "nginx:latest"
                          eks_cluster: "my-soca-cluster"
          '400':
            description: Bad request - missing required parameters
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
                      example: "Missing required parameter: cluster"
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
                      example: "Unauthorized: Verify if the IAM role is allowed to connect to cluster"
          '404':
            description: Namespace not found
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
                      example: "Namespace not found on your EKS cluster"
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
                      example: "Error listing jobs across clusters"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("cluster", type=str, location="args")
        parser.add_argument("namespace", type=str, location="args")
        args = parser.parse_args()

        logger.info(f"Received EKS List Jobs for {locals()}")
        _user = request.headers.get("X-SOCA-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        _cluster = args.get("cluster") or ""
        if not _cluster:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="cluster").as_flask()

        _namespace = args.get("namespace") or "default"
        _soca_cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().get("message")
        )
        _jobs = {}
        try:
            resource_tagging = get_boto(service_name="resourcegroupstaggingapi").message

            response = resource_tagging.get_resources(
                TagFilters=[
                    {"Key": f"soca:visibility:{_soca_cluster_id}", "Values": ["true"]}
                ],
                ResourceTypeFilters=["eks:cluster"],
            )

            tagged_clusters = [
                arn.split("/")[-1]
                for res in response.get("ResourceTagMappingList", [])
                for arn in [res.get("ResourceARN")]
            ]

            logger.info(f"Found tagged EKS clusters: {tagged_clusters}")

            for _eks_cluster in tagged_clusters:
                logger.info(f"Processing cluster: {_eks_cluster}")

                _soca_eks_client = SocaEKSClient(cluster_name=_eks_cluster)
                if _soca_eks_client.healthcheck() is False:
                    return SocaError.GENERIC_ERROR(
                        helper=f"EKS cluster {_eks_cluster} is unreachable. Check firewall/security group rules."
                    ).as_flask()
                
                _labels = f"soca_JobOwner={_user},soca_ClusterId={_soca_cluster_id}"  # : is not supported by kube

                logger.info(f"Listing job with label selector {_labels}")
                _list_jobs = _soca_eks_client.list_namespaced_job(
                    namespace=_namespace,
                    label_selector=_labels,
                )
                if _list_jobs.get("success") is False:
                    logger.error(
                        f"Unable to list jobs due to {_list_jobs.get('message')} for {_eks_cluster}"
                    )
                    continue
                
                _get_jobs = _list_jobs.get("message")
                logger.info(f"Found EKS Jobs for user {_user}: {_get_jobs}")
                
                for job in _get_jobs.items:
                    job_dict = job.to_dict()
                    job_name = job.metadata.name

                    _get_pods = _soca_eks_client.list_namespaced_pod(
                        namespace=_namespace, label_selector=f"job-name={job_name}"
                    )

                    if _get_pods.get("success") is False:
                        logger.error(
                            f"Unable to list pods due to {_get_pods.get('message')} for {_eks_cluster}"
                        )
                        continue
                    else:
                        pod_list = _get_pods.get("message")

                    pod_ips = [
                        pod.status.pod_ip for pod in pod_list.items if pod.status.pod_ip
                    ]

                    # Get images used
                    images = [c.image for c in job.spec.template.spec.containers]

                    # Add metadata
                    job_dict["pod_ips"] = pod_ips
                    job_dict["images"] = images
                    job_dict["eks_cluster"] = _eks_cluster

                    _jobs[job.metadata.uid] = json.loads(full_serialize(job_dict))

        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Error listing jobs across clusters: {err}"
            ).as_flask()
        return SocaResponse(success=True, message=_jobs).as_flask()
