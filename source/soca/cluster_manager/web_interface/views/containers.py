# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from decorators import login_required, feature_flag
from flask import Blueprint, render_template, session, redirect
from utils.aws.ssm_parameter_store import SocaConfig
from utils.http_client import SocaHttpClient
from utils.aws.boto3_wrapper import get_boto
from flask import request, flash, redirect

logger = logging.getLogger("soca_logger")
containers = Blueprint("containers", __name__, template_folder="templates")


@containers.route("/containers", methods=["GET"])
@login_required
@feature_flag(flag_name="CONTAINERS_MANAGEMENT", mode="view")
def index():
    logger.info("Listing all Container images available")
    _user = session.get("user")

    _soca_cluster_id = (
        SocaConfig(key="/configuration/ClusterId").get_value().get("message")
    )

    _get_ecr_repo_info = SocaHttpClient(
        endpoint=f"/api/containers/ecr/repository",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get()

    logger.debug(f"Get ECR Repo Info {_get_ecr_repo_info}")
    if _get_ecr_repo_info.get("success") is True:
        _container_images = _get_ecr_repo_info.get("message")
    else:
        logger.error(f"Unable to list container image because of {_get_ecr_repo_info}")
        flash("Unable to list your container images", "error")
        _container_images = {}

    _get_eks_cluster = SocaHttpClient(
        endpoint=f"/api/containers/eks/list_clusters",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get()

    logger.debug(f"Get EKS cluster Info {_get_eks_cluster}")
    if _get_eks_cluster.get("success") is True:
        _eks_clusters = _get_eks_cluster.get("message")
    else:
        logger.error(
            f"Unable to list EKS clusters image because of {_get_ecr_repo_info}"
        )
        flash("Unable to list your clusters images", "error")
        _eks_clusters = []

    logger.debug(f"All ECR Repo and Images {_container_images}")
    logger.debug(f"All EKS Clusters {_eks_clusters}")

    return render_template(
        "containers/images.html",
        container_images=_container_images,
        eks_clusters=_eks_clusters,
        cluster_id=_soca_cluster_id,
        page="containers_list_images",
    )


@containers.route("/containers/submit_job", methods=["POST"])
@login_required
@feature_flag(flag_name="CONTAINERS_MANAGEMENT", mode="view")
def submit_job():
    _submit_job = SocaHttpClient(
        endpoint="/api/containers/eks/job",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).post(request.form.to_dict())
    if _submit_job.get("success") is True:
        flash(f"Your job was submitted successfully", "success")
        return redirect("/containers/my_containers")
    else:
        flash(
            _submit_job.get("message"),
            "error",
        )
        return redirect("/containers")


@containers.route("/containers/my_containers", methods=["GET"])
@login_required
@feature_flag(flag_name="CONTAINERS_MANAGEMENT", mode="view")
def list_jobs():
    _soca_cluster_id = (
        SocaConfig(key="/configuration/ClusterId").get_value().get("message")
    )
    _namespace = request.args.get("namespace", "default")
    _cluster = request.args.get("cluster", "")
    _containers = {}

    try:

        if not _cluster:
            _resource_tagging = get_boto(
                service_name="resourcegroupstaggingapi"
            ).message
            response = _resource_tagging.get_resources(
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
        else:
            tagged_clusters = [_cluster]

        for cluster in tagged_clusters:
            logger.info(f"Checking for job {cluster} and namespace {_namespace}")
            _get_job_for_cluster = SocaHttpClient(
                endpoint="/api/containers/eks/jobs",
                headers={
                    "X-SOCA-USER": session["user"],
                    "X-SOCA-TOKEN": session["api_key"],
                },
            ).get(params={"cluster": cluster, "namespace": _namespace})
            if _get_job_for_cluster.get("success") is True:
                _containers[cluster] = _get_job_for_cluster.get("message")
            else:
                logger.error(
                    f"Unable to list job for cluster {cluster} because of {_get_job_for_cluster}"
                )
                flash(
                    f"{_get_job_for_cluster.get('message')}",
                    "error",
                )

    except Exception as err:
        logger.error(f"Error listing containers: {err}")
        flash(f"Failed to list containers: {err}", "error")

    logger.debug(f"Detected jobs {_containers}")
    return render_template(
        "containers/my_containers.html",
        containers=_containers,
        page="containers",
    )


@containers.route("/containers/delete_job", methods=["GET"])
@login_required
@feature_flag(flag_name="CONTAINERS_MANAGEMENT", mode="view")
def delete_job():
    _user = session.get("user")
    _delete_job = SocaHttpClient(
        endpoint=f"/api/containers/eks/job",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).delete(data=request.args.to_dict())
    if _delete_job.get("success") is True:
        flash(f"Your job was deleted successfully", "success")
    else:
        flash(
            _delete_job.get("message"),
            "error",
        )
    return redirect("/containers/my_containers")
