# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import time
import logging
import config
from flask import (
    render_template,
    Blueprint,
    request,
    redirect,
    session,
    flash,
    Response,
)
from requests import get, post, put, delete
from decorators import login_required, feature_flag
from models import db, TargetNodeSessions, TargetNodeSoftwareStacks, TargetNodeProfiles
from datetime import datetime, timezone
from utils.aws.ssm_parameter_store import SocaConfig
from utils.http_client import SocaHttpClient
from utils.error import SocaError
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.aws.boto3_wrapper import get_boto
import boto3
import botocore
import fnmatch
import pytz
import json

target_nodes = Blueprint("target_nodes", __name__, template_folder="templates")
logger = logging.getLogger("soca_logger")

@target_nodes.route("/target_nodes", methods=["GET"])
@login_required
@feature_flag(flag_name="TARGET_NODES", mode="view")
def index():
    _get_all_sessions = SocaHttpClient(
        endpoint=f"/api/target_nodes/list",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get(params={"user": session["user"], "is_active": "true"})

    logger.debug(f"get all target_nodes {_get_all_sessions}")
    if _get_all_sessions.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to list target nodes because of {_get_all_sessions.get('message')}"
        ).as_flask()

    try:
        tz = pytz.timezone(config.Config.TIMEZONE)
    except pytz.exceptions.UnknownTimeZoneError:
        flash(
            f"Timezone {config.Config.TIMEZONE} configured by the admin does not exist. Defaulting to UTC. Refer to https://en.wikipedia.org/wiki/List_of_tz_database_time_zones for a full list of supported timezones"
        )
        tz = pytz.timezone("UTC")

    server_time = (
        (datetime.now(timezone.utc)).astimezone(tz).strftime("%Y-%m-%d (%A) %H:%M")
    )

    # List all target nodes stack this user is authorized to launch
    _get_tn_software_stacks_for_user = SocaHttpClient(
        endpoint=f"/api/user/resources_permissions",
        headers={
            "X-SOCA-USER": session["user"],
            "X-SOCA-TOKEN": session["api_key"],
        },
    ).get(params={"target_nodes": "all"})

    if _get_tn_software_stacks_for_user.get("success") is False:
        flash(
            f"Unable to list software stack for this user because of {_get_tn_software_stacks_for_user.get('message')}",
            "error",
        )
        _software_stacks = {}
    else:
        _software_stacks = _get_tn_software_stacks_for_user.get("message").get(
            "target_node_software_stacks"
        )

    return render_template(
        "target_nodes.html",
        allowed_dcv_session_types=config.Config.DCV_ALLOWED_SESSION_TYPES,
        software_stacks=_software_stacks,
        base_os_labels=config.Config.DCV_BASE_OS,
        user_sessions=_get_all_sessions.get("message"),
        allow_instance_change=config.Config.TARGET_NODE_ALLOW_INSTANCE_CHANGE,
        page="target_nodes",
        server_time=server_time,
        server_timezone_human=config.Config.TIMEZONE,
    )


@target_nodes.route("/target_nodes/get_session_state", methods=["GET"])
@login_required
@feature_flag(flag_name="TARGET_NODES", mode="view")
def get_session_state():
    logger.info(
        f"Received following parameters {request.args} for target node session state"
    )
    _get_all_state = SocaHttpClient(
        endpoint=f"/api/target_nodes/session_state",
    ).get(params={"session_uuid": request.args.get("session_uuid")})

    return _get_all_state.get("message"), 200


@target_nodes.route("/target_nodes/create", methods=["POST"])
@login_required
@feature_flag(flag_name="TARGET_NODES", mode="view")
def create():
    logger.info(f"Received following parameters {request.form} for new target node")

    _create_target_node = SocaHttpClient(
        endpoint="/api/target_nodes/create",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).post(data=request.form.to_dict())

    if _create_target_node.get("success") is True:
        flash(
            "Your Target Node session has been initiated. It will be ready shortly",
            "success",
        )
    else:
        flash(
            f"{_create_target_node.get('message')} ",
            "error",
        )

    return redirect("/target_nodes")


@target_nodes.route("/target_nodes/delete", methods=["POST"])
@login_required
@feature_flag(flag_name="TARGET_NODES", mode="view")
def delete():
    _session_uuid = request.form.get("session_uuid", None)
    logger.info(
        f"Received following parameters {request.form} to delete Target Node Session"
    )

    _delete_target_node = SocaHttpClient(
        endpoint="/api/target_nodes/delete",
        headers={
            "X-SOCA-USER": session["user"],
            "X-SOCA-TOKEN": session["api_key"],
        },
    ).delete(data={"session_uuid": _session_uuid})

    if _delete_target_node.get("success") is True:
        flash(f"Your target note is about to be terminated as requested", "success")
    else:
        flash(
            f"Unable to delete target node: {_delete_target_node.get('message')} ",
            "error",
        )

    return redirect("/target_nodes")


@target_nodes.route("/target_nodes/stop", methods=["POST"])
@login_required
@feature_flag(flag_name="TARGET_NODES", mode="view")
def stop():
    _session_uuid = request.form.get("session_uuid", None)
    logger.info(f"Received following parameters {request.form} to stop target nodes")

    _stop_target_node_request = SocaHttpClient(
        endpoint="/api/target_nodes/stop",
        headers={
            "X-SOCA-USER": session["user"],
            "X-SOCA-TOKEN": session["api_key"],
        },
    ).put(data={"session_uuid": _session_uuid})

    if _stop_target_node_request.get("success") is True:
        flash(f"Your target node is about to be stopped as requested", "success")
    else:
        flash(
            f"Unable to stop target nodes: {_stop_target_node_request.get('message')} ",
            "error",
        )

    return redirect("/target_nodes")


@target_nodes.route("/target_nodes/start", methods=["GET"])
@login_required
@feature_flag(flag_name="TARGET_NODES", mode="view")
def start():
    _session_uuid = request.args.get("session_uuid", None)
    logger.info(
        f"Received following parameters {request.args} to start target nodes Session"
    )

    # Delete a desktop
    _start_desktop_request = SocaHttpClient(
        endpoint="/api/target_nodes/start",
        headers={
            "X-SOCA-USER": session["user"],
            "X-SOCA-TOKEN": session["api_key"],
        },
    ).put(data={"session_uuid": _session_uuid})

    if _start_desktop_request.get("success") is True:
        flash(f"Your target node is starting", "success")
    else:
        flash(
            f"Unable to start target node: {_start_desktop_request.get('message')} ",
            "error",
        )

    return redirect("/target_nodes")


@target_nodes.route("/target_nodes/schedule", methods=["POST"])
@login_required
@feature_flag(flag_name="TARGET_NODES", mode="view")
def schedule():
    _session_uuid = request.form.get("session_uuid", None)
    _schedule = request.form.get("schedule", None)
    logger.info(
        f"Received following parameters {request.form} to update for target node"
    )

    # Update Schedule
    _update_schedule_request = SocaHttpClient(
        endpoint="/api/target_nodes/schedule",
        headers={
            "X-SOCA-USER": session["user"],
            "X-SOCA-TOKEN": session["api_key"],
        },
    ).put(data={"session_uuid": _session_uuid, "schedule": _schedule})

    if _update_schedule_request.get("success") is True:
        flash(f"Your schedule has been updated successfully", "success")
    else:
        flash(
            f"{_update_schedule_request.get('message')} ",
            "error",
        )

    return redirect("/target_nodes")


@target_nodes.route("/target_nodes/resize", methods=["POST"])
@login_required
@feature_flag(flag_name="TARGET_NODES", mode="view")
def resize():
    _session_uuid = request.form.get("session_uuid", None)
    _instance_type = request.form.get("instance_type", None)

    logger.info(
        f"Received following parameters {request.form} to modify target node instance"
    )

    _resize_request = SocaHttpClient(
        endpoint="/api/target_nodes/resize",
        headers={
            "X-SOCA-USER": session["user"],
            "X-SOCA-TOKEN": session["api_key"],
        },
    ).put(data={"session_uuid": _session_uuid, "instance_type": _instance_type})

    if _resize_request.get("success") is True:
        flash(f"Your target node is now using {_instance_type}", "success")
    else:
        flash(
            f"Unable to update hardware size: {_resize_request.get('message')} ",
            "error",
        )

    return redirect("/target_nodes")
