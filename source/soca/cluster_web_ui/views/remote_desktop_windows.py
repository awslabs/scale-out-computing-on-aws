######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

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
from decorators import login_required
import boto3
from models import db, WindowsDCVSessions, AmiList
import random
from datetime import datetime, timezone
import pytz
import read_secretmanager
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet

remote_desktop_windows = Blueprint(
    "remote_desktop_windows", __name__, template_folder="templates"
)
client_ec2 = boto3.client("ec2", config=config.boto_extra_config())
client_lambda = boto3.client("lambda", config=config.boto_extra_config())
client_cfn = boto3.client("cloudformation", config=config.boto_extra_config())
logger = logging.getLogger("application")


def get_ami_info():
    ami_info = {}
    for session_info in AmiList.query.filter_by(
        is_active=True, ami_type="windows"
    ).all():
        ami_info[session_info.ami_label] = session_info.ami_id
    return ami_info


def encrypt(message):
    key = config.Config.DCV_TOKEN_SYMMETRIC_KEY
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(message.encode("utf-8"))


def can_launch_instance(launch_parameters):
    try:
        client_ec2.run_instances(
            BlockDeviceMappings=[
                {
                    "DeviceName": "/dev/sda1",
                    "Ebs": {
                        "DeleteOnTermination": True,
                        "VolumeSize": 40
                        if launch_parameters["disk_size"] is False
                        else int(launch_parameters["disk_size"]),
                        "VolumeType": "gp3",
                        "Encrypted": True,
                    },
                },
            ],
            MaxCount=1,
            MinCount=1,
            SecurityGroupIds=[launch_parameters["security_group_id"]],
            InstanceType=launch_parameters["instance_type"],
            IamInstanceProfile={"Arn": launch_parameters["instance_profile"]},
            SubnetId=random.choice(launch_parameters["soca_private_subnets"]),
            UserData=launch_parameters["user_data"],
            ImageId=launch_parameters["image_id"],
            DryRun=True,
            HibernationOptions={"Configured": launch_parameters["hibernate"]},
        )

    except ClientError as err:
        if err.response["Error"].get("Code") == "DryRunOperation":
            return True
        else:
            return f"Dry run failed. Unable to launch capacity due to: {err}"


def get_host_info(tag_uuid, cluster_id):
    host_info = {}

    ec2_paginator = client_ec2.get_paginator("describe_instances")
    ec2_iterator = ec2_paginator.paginate(
        Filters=[
            {"Name": "tag:soca:DCVSessionUUID", "Values": [tag_uuid]},
            {"Name": "tag:soca:ClusterId", "Values": [cluster_id]},
            {"Name": "tag:soca:DCVSystem", "Values": ["windows"]},
        ],
    )

    for page in ec2_iterator:
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                if instance["PrivateDnsName"].split(".")[0]:
                    host_info["private_dns"] = instance["PrivateDnsName"].split(".")[0]
                    host_info["private_ip"] = instance["PrivateIpAddress"]
                    host_info["instance_id"] = instance["InstanceId"]
                    host_info["status"] = instance["State"]["Name"]

    return host_info


@remote_desktop_windows.route("/remote_desktop_windows", methods=["GET"])
@login_required
def index():
    get_desktops = get(
        config.Config.FLASK_ENDPOINT + "/api/dcv/desktops",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        params={"user": session["user"], "os": "windows", "is_active": "true"},
        verify=False,
    )  # nosec
    if get_desktops.status_code == 200:
        user_sessions = get_desktops.json()["message"]
        user_sessions = {
            int(k): v for k, v in user_sessions.items()
        }  # convert all keys (session number) back to integer
    else:
        flash(f"{get_desktops.json()}", "error")
        user_sessions = {}

    max_number_of_sessions = config.Config.DCV_WINDOWS_SESSION_COUNT
    # List of instances not available for DCV. Adjust as needed
    blocked_instances = config.Config.DCV_RESTRICTED_INSTANCE_TYPE
    all_instances_available = client_ec2._service_model.shape_for("InstanceType").enum
    all_instances = [
        p
        for p in all_instances_available
        if not any(substr in p for substr in blocked_instances)
    ]
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

    return render_template(
        "remote_desktop_windows.html",
        user=session["user"],
        user_sessions=user_sessions,
        hibernate_idle_session=config.Config.DCV_WINDOWS_HIBERNATE_IDLE_SESSION,
        stop_idle_session=config.Config.DCV_WINDOWS_STOP_IDLE_SESSION,
        terminate_stopped_session=config.Config.DCV_WINDOWS_TERMINATE_STOPPED_SESSION,
        terminate_session=config.Config.DCV_WINDOWS_TERMINATE_STOPPED_SESSION,
        allow_instance_change=config.Config.DCV_WINDOWS_ALLOW_INSTANCE_CHANGE,
        page="remote_desktop",
        server_time=server_time,
        server_timezone_human=config.Config.TIMEZONE,
        all_instances=all_instances,
        max_number_of_sessions=max_number_of_sessions,
        auth_provider=config.Config.SOCA_AUTH_PROVIDER,
        netbios="false"
        if config.Config.SOCA_AUTH_PROVIDER == "openldap"
        else config.Config.NETBIOS,
        ami_list=get_ami_info(),
    )


@remote_desktop_windows.route("/remote_desktop_windows/create", methods=["POST"])
@login_required
def create():
    logger.info(f"Received following parameters {request.form} for new Windows Windows")
    create_desktop = post(
        f"{config.Config.FLASK_ENDPOINT}/api/dcv/desktop/{request.form['session_number']}/windows",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        data={
            "instance_type": request.form["instance_type"],
            "disk_size": request.form["disk_size"],
            "session_name": request.form["session_name"],
            "instance_ami": request.form["instance_ami"],
            "subnet_id": request.form["subnet_id"],
            "hibernate": request.form["hibernate"],
            "tenancy": request.form["tenancy"]
        },
        verify=False,
    )  # nosec
    if create_desktop.status_code == 200:
        flash(
            "Your session has been initiated. It will be ready within 20 minutes.",
            "success",
        )
    else:
        flash(f"{create_desktop.json()['message']} ", "error")

    return redirect("/remote_desktop_windows")


@remote_desktop_windows.route("/remote_desktop_windows/delete", methods=["GET"])
@login_required
def delete():
    session_number = request.args.get("session", None)
    action = request.args.get("action", None)
    logger.info(f"Received following parameters {request.args} to delete DCV Windows")
    if action == "delete":
        # Terminate a desktop
        delete_desktop = delete(
            f"{config.Config.FLASK_ENDPOINT}/api/dcv/desktop/{session_number}/delete",
            headers={
                "X-SOCA-USER": session["user"],
                "X-SOCA-TOKEN": session["api_key"],
            },
            data={"os": "windows"},
            verify=False,
        )  # nosec

    else:
        # Stop/Hibernate
        delete_desktop = put(
            f"{config.Config.FLASK_ENDPOINT}/api/dcv/desktop/{session_number}/{action}",
            headers={
                "X-SOCA-USER": session["user"],
                "X-SOCA-TOKEN": session["api_key"],
            },
            data={"os": "windows", "action": action},
            verify=False,
        )  # nosec
    if delete_desktop.status_code == 200:
        if action == "terminate":
            flash(f"Your desktop is about to be terminated", "success")
        else:
            flash(f"Your desktop is about to be changed to {action} state", "success")
    else:
        flash(f"{delete_desktop.json()['message']} ", "error")

    return redirect("/remote_desktop_windows")


@remote_desktop_windows.route("/remote_desktop_windows/restart", methods=["GET"])
@login_required
def restart_from_hibernate():
    session_number = request.args.get("session", None)
    logger.info(f"Received following parameters {request.args} to restart DCV Windows")
    restart_desktop = put(
        f"{config.Config.FLASK_ENDPOINT}/api/dcv/desktop/{session_number}/restart",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        data={"os": "windows"},
        verify=False,
    )  # nosec
    if restart_desktop.status_code == 200:
        flash(f"Your desktop is about to be restarted", "success")
    else:
        flash(f"{restart_desktop.json()['message']} ", "error")

    return redirect("/remote_desktop_windows")


@remote_desktop_windows.route("/remote_desktop_windows/modify", methods=["POST"])
@login_required
def modify():
    session_number = request.form.get("session_number", None)
    instance_type = request.form.get("instance_type", None)

    logger.info(f"Received following parameters {request.args} to modify DCV Windows")
    modify_desktop = put(
        f"{config.Config.FLASK_ENDPOINT}/api/dcv/desktop/{session_number}/modify",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        data={"os": "windows", "instance_type": instance_type},
        verify=False,
    )  # nosec
    if modify_desktop.status_code == 200:
        flash(f"Your desktop hardware has been updated to {instance_type}", "success")
    else:
        flash(f"{modify_desktop.json()['message']} ", "error")

    return redirect("/remote_desktop_windows")


@remote_desktop_windows.route("/remote_desktop_windows/schedule", methods=["POST"])
@login_required
def schedule():
    session_number = request.form.get("session_number", None)
    monday = request.form.get("monday", None)
    tuesday = request.form.get("tuesday", None)
    wednesday = request.form.get("wednesday", None)
    thursday = request.form.get("thursday", None)
    friday = request.form.get("friday", None)
    saturday = request.form.get("saturday", None)
    sunday = request.form.get("sunday", None)

    logger.info(
        f"Received following parameters {request.args} to modify DCV Windows schedule"
    )
    modify_schedule = put(
        f"{config.Config.FLASK_ENDPOINT}/api/dcv/desktop/{session_number}/schedule",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        data={
            "os": "windows",
            "monday": monday,
            "tuesday": tuesday,
            "wednesday": wednesday,
            "thursday": thursday,
            "friday": friday,
            "saturday": saturday,
            "sunday": sunday,
        },
        verify=False,
    )  # nosec
    if modify_schedule.status_code == 200:
        flash(f"Your schedule has been updated successfully", "success")
    else:
        flash(
            f"Unable to modify your schedule because of {modify_schedule.json()['message']} ",
            "error",
        )

    return redirect("/remote_desktop_windows")


@remote_desktop_windows.route("/remote_desktop_windows/client", methods=["GET"])
@login_required
def generate_client():
    dcv_session = request.args.get("session", None)
    if dcv_session is None:
        flash("Invalid graphical sessions", "error")
        return redirect("/remote_desktop_windows")

    check_session = WindowsDCVSessions.query.filter_by(
        user=session["user"], session_number=dcv_session, is_active=True
    ).first()
    if check_session:
        if config.Config.SOCA_AUTH_PROVIDER == "activedirectory":
            user = f"{config.Config.NETBIOS}\{session['user']}"
            session_file = f"""
[version]
format=1.0

[connect]
host={read_secretmanager.get_soca_configuration()['LoadBalancerDNSName']}
port=443
sessionid=console
user={user}
weburlpath=/{check_session.session_host_private_dns}"""
        else:
            user = session["user"]
            session_file = f"""
[version]
format=1.0
    
[connect]
host={read_secretmanager.get_soca_configuration()['LoadBalancerDNSName']}
port=443
sessionid=console
username={user}
authToken={check_session.dcv_authentication_token}
weburlpath=/{check_session.session_host_private_dns}"""
        return Response(
            session_file,
            mimetype="text/txt",
            headers={
                "Content-disposition": "attachment; filename="
                + session["user"]
                + "_soca_"
                + str(dcv_session)
                + ".dcv"
            },
        )

    else:
        flash(
            "Unable to retrieve this session. This session may have been terminated.",
            "error",
        )
        return redirect("/remote_desktop_windows")
