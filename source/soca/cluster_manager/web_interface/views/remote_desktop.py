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
from decorators import login_required
from models import db, LinuxDCVSessions, AmiList
import pytz
from datetime import datetime, timezone
from utils.aws.ssm_parameter_store import SocaConfig
import remote_desktop_common as utils_remote_desktop_common

remote_desktop = Blueprint("remote_desktop", __name__, template_folder="templates")
logger = logging.getLogger("soca_logger")


def get_ami_info(image=False):
    ami_info = {}
    if image is False:
        for session_info in (
            AmiList.query.filter(AmiList.is_active == True)
            .filter(AmiList.ami_type != "windows")
            .all()
        ):
            ami_info[f"{session_info.ami_label}_{session_info.ami_arch}"] = {
                "ami_label": session_info.ami_label,
                "ami_id": session_info.ami_id,
                "ami_base_os": session_info.ami_type,
                "ami_arch": session_info.ami_arch,
                "ami_root_size": session_info.ami_root_disk_size,
            }
    else:
        check_image = (
            AmiList.query.filter(AmiList.is_active == True, AmiList.ami_id == image)
            .filter(AmiList.ami_type != "windows")
            .first()
        )
        if check_image:
            ami_info[f"{check_image.ami_label}_{check_image.ami_arch}"] = {
                "ami_label": check_image.ami_label,
                "ami_id": check_image.ami_id,
                "ami_base_os": check_image.ami_type,
                "ami_arch": check_image.ami_arch,
                "ami_root_size": check_image.ami_root_disk_size,
            }

    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"linux - get_ami_info(): Returning {ami_info}")
    return ami_info


@remote_desktop.route("/remote_desktop", methods=["GET"])
@login_required
def index():
    get_desktops = get(
        config.Config.FLASK_ENDPOINT + "/api/dcv/desktops",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        params={"user": session["user"], "os": "linux", "is_active": "true"},
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

    logger.info(user_sessions)
    max_number_of_sessions = config.Config.DCV_LINUX_SESSION_COUNT

    all_instances = utils_remote_desktop_common.generate_allowed_instances_list(
        baseos="linux", architecture="x86_64"
    )

    logger.debug(f"Got back all instances: {all_instances}")

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

    _all_amis = get_ami_info()
    _ami_default_linux_x86 = dict(
        (key, value)
        for key, value in _all_amis.items()
        if value["ami_arch"] == "x86_64"
    )
    _ami_default_linux_arm64 = dict(
        (key, value) for key, value in _all_amis.items() if value["ami_arch"] == "arm64"
    )

    return render_template(
        "remote_desktop.html",
        user=session["user"],
        user_sessions=user_sessions,
        hibernate_idle_session=config.Config.DCV_LINUX_HIBERNATE_IDLE_SESSION,
        stop_idle_session=config.Config.DCV_LINUX_STOP_IDLE_SESSION,
        terminate_stopped_session=config.Config.DCV_LINUX_TERMINATE_STOPPED_SESSION,
        terminate_session=config.Config.DCV_LINUX_TERMINATE_STOPPED_SESSION,
        allow_instance_change=config.Config.DCV_LINUX_ALLOW_INSTANCE_CHANGE,
        page="remote_desktop",
        base_os=SocaConfig(key="/configuration/BaseOS").get_value().get("message"),
        all_instances=all_instances,
        max_number_of_sessions=max_number_of_sessions,
        server_time=server_time,
        server_timezone_human=config.Config.TIMEZONE,
        ami_default_linux_x86=_ami_default_linux_x86,
        ami_default_linux_arm64=_ami_default_linux_arm64,
    )


@remote_desktop.route("/remote_desktop/create", methods=["POST"])
@login_required
def create():
    logger.info(f"Received following parameters {request.form} for new DCV Linux")
    create_desktop = post(
        f"{config.Config.FLASK_ENDPOINT}/api/dcv/desktop/{request.form['session_number']}/linux",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        data={
            "instance_type": request.form["instance_type"],
            "disk_size": request.form["disk_size"],
            "session_name": request.form["session_name"],
            "instance_ami": request.form["instance_ami"],
            "subnet_id": request.form["subnet_id"],
            "hibernate": request.form["hibernate"],
            "tenancy": request.form["tenancy"],
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

    return redirect("/remote_desktop")


@remote_desktop.route("/remote_desktop/delete", methods=["GET"])
@login_required
def delete():
    session_number = request.args.get("session", None)
    action = request.args.get("action", None)
    logger.info(f"Received following parameters {request.args} to delete DCV Linux")

    if action == "delete":
        # Delete a desktop
        delete_desktop = delete(
            f"{config.Config.FLASK_ENDPOINT}/api/dcv/desktop/{session_number}/delete",
            headers={
                "X-SOCA-USER": session["user"],
                "X-SOCA-TOKEN": session["api_key"],
            },
            data={"os": "linux", "action": action},
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
            data={"os": "linux", "action": action},
            verify=False,
        )  # nosec

    if delete_desktop.status_code == 200:
        if action == "terminate":
            flash(f"Your desktop is about to be terminated as requested", "success")
        else:
            flash(f"Your desktop is about to be changed to {action} state", "success")
    else:
        flash(f"{delete_desktop.json()['message']} ", "error")

    return redirect("/remote_desktop")


@remote_desktop.route("/remote_desktop/restart", methods=["GET"])
@login_required
def restart_from_hibernate():
    session_number = request.args.get("session", None)
    logger.info(
        f"Received following parameters {request.args} to restart Linux Desktop"
    )
    restart_desktop = put(
        f"{config.Config.FLASK_ENDPOINT}/api/dcv/desktop/{session_number}/restart",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        data={"os": "linux"},
        verify=False,
    )  # nosec
    if restart_desktop.status_code == 200:
        flash(f"Your desktop is about to be restarted", "success")
    else:
        flash(f"{restart_desktop.json()['message']} ", "error")

    return redirect("/remote_desktop")


@remote_desktop.route("/remote_desktop/modify", methods=["POST"])
@login_required
def modify():
    session_number = request.form.get("session_number", None)
    instance_type = request.form.get("instance_type", None)

    logger.info(f"Received following parameters {request.form} to modify DCV Linux")
    modify_desktop = put(
        f"{config.Config.FLASK_ENDPOINT}/api/dcv/desktop/{session_number}/modify",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        data={"os": "linux", "instance_type": instance_type},
        verify=False,
    )  # nosec
    if modify_desktop.status_code == 200:
        flash(f"Your desktop hardware has been updated to {instance_type}", "success")
    else:
        flash(f"{modify_desktop.json()['message']} ", "error")

    return redirect("/remote_desktop")


@remote_desktop.route("/remote_desktop/client", methods=["GET"])
@login_required
def generate_client():
    dcv_session = request.args.get("session", None)
    if dcv_session is None:
        flash("Invalid graphical sessions", "error")
        return redirect("/remote_desktop")

    check_session = LinuxDCVSessions.query.filter_by(
        user=session["user"], session_number=dcv_session, is_active=True
    ).first()
    if check_session:
        session_file = (
            """
[version]
format=1.0

[connect]
host="""
            + SocaConfig(key="/configuration/LoadBalancerDNSName")
            .get_value()
            .get("message")
            + """
port=443
sessionid="""
            + check_session.session_id
            + """
user="""
            + session["user"]
            + """
authToken="""
            + check_session.dcv_authentication_token
            + """
weburlpath=/"""
            + check_session.session_host_private_dns
            + """
"""
        )
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
        return redirect("/remote_desktop")


@remote_desktop.route("/remote_desktop/schedule", methods=["POST"])
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
        f"Received following parameters {request.form} to modify DCV Linux schedule"
    )
    modify_schedule = put(
        f"{config.Config.FLASK_ENDPOINT}/api/dcv/desktop/{session_number}/schedule",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        data={
            "os": "linux",
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
        flash(f"{modify_schedule.json()['message']} ", "error")

    return redirect("/remote_desktop")
