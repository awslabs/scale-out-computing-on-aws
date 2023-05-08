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
import boto3
import config
from flask import render_template, Blueprint, request, redirect, session, flash
from decorators import login_required, admin_only
from requests import delete, post, get

logger = logging.getLogger("application")
admin_ami_management = Blueprint(
    "ami_management", __name__, template_folder="templates"
)


def get_region():
    session = boto3.session.Session()
    aws_region = session.region_name
    return aws_region


@admin_ami_management.route("/admin/ami_management/", methods=["GET"])
@login_required
@admin_only
def index():
    logger.info(f"List all DCV images registered to SOCA")
    list_images = get(
        f"{config.Config.FLASK_ENDPOINT}/api/dcv/images",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        verify=False,
    )  # nosec
    if list_images.status_code == 200:
        ami_infos = list_images.json()["message"]
    else:
        flash(f"{list_images.json()['message']} ", "error")
        ami_infos = {}

    return render_template(
        "admin/ami_management.html",
        user=session["user"],
        ami_infos=ami_infos,
        region_name=get_region(),
    )


@admin_ami_management.route("/admin/ami_management/create", methods=["POST"])
@login_required
@admin_only
def ami_create():
    ami_id = str(request.form.get("ami_id"))
    choose_os = request.form.get("os")
    ami_label = str(request.form.get("ami_label"))
    root_size = request.form.get("root_size")
    logger.info(f"Received following parameters {request.form} to create DCV image")
    list_images = post(
        f"{config.Config.FLASK_ENDPOINT}/api/dcv/image",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        data={
            "os": choose_os,
            "ami_label": ami_label,
            "root_size": root_size,
            "ami_id": ami_id,
        },
        verify=False,
    )  # nosec
    if list_images.status_code == 200:
        flash(
            f"Your image {ami_label} has been registered successfully with EC2 ID: {ami_id}",
            "success",
        )
    else:
        flash(f"{list_images.json()['message']} ", "error")
    return redirect("/admin/ami_management")


@admin_ami_management.route("/admin/ami_management/delete", methods=["POST"])
@login_required
@admin_only
def ami_delete():
    ami_label = request.form.get("ami_label")
    logger.info(f"Received following parameters {request.form} to delete DCV image")
    delete_image = delete(
        f"{config.Config.FLASK_ENDPOINT}/api/dcv/image",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        data={"ami_label": ami_label},
        verify=False,
    )  # nosec
    if delete_image.status_code == 200:
        flash(f"Your image {ami_label} has been deleted successfully", "success")
    else:
        flash(f"{delete_image.json()['message']} ", "error")

    return redirect("/admin/ami_management")
