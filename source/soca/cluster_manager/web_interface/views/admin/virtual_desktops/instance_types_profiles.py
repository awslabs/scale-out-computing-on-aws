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

logger = logging.getLogger("soca_logger")
admin_virtual_desktops_instance_types_profiles = Blueprint(
    "virtual_desktops_instance_type_profiles", __name__, template_folder="templates"
)


def get_region():
    session = boto3.session.Session()
    aws_region = session.region_name
    return aws_region


@admin_virtual_desktops_instance_types_profiles.route("/admin/virtual_desktops/instance_types_profiles", methods=["GET"])
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
        "admin/virtual_desktops/instance_types_profiles.html",
        user=session["user"],
        ami_infos=ami_infos,
        region_name=get_region(),
    )



