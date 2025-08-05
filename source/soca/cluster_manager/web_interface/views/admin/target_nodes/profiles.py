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
from flask import render_template, Blueprint, request, redirect, session, flash
from decorators import login_required, admin_only
from utils.aws.ssm_parameter_store import SocaConfig
from utils.error import SocaError
from utils.response import SocaResponse
from utils.http_client import SocaHttpClient

logger = logging.getLogger("soca_logger")
admin_target_nodes_profiles = Blueprint(
    "admin_target_nodes_profiles", __name__, template_folder="templates"
)


@admin_target_nodes_profiles.route("/admin/target_nodes/profiles", methods=["GET"])
@login_required
@admin_only
def index():
    logger.info(f"Get all target nodes profiles")
    _all_profiles = SocaHttpClient(
        endpoint="/api/target_nodes/profiles",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get()

    if _all_profiles.get("success") is False:
        flash(
            f"Unable to list Target Node profiles because of {_all_profiles.get('message')}",
            "error",
        )
        _profiles = {}
    else:
        _profiles = _all_profiles.get("message")

    _soca_private_subnets = (
        SocaConfig(key="/configuration/PrivateSubnets")
        .get_value(return_as=list)
        .get("message")
    )

    _default_instance_type_pattern = ", ".join(
        config.Config.DCV_DEFAULT_AMI_INSTANCE_TYPES
    )

    return render_template(
        "admin/target_nodes/profiles.html",
        allowed_subnets=", ".join(_soca_private_subnets),
        default_instance_type_pattern=_default_instance_type_pattern,
        profiles=_profiles,
        page="admin_target_node_profiles",
    )


@admin_target_nodes_profiles.route(
    "/admin/target_nodes/profiles/create", methods=["POST"]
)
@login_required
@admin_only
def create_new_profile():
    logger.info(f"Creating new Target Node profile")
    _create_new_profile = SocaHttpClient(
        endpoint="/api/target_nodes/profiles",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).post(request.form.to_dict())

    if _create_new_profile.get("success") is False:
        flash(
            f"{_create_new_profile.get('message')}",
            "error",
        )
    else:
        flash(f"Your profile has been created successfully", "success")

    return redirect("/admin/target_nodes/profiles")


@admin_target_nodes_profiles.route(
    "/admin/target_nodes/profiles/delete", methods=["POST"]
)
@login_required
@admin_only
def delete_profile():
    logger.info(f"Deleting target node profile")
    _delete_new_profile = SocaHttpClient(
        endpoint="/api/target_nodes/profiles",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).delete(request.form.to_dict())

    if _delete_new_profile.get("success") is False:
        flash(
            f"{_delete_new_profile.get('message')}",
            "error",
        )
    else:
        flash(f"Your profile has been deleted successfully", "success")

    return redirect("/admin/target_nodes/profiles")


@admin_target_nodes_profiles.route(
    "/admin/target_nodes/profiles/edit", methods=["POST", "GET"]
)
@login_required
@admin_only
def profile_edit():
    if request.method == "GET":
        return redirect("/admin/target_nodes/profiles")

    logger.info(
        f"Received following parameters {request.form} to edit target node profile"
    )
    _profile_to_modify = request.form.get("profile_id", None)
    if _profile_to_modify is None:
        flash("Missing profile_id", "error")
        return redirect("/admin/target_nodes/profiles")

    _get_profile_info = SocaHttpClient(
        endpoint="/api/target_nodes/profiles",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get(params={"profile_id": request.form.get("profile_id")})

    _list_profiles = SocaHttpClient(
        endpoint="/api/target_nodes/profiles",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get()

    if _get_profile_info.get("success") is True:
        _profile_info = _get_profile_info.get("message").get(_profile_to_modify)
        return render_template(
            "admin/target_nodes/profiles_edit.html",
            user=session["user"],
            profiles=_list_profiles.get("message"),
            profile_info=_get_profile_info.get("message").get(_profile_to_modify),
            page="admin_profiles",
        )
    else:
        flash(
            f"Unable to list Target Node Profiles because of {_get_profile_info.get('message')}",
            "error",
        )
        return redirect("/admin/target_nodes/profiles")


@admin_target_nodes_profiles.route(
    "/admin/target_nodes/profiles/edit/update", methods=["POST"]
)
@login_required
@admin_only
def profile_update():
    logger.info(f"Received following parameters {request.form} to edit profile ")

    _profile_to_modify = request.form.get("profile_id", None)
    if _profile_to_modify is None:
        flash("Missing profile_id", "error")
        return redirect("/admin/target_nodes/profiles")

    _modify_profile = SocaHttpClient(
        endpoint="/api/target_nodes/profiles",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).put(data=request.form.to_dict())

    if _modify_profile.get("success") is True:
        flash(
            f"Your Target Node Profile has been updated successfully",
            "success",
        )
    else:
        flash(
            f"{_modify_profile.get('message')}",
            "error",
        )
    return redirect("/admin/target_nodes/profiles")
