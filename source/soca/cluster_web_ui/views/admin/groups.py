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
from requests import get, post, delete, put
from models import ApiKeys
from decorators import login_required, admin_only

logger = logging.getLogger("application")
admin_groups = Blueprint("admin_groups", __name__, template_folder="templates")


@admin_groups.route("/admin/groups", methods=["GET"])
@login_required
@admin_only
def index():
    get_all_groups = get(
        config.Config.FLASK_ENDPOINT + "/api/ldap/groups",
        headers={"X-SOCA-TOKEN": session["api_key"], "X-SOCA-USER": session["user"]},
        verify=False,
    )  # nosec

    if get_all_groups.status_code == 200:
        all_groups = get_all_groups.json()["message"].keys()
    else:
        flash("Unable to list groups: " + str(get_all_groups._content), "error")
        all_groups = {}

    get_all_users = get(
        config.Config.FLASK_ENDPOINT + "/api/ldap/users",
        headers={"X-SOCA-TOKEN": session["api_key"], "X-SOCA-USER": session["user"]},
        verify=False,
    )  # nosec

    if get_all_users.status_code == 200:
        all_users = get_all_users.json()["message"].keys()
    else:
        flash("Unable to list all_users: " + str(get_all_users._content), "error")
        all_users = {}

    return render_template(
        "admin/groups.html",
        user=session["user"],
        sudoers=session["sudoers"],
        all_groups=sorted(all_groups),
        all_users=sorted(all_users),
    )


@admin_groups.route("/admin/create_group", methods=["POST"])
@login_required
@admin_only
def create_group():
    group_name = request.form.get("group_name")
    members = request.form.getlist("members")
    create_group = post(
        config.Config.FLASK_ENDPOINT + "/api/ldap/group",
        headers={"X-SOCA-TOKEN": session["api_key"], "X-SOCA-USER": session["user"]},
        data={"group": group_name, "members": ",".join(members)},
        verify=False,
    )  # nosec

    if create_group.status_code == 200:
        flash("Group " + group_name + " created successfully", "success")
    else:
        flash(
            "Error while creating "
            + group_name
            + " because of "
            + create_group.json()["message"],
            "error",
        )

    return redirect("/admin/groups")


@admin_groups.route("/admin/delete_group", methods=["POST"])
@login_required
@admin_only
def delete_group():
    group = str(request.form.get("group_to_delete"))
    if session["user"] == group:  # user group name is <username>group
        flash("You cannot delete your own group.", "error")
        return redirect("/admin/groups")

    group_to_delete = delete(
        config.Config.FLASK_ENDPOINT + "/api/ldap/group",
        headers={"X-SOCA-TOKEN": session["api_key"], "X-SOCA-USER": session["user"]},
        data={"group": group},
        verify=False,
    )  # nosec

    if group_to_delete.status_code == 200:
        flash("Group: " + group + " has been deleted correctly", "success")
    else:
        flash(
            "Could not delete group: "
            + group
            + ". Check trace: "
            + str(group_to_delete.text),
            "error",
        )

    return redirect("/admin/groups")


@admin_groups.route("/admin/check_group", methods=["POST"])
@login_required
@admin_only
def check_group():
    group = str(request.form.get("group"))
    check_group = get(
        config.Config.FLASK_ENDPOINT + "/api/ldap/group",
        headers={"X-SOCA-TOKEN": session["api_key"], "X-SOCA-USER": session["user"]},
        params={"group": group},
        verify=False,
    )  # nosec

    if check_group.status_code == 200:
        members = check_group.json()["message"]["members"]
        if members.__len__() == 0:
            members = ["No member found."]
        flash("List of users of " + group + ": <hr> " + " ".join(members), "success")
    else:
        flash(
            "Could not check group membership: "
            + group
            + ". Check trace: "
            + check_group.json()["message"],
            "error",
        )

    return redirect("/admin/groups")


@admin_groups.route("/admin/manage_group", methods=["POST"])
@login_required
@admin_only
def manage_group():
    group = request.form.get("group")
    user = request.form.get("user")
    action = request.form.get("action")
    update_group = put(
        config.Config.FLASK_ENDPOINT + "/api/ldap/group",
        headers={"X-SOCA-TOKEN": session["api_key"], "X-SOCA-USER": session["user"]},
        data={"group": group, "user": user, "action": action},
        verify=False,
    )  # nosec

    if update_group.status_code == 200:
        flash("Group update successfully", "success")
    else:
        flash("Unable to update group: " + update_group.json()["message"], "error")

    return redirect("/admin/groups")
