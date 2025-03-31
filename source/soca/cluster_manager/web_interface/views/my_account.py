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
from requests import get, post, put
from decorators import login_required
import string
import random
from utils.error import SocaError
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.response import SocaResponse
from utils.aws.ssm_parameter_store import SocaConfig
from utils.http_client import SocaHttpClient
logger = logging.getLogger("soca_logger")
my_account = Blueprint("my_account", __name__, template_folder="templates")


@my_account.route("/my_account", methods=["GET"])
@login_required
def index():
    group_name = f"{session['user']}{config.Config.DIRECTORY_GROUP_NAME_SUFFIX}"
    _get_user_ldap_group = SocaHttpClient(endpoint="/api/ldap/group",  headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY}).get(params={"group": group_name})
    _get_user_ldap_users = SocaHttpClient(endpoint="/api/ldap/users",  headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY}).get()
    all_users = []
    group_members = []

    if _get_user_ldap_group.success:
        for _member in _get_user_ldap_group.message.get("members"):
            if f"{'uid=' if config.Config.DIRECTORY_AUTH_PROVIDER in ['openldap', 'existing_openldap'] else 'cn='}{session['user']}," not in _member.lower():
                group_members.append(_member)

    if _get_user_ldap_users.success:
        for _user in _get_user_ldap_users.message.keys():
            # do not show current user, cannot being added/removed to its own group
            if _user !=  session["user"]:
                all_users.append(_user)

    return render_template(
        "my_account.html",
        user=session["user"],
        group_members=group_members,
        all_users=all_users,
    )


@my_account.route("/manage_group", methods=["POST"])
@login_required
def manage_group():
    group_name = f"{session['user']}{config.Config.DIRECTORY_GROUP_NAME_SUFFIX}"
    user = request.form.get("user")
    action = request.form.get("action")
    _update_group = SocaHttpClient(endpoint="/api/ldap/group",  headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY}).put(data={"group": group_name, "user": user, "action": action})

    if _update_group.success:
        flash("Group update successfully", "success")
    else:
        flash(f"Unable to update group:{_update_group.message}", "error")

    return redirect("/my_account")


@my_account.route("/reset_password", methods=["POST"])
@login_required
def reset_key():
    password = request.form.get("password", None)
    password_verif = request.form.get("password_verif", None)
    admin_reset = request.form.get("admin_reset", None)
    if admin_reset == "yes":
        # Admin can generate a temp password on behalf of the user
        user = request.form.get("user", None)
        if user is None:
            return redirect("/admin/users")
        elif user == session["user"]:
            flash(
                "You can not reset your own password using this tool. Please visit 'My Account' section for that",
                "error",
            )
            return redirect("/admin/users")
        else:
            password = "".join(
                random.choice(
                    string.ascii_lowercase + string.ascii_uppercase + string.digits
                )
                for _i in range(25)
            )
            change_password = post(
                config.Config.FLASK_ENDPOINT + "/api/user/reset_password",
                headers={
                    "X-SOCA-TOKEN": session["api_key"],
                    "X-SOCA-USER": session["user"],
                },
                data={"user": user, "password": password},
                verify=False,
            )  # nosec
            if change_password.status_code == 200:
                flash(
                    "Password for "
                    + user
                    + " has been changed to "
                    + password
                    + "<hr> User is recommended to change it using 'My Account' section",
                    "success",
                )
                return redirect("/admin/users")
            else:
                flash(
                    "Unable to reset password. Error: " + str(change_password._content),
                    "error",
                )
                return redirect("/admin/users")
    else:
        if password is not None:
            # User can change their own password
            if password == password_verif:
                change_password = post(
                    config.Config.FLASK_ENDPOINT + "/api/user/reset_password",
                    headers={
                        "X-SOCA-TOKEN": config.Config.API_ROOT_KEY,
                        "X-SOCA-USER": session["user"],
                    },
                    data={"user": session["user"], "password": password},
                    verify=False,
                )  # nosec

                if change_password.status_code == 200:
                    flash("Your password has been changed successfully.", "success")
                    return redirect("/my_account")
                else:
                    flash(
                        "Unable to reset your password. Error: "
                        + str(change_password._content),
                        "error",
                    )
                    return redirect("/my_account")
            else:
                flash("Password does not match", "error")
                return redirect("/my_account")
        else:
            return redirect("/my_account")
