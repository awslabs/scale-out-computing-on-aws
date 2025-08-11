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
from flask import render_template, Blueprint, request, redirect, session, flash
from decorators import login_required, admin_only
from utils.http_client import SocaHttpClient
from collections import defaultdict

logger = logging.getLogger("soca_logger")
admin_projects = Blueprint("admin_projects", __name__, template_folder="templates")


def get_region():
    session = boto3.session.Session()
    aws_region = session.region_name
    return aws_region


@admin_projects.route("/admin/projects", methods=["GET"])
@login_required
@admin_only
def index():
    logger.info(f"List all SOCA Projects")
    _list_projects = SocaHttpClient(
        endpoint="/api/projects",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get()

    _list_all_users = SocaHttpClient(
        endpoint="/api/ldap/users",
        headers={"X-SOCA-TOKEN": session["api_key"], "X-SOCA-USER": session["user"]},
    ).get()

    if _list_all_users.get("success") is True:
        _all_users = _list_all_users.get("message")
    else:
        flash(f"Unable to list all users: {_list_all_users.get('message')}", "error")
        _all_users = []
        
    _list_all_groups = SocaHttpClient(
        endpoint="/api/ldap/groups",
        headers={"X-SOCA-TOKEN": session["api_key"], "X-SOCA-USER": session["user"]},
    ).get()

    if _list_all_groups.get("success") is True:
        _all_groups = _list_all_groups.get("message")
    else:
        flash(f"Unable to list all groups: {_list_all_groups.get('message')}", "error")
        _all_groups = []

    _list_software_stacks = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/software_stacks",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get()

    if _list_software_stacks.get("success") is False:
        flash(
            f"Unable to list Software Stacks because of {_list_software_stacks.get('message')}",
            "error",
        )
        _software_stacks = {}
    else:
        _software_stacks = _list_software_stacks.get("message")

    _list_target_nodes_software_stacks = SocaHttpClient(
        endpoint="/api/target_nodes/software_stacks",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get()

    if _list_target_nodes_software_stacks.get("success") is False:
        flash(
            f"Unable to list Target Node Software Stacks because of {_list_target_nodes_software_stacks.get('message')}",
            "error",
        )
        _target_nodes_software_stacks = {}
    else:
        _target_nodes_software_stacks = _list_target_nodes_software_stacks.get(
            "message"
        )

    _list_application_profiles = SocaHttpClient(
        endpoint="/api/applications/list_applications",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get()

    if _list_application_profiles.get("success") is False:
        flash(
            f"Unable to list Software Applications because of {_list_application_profiles.get('message')}",
            "error",
        )
        _application_profiles = {}
    else:
        _application_profiles = _list_application_profiles.get("message")

    _list_target_nodes_software_stacks = SocaHttpClient(
        endpoint="/api/target_nodes/software_stacks",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get()

    if _list_target_nodes_software_stacks.get("success") is False:
        flash(
            f"Unable to list Target Node Software Stacks because of {_list_target_nodes_software_stacks.get('message')}",
            "error",
        )
        _target_nodes_software_stacks = {}
    else:
        _target_nodes_software_stacks = _list_target_nodes_software_stacks.get(
            "message"
        )

    _check_budget = SocaHttpClient(
        endpoint=f"/api/cost_management/budgets",
        headers={
            "X-SOCA-USER": session["user"],
            "X-SOCA-TOKEN": session["api_key"],
        },
    ).get()
    if _check_budget.get("success") is False:
        flash(f"Unable to check budget due to {_check_budget.get('message')}", "error")
        _budgets = []
    else:
        _budgets = _check_budget.get("message")

    if _list_projects.get("success") is False:
        flash(
            f"Unable to list SOCA Projects because of {_list_projects.get('message')}",
            "error",
        )
        _projects = {}
    else:
        _projects = _list_projects.get("message")

    return render_template(
        "admin/projects/projects.html",
        projects=_projects,
        budgets=_budgets,
        all_users=_all_users,
        all_groups=_all_groups,
        software_stacks=_software_stacks,
        application_profiles=_application_profiles,
        target_nodes_software_stacks=_target_nodes_software_stacks,
        page="admin_projects",
    )


@admin_projects.route("/admin/projects/create", methods=["POST"])
@login_required
@admin_only
def project_create():
    logger.info(f"Received following parameters {request.form} to create soca projects")
    _create_project = SocaHttpClient(
        endpoint="/api/projects",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).post(data=request.form.to_dict())

    if _create_project.get("success") is True:
        flash(
            f"Your project has been created successfully",
            "success",
        )
    else:
        flash(
            f"Unable to create your project because of {_create_project.get('message')}",
            "error",
        )

    return redirect("/admin/projects")


@admin_projects.route("/admin/projects/delete", methods=["POST"])
@login_required
@admin_only
def project_delete():
    logger.info(f"Received following parameters {request.form} to delete soca project")

    _delete_project = SocaHttpClient(
        endpoint="/api/projects",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).delete(data=request.form.to_dict())

    if _delete_project.get("success") is True:
        flash(
            f"Your project has been removed  successfully",
            "success",
        )
    else:
        flash(
            f"Unable to remove your project because of {_delete_project.get('message')}",
            "error",
        )

    return redirect("/admin/projects")


@admin_projects.route("/admin/projects/edit", methods=["POST", "GET"])
@login_required
@admin_only
def project_edit():
    if request.method == "GET":
        return redirect("/admin/projects")

    logger.info(f"Received following parameters {request.form} to edit projects")
    _project_to_modify = request.form.get("project_id", None)
    if _project_to_modify is None:
        flash("Missing project_id", "error")
        return redirect("/admin/projects")

    _get_project_info = SocaHttpClient(
        endpoint="/api/projects",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get(params={"project_id": request.form.get("project_id")})

    _list_software_stacks = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/software_stacks",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get()

    if _list_software_stacks.get("success") is False:
        flash(
            f"Unable to list Software Stacks because of {_list_software_stacks.get('message')}",
            "error",
        )
        _software_stacks = {}
    else:
        _software_stacks = _list_software_stacks.get("message")

    _list_all_groups = SocaHttpClient(
        endpoint="/api/ldap/groups",
        headers={"X-SOCA-TOKEN": session["api_key"], "X-SOCA-USER": session["user"]},
    ).get()

    if _list_all_groups.get("success") is True:
        _all_groups = _list_all_groups.get("message")
    else:
        flash(f"Unable to list all groups: {_list_all_groups.get('message')}", "error")
        _all_groups = []
        
    _list_target_nodes_software_stacks = SocaHttpClient(
        endpoint="/api/target_nodes/software_stacks",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get()

    if _list_target_nodes_software_stacks.get("success") is False:
        flash(
            f"Unable to list Target Node Software Stacks because of {_list_target_nodes_software_stacks.get('message')}",
            "error",
        )
        _target_nodes_software_stacks = {}
    else:
        _target_nodes_software_stacks = _list_target_nodes_software_stacks.get(
            "message"
        )

    _list_all_users = SocaHttpClient(
        endpoint="/api/ldap/users",
        headers={"X-SOCA-TOKEN": session["api_key"], "X-SOCA-USER": session["user"]},
    ).get()

    if _list_all_users.get("success") is True:
        _all_users = _list_all_users.get("message")
    else:
        flash(f"Unable to list all users: {_list_all_users.get('message')}", "error")
        _all_users = []

    _list_application_profiles = SocaHttpClient(
        endpoint="/api/applications/list_applications",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get()

    if _list_application_profiles.get("success") is False:
        flash(
            f"Unable to list Software Applications because of {_list_application_profiles.get('message')}",
            "error",
        )
        _application_profiles = {}
    else:
        _application_profiles = _list_application_profiles.get("message")

    _check_budget = SocaHttpClient(
        endpoint=f"/api/cost_management/budgets",
        headers={
            "X-SOCA-USER": session["user"],
            "X-SOCA-TOKEN": session["api_key"],
        },
    ).get()
    if _check_budget.get("success") is False:
        flash(f"Unable to check budget due to {_check_budget.get('message')}", "error")
        _budgets = []
    else:
        _budgets = _check_budget.get("message")

    if _get_project_info.get("success") is True:
        return render_template(
            "admin/projects/projects_edit.html",
            user=session["user"],
            all_users=_all_users,
            all_groups=_all_groups,
            budgets=_budgets,
            application_profiles=_application_profiles,
            project_info=_get_project_info.get("message").get(_project_to_modify),
            software_stacks=_software_stacks,
            target_nodes_software_stacks=_target_nodes_software_stacks,
            page="admin_projects",
        )
    else:
        flash(
            f"Unable to list SOCA Projects because of {_get_project_info.get('message')}",
            "error",
        )
        return redirect("/admin/projects")


@admin_projects.route("/admin/projects/edit/update", methods=["POST"])
@login_required
@admin_only
def software_stack_update():
    logger.info(f"Received following parameters {request.form} to update projects ")

    _project_to_modify = request.form.get("project_id", None)
    if _project_to_modify is None:
        flash("Missing project_id", "error")
        return redirect("/admin/projects")

    # Convert to a dictionary, merging duplicate keys into CSV strings
    # Handle software_stack_ids which is a select with multiple options.

    result_dict = defaultdict(list)
    for key, value in request.form.items(multi=True):
        result_dict[key].append(value)
    _converted_data = {
        key: ",".join(values) if len(values) > 1 else values[0]
        for key, values in result_dict.items()
    }

    _modify_project = SocaHttpClient(
        endpoint="/api/projects",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).put(data=_converted_data)

    if _modify_project.get("success") is True:
        flash(
            f"Your project has been updated successfully",
            "success",
        )
    else:
        flash(
            f"{_modify_project.get('message')}",
            "error",
        )
    return redirect("/admin/projects")


@admin_projects.route("/admin/projects/by_user", methods=["GET", "POST"])
@login_required
@admin_only
def projects_by_user():
    _user = request.form.get("user", "")
    _user_projects = {}
    if request.method == "POST":
        logger.info(f"List all SOCA Projects for user {_user}")
        _get_all_projects_for_user = SocaHttpClient(
            endpoint=f"/api/user/resources_permissions",
            headers={
                "X-SOCA-USER": session["user"],
                "X-SOCA-TOKEN": session["api_key"],
            },
        ).post(
            data={
                "user": _user,
                "virtual_desktops": "all",
                "target_nodes": "all",
                "application_profiles": "all",
                "exclude_columns": "thumbnail",
            }
        )
        _user_projects = _get_all_projects_for_user.get("message")

    _get_all_soca_users = SocaHttpClient(
        endpoint=f"/api/ldap/users",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get()

    return render_template(
        "admin/projects/projects_by_user.html",
        user_to_check=_user,
        projects=_user_projects,
        all_soca_users=_get_all_soca_users.get("message"),
        page="admin_projects_per_user",
    )
