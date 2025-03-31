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
from flask import (
    render_template,
    Blueprint,
    request,
    redirect,
    session,
    flash,
    Response,
)
from decorators import login_required, admin_only
from utils.http_client import SocaHttpClient
from utils.error import SocaError


admin_virtual_desktops_list_all = Blueprint(
    "admin_virtual_desktops_list_all", __name__, template_folder="templates"
)
logger = logging.getLogger("soca_logger")


@admin_virtual_desktops_list_all.route(
    "/admin/virtual_desktops/list_all", methods=["GET"]
)
@login_required
@admin_only
def index():
    _get_all_sessions = SocaHttpClient(
        endpoint=f"/api/dcv/virtual_desktops/list_all",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get()

    logger.info(f"get_all_desktops {_get_all_sessions}")
    if _get_all_sessions.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to list desktops because of {_get_all_sessions.get('message')}"
        ).as_flask()

    return render_template(
        "admin/virtual_desktops/list_all_virtual_desktops.html",
        user=session["user"],
        virtual_desktops=_get_all_sessions.get("message"),
        page="admin_virtual_desktop_list_all",
    )
