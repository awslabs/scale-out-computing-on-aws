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
from requests import get, delete
from decorators import login_required

logger = logging.getLogger("application")
my_api_key = Blueprint("my_api_key", __name__, template_folder="templates")


@my_api_key.route("/my_api_key", methods=["GET"])
@login_required
def index():
    check_user_key = get(
        config.Config.FLASK_ENDPOINT + "/api/user/api_key",
        headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
        params={"user": session["user"]},
        verify=False,
    )  # nosec
    if check_user_key.status_code == 200:
        user_token = check_user_key.json()["message"]
    else:
        user_token = "UNKNOWN"
        flash("Unable to retrieve API key for user", "error")

    return render_template(
        "my_api_key.html",
        user=session["user"],
        user_token=user_token,
        scheduler_host=request.host_url,
    )


@my_api_key.route("/reset_api_key", methods=["POST"])
@login_required
def reset_key():
    user = request.form.get("user", None)
    if user is not None:
        invalidate_user_key = delete(
            config.Config.FLASK_ENDPOINT + "/api/user/api_key",
            headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
            data={"user": user},
            verify=False,
        )  # nosec
        logger.info(
            str(request)
            + ": invalidate_user_key: Status: "
            + str(invalidate_user_key.status_code)
        )
        logger.debug(
            "invalidate_user_key: Content: " + str(invalidate_user_key._content)
        )

        if invalidate_user_key.status_code == 200:
            session.pop("api_key", None)
            return redirect("/my_api_key")
        else:
            logger.error(
                "Error while trying to reset Trace: " + str(invalidate_user_key)
            )
            return redirect("/my_api_key")

    else:
        return redirect("/my_api_key")
