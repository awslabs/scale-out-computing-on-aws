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
from decorators import login_required
import config
import subprocess
from datetime import datetime, timezone
from flask import (
    send_file,
    render_template,
    Blueprint,
    session,
    redirect,
    request,
    flash,
)
import os
from utils.aws.ssm_parameter_store import SocaConfig
from utils.error import SocaError
from pathlib import Path


logger = logging.getLogger("soca_logger")

ssh = Blueprint("ssh", __name__, template_folder="templates")


@ssh.route("/ssh", methods=["GET"])
@login_required
def home():
    _login_nodes_endpoint = (
        SocaConfig(key="/configuration/NLBLoadBalancerDNSName").get_value().get("message")
    )
    return render_template(
        "ssh.html",
        user=session["user"],
        login_nodes_endpoint=_login_nodes_endpoint,
        timestamp=datetime.now(timezone.utc).strftime("%s"),
    )


@ssh.route("/ssh/get_key", methods=["GET"])
@login_required
def get_key():
    key_type = request.args.get("type", None)
    ts = request.args.get("ts", None)

    if ts is None:
        return redirect("/ssh")

    if key_type is None or key_type not in ["pem", "ppk"]:
        return redirect("/ssh")

    user = session["user"]
    # these are the keys generated when you create a new user
    _ssh_keys = ["id_rsa", "id_ed25519", "id_dsa", "id_ecdsa"]
    user_private_key_path = False
    for _key in _ssh_keys:
        _key_path = f"/data/home/{user}/.ssh/{_key}"
        if Path(_key_path).is_file():
            user_private_key_path = _key_path
            break

    if user_private_key_path is False:
        return SocaError.GENERIC_ERROR(helper=f"Unable to locate any user private key (id_rsa, id_dsa, id_ecdsa or id_ed25519) in /data/home/{user}/.ssh/, please try again").as_flask()

    if key_type == "pem":
        logger.debug(f"Downloading pem file {user_private_key_path}")
        return send_file(
            user_private_key_path,
            as_attachment=True,
            download_name=f"{user}_soca_privatekey.pem",
        )
    else:
        user_private_key_path_ppk = (
            "/apps/soca/"
            + SocaConfig(key="/configuration/ClusterId").get_value().get("message")
            + "/cluster_manager/web_interface/"
            + config.Config.SSH_PRIVATE_KEY_LOCATION
            + "/"
            + user
            + "_soca_privatekey.ppk"
        )
        generate_ppk = [
            "/apps/soca/"
            + SocaConfig(key="/configuration/ClusterId").get_value().get("message")
            + "/cluster_manager/web_interface/unix/puttygen",
            user_private_key_path,
            "-o",
            user_private_key_path_ppk,
        ]

        create_ppk = subprocess.call(generate_ppk)
        if int(create_ppk) != 0:
            flash("Unable to create the download archive, please try again", "error")
            logger.error(
                "Unable to create zip. " + str(generate_ppk) + " : " + str(create_ppk)
            )
            return redirect("/ssh")

        if os.path.exists(user_private_key_path_ppk):
            return send_file(
                user_private_key_path_ppk,
                as_attachment=True,
                download_name=user + "_soca_privatekey.ppk",
            )
        else:
            flash("Unable to locate  the download archive, please try again", "error")
            logger.error(
                "Unable to locate zip. " + str(generate_ppk) + " : " + str(create_ppk)
            )
            return redirect("/ssh")
