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
from decorators import login_required, feature_flag
from flask import render_template, request, redirect, session, flash, Blueprint
from cryptography.fernet import Fernet, InvalidToken, InvalidSignature
import json
import base64
from requests import post
from views.my_files import decrypt
from models import ApplicationProfiles
from collections import OrderedDict
import re
import math
from utils.jinjanizer import SocaJinja2Renderer
from utils.http_client import SocaHttpClient

logger = logging.getLogger("soca_logger")
submit_job = Blueprint("submit_job", __name__, template_folder="templates")

# Options delimiter character for Checkbox group values
# should be a single char - such as a comma (,) (default) , or pipe (|) depending on site policy
MULTI_SELECT_DELIMITER = ","


@submit_job.route("/submit_job", methods=["GET"])
@login_required
@feature_flag(flag_name="HPC", mode="view")
def index():
    input_file = request.args.get("input_file", None)
    if input_file is None or input_file == "":
        # User must specify input first
        flash(
            "What input file do you want to use? <hr> Navigate to the folder where your input file is located then click 'Use as Simulation Input' icon: <i class='fas fa-microchip fa-lg'  style='color: grey'></i>",
            "info",
        )
        return redirect("/my_files")

    _get_authorized_application_profiles = SocaHttpClient(
        endpoint=f"/api/user/resources_permissions",
        headers={
            "X-SOCA-USER": session["user"],
            "X-SOCA-TOKEN": session["api_key"],
        },
    ).get(params={"application_profiles": "all"})

    if _get_authorized_application_profiles.get("success") is False:
        flash(
            f"Unable to list software stack for this user because of {_get_authorized_application_profiles.get('message')}",
            "error",
        )
        _application_profiles = {}
    else:
        _application_profiles = _get_authorized_application_profiles.get("message").get(
            "application_profiles"
        )

    return render_template(
        "submit_job.html",
        application_profiles=_application_profiles,
        input_file=False if input_file is None else input_file,
    )


@submit_job.route("/submit_job", methods=["POST"])
@login_required
@feature_flag(flag_name="HPC", mode="view")
def job_submission():
    if "app" not in request.form or "input_file" not in request.form:
        flash("Missing required parameters.", "error")
        return redirect("/submit_job")

    app = request.form["app"]

    _get_authorized_application_profiles = SocaHttpClient(
        endpoint=f"/api/user/resources_permissions",
        headers={
            "X-SOCA-USER": session["user"],
            "X-SOCA-TOKEN": session["api_key"],
        },
    ).get(params={"application_profiles": f"{app}"})

    if _get_authorized_application_profiles.get("success") is False:
        flash(
            f"Unable to list software stack for this user because of {_get_authorized_application_profiles.get('message')}",
            "error",
        )
        return redirect("/submit_job")
    else:
        get_application_profile = _get_authorized_application_profiles.get(
            "message"
        ).get("application_profiles")

    input_file_info = request.form["input_file"]
    if get_application_profile:
        file_info = decrypt(input_file_info)
        if file_info["success"] is not True:
            flash(
                "Unable to use this file as an input (maybe the file was removed or you do not have permission to access it. <br> Please try again or use a different model. Error is: "
                + str(file_info),
                "error",
            )
            return redirect("/submit_job")
        profile_form = base64.b64decode(
            get_application_profile[0].get("profile_form")
        ).decode()
        profile_interpreter = get_application_profile[0].get("profile_interpreter")
        if profile_interpreter == "qsub":
            profile_interpreter = config.Config.PBS_QSUB

        profile_job = get_application_profile[0].get("profile_job")
        profile_name = get_application_profile[0].get("profile_name")
        input_path = json.loads(file_info["message"])["file_path"]
        input_name = input_path.split("/")[-1]
        input_file_path = "/".join(input_path.split("/")[:-1])

        return render_template(
            "submit_job_selected_application.html",
            profile_name=profile_name,
            user=session["user"],
            profile_form=profile_form,
            profile_job=profile_job,
            page="submit_job",
            profile_interpreter=profile_interpreter,
            pbs_interpreter=config.Config.PBS_QSUB,
            input_path=input_path.rstrip().lstrip(),
            input_file_path=input_file_path,
            input_name=input_name,
        )

    else:
        flash("Application not found or user is not authorized.", "error")
        return redirect("/submit_job")


@submit_job.route("/submit_job/send", methods=["POST"])
@login_required
@feature_flag(flag_name="HPC", mode="view")
def send_job():
    try:
        job_to_submit = base64.b64decode(request.form["job_script"]).decode()
    except Exception as err:
        flash("Unable to read the job script due to: " + str(err), "error")
        return redirect("/my_files")

    if request.form["profile_interpreter"] == config.Config.PBS_QSUB:
        required_parameters = ["cpus", "instance_type"]
        for param in required_parameters:
            if param not in request.form:
                flash("You must specify cpus and instance_type parameters", "error")
                return redirect("/my_files")

        # Calculate the number of nodes to be provisioned for the simulation
        cpus = request.form["cpus"]
        instance_type = request.form["instance_type"]
        if cpus is None:
            nodect = 1
        else:
            cpus_count_pattern = re.search(r"[.](\d+)", instance_type)
            if cpus_count_pattern:
                cpu_per_system = int(cpus_count_pattern.group(1)) * 2
            else:
                if re.search(r"[.](xlarge)", instance_type):
                    cpu_per_system = 2
                else:
                    cpu_per_system = 1
            nodect = math.ceil(int(cpus) / cpu_per_system)

        find_shebang = re.search(r"#!([^\s]+)", job_to_submit)
        check_job_node_count = re.search(r"#PBS -l select=(\d+)", job_to_submit)
        if find_shebang:
            shebang = find_shebang.group(1)
        else:
            shebang = False

        if check_job_node_count:
            if str(check_job_node_count.group(1)) != str(nodect):
                job_to_submit = job_to_submit.replace(
                    "#PBS -l select=" + str(check_job_node_count.group(1)),
                    "#PBS -l select=" + str(nodect),
                )
        else:
            if shebang:
                # Add right after shebang
                job_to_submit = job_to_submit.replace(
                    shebang,
                    shebang
                    + "\n #Added by SOCA Web UI \n"
                    + "#PBS -l select="
                    + str(nodect)
                    + ":ncpus="
                    + str(cpu_per_system)
                    + "\n",
                )
            else:
                # Add first line
                job_to_submit = (
                    "#PBS -l select="
                    + str(nodect)
                    + ":ncpus="
                    + str(cpu_per_system)
                    + " \n #Added by SOCA Web UI \n"
                    + job_to_submit
                )

    params = {}
    for param_name in request.form:
        param_value = request.form.get(param_name)

        if param_name.endswith("[]"):  # Multi-select (Checkbox Group) look like: name[]
            param_value = MULTI_SELECT_DELIMITER.join(request.form.getlist(param_name))
            # Now remove the [] from the param name to make it easier for the user in the job scripting
            param_name = param_name[:-2]

        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                f"Processing Form inputs for macro expansion - Parameter name: ({param_name}), Value: ({param_value})"
            )

        if param_name != "csrf_token":
            if param_name.lower() == "user":
                params[param_name] = session["user"]
            elif param_name == "HOME":
                params[param_name] = config.Config.USER_HOME + "/" + session["user"]
            else:
                params[param_name] = param_value

    soca_result = SocaJinja2Renderer().from_string(data=job_to_submit, variables=params)

    if (soca_result).get("success") is True:
        rendered_template = soca_result.get("message")
    else:
        flash(
            "Error during job submission: " + str(soca_result.get("message")),
            "error",
        )
        return redirect("/my_jobs")

    payload = base64.b64encode(rendered_template.encode()).decode()
    send_to_to_queue = post(
        config.Config.FLASK_ENDPOINT + "/api/scheduler/job",
        headers={"X-SOCA-TOKEN": session["api_key"], "X-SOCA-USER": session["user"]},
        data={
            "payload": payload,
            "interpreter": request.form["profile_interpreter"],
            "input_file_path": request.form["input_file_path"],
        },
        verify=False,
    )  # nosec
    if send_to_to_queue.status_code == 200:
        if request.form["profile_interpreter"] == config.Config.PBS_QSUB:
            flash(
                "Job submitted to the queue with ID: "
                + send_to_to_queue.json()["message"],
                "success",
            )
        else:
            flash(send_to_to_queue.json()["message"], "success")
    else:
        flash(
            "Error during job submission: " + str(send_to_to_queue.json()["message"]),
            "error",
        )

    return redirect("/my_jobs")
