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
from decorators import login_required
from flask import render_template, request, redirect, session, flash, Blueprint
from cryptography.fernet import Fernet, InvalidToken, InvalidSignature
import json
import base64
from requests import post
from views.my_files import decrypt, user_has_permission
from models import ApplicationProfiles
from collections import OrderedDict
import re
import math

logger = logging.getLogger("soca_logger")
submit_job = Blueprint("submit_job", __name__, template_folder="templates")

# Options delimiter character for Checkbox group values
# should be a single char - such as a comma (,) (default) , or pipe (|) depending on site policy
MULTI_SELECT_DELIMITER = ","


@submit_job.route("/submit_job", methods=["GET"])
@login_required
def index():
    input_file = request.args.get("input_file", None)
    if input_file is None or input_file == "":
        # User must specify input first
        flash(
            "What input file do you want to use? <hr> Navigate to the folder where your input file is located then click 'Use as Simulation Input' icon: <i class='fas fa-microchip fa-lg'  style='color: grey'></i>",
            "info",
        )
        return redirect("/my_files")

    application_profiles = {}
    get_all_application_profiles = ApplicationProfiles.query.all()
    for profile in get_all_application_profiles:
        application_profiles[profile.id] = {
            "profile_name": profile.profile_name,
            "profile_thumbnail": profile.profile_thumbnail,
        }

    return render_template(
        "submit_job.html",
        user=session["user"],
        application_profiles=OrderedDict(
            sorted(
                application_profiles.items(), key=lambda x: x[1]["profile_name"].lower()
            )
        ),
        input_file=False if input_file is None else input_file,
    )


@submit_job.route("/submit_job", methods=["POST"])
@login_required
def job_submission():
    if "app" not in request.form or "input_file" not in request.form:
        flash("Missing required parameters.", "error")
        return redirect("/submit_job")

    app = request.form["app"]
    input_file_info = request.form["input_file"]
    get_application_profile = ApplicationProfiles.query.filter_by(id=app).first()
    if get_application_profile:
        file_info = decrypt(input_file_info)
        if file_info["success"] is not True:
            flash(
                "Unable to use this file as an input (maybe the file was removed or you do not have permission to access it. <br> Please try again or use a different model. Error is: "
                + str(file_info),
                "error",
            )
            return redirect("/submit_job")
        profile_form = base64.b64decode(get_application_profile.profile_form).decode()
        profile_interpreter = get_application_profile.profile_interpreter
        if profile_interpreter == "qsub":
            profile_interpreter = config.Config.PBS_QSUB

        profile_job = get_application_profile.profile_job

        input_path = json.loads(file_info["message"])["file_path"]
        input_name = input_path.split("/")[-1]
        input_file_path = "/".join(input_path.split("/")[:-1])

        return render_template(
            "submit_job_selected_application.html",
            profile_name=get_application_profile.profile_name,
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
        flash("Application not found.", "error")
        return redirect("/submit_job")


@submit_job.route("/submit_job/send", methods=["POST"])
@login_required
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
                job_to_submit = job_to_submit.replace(
                    "%" + param_name + "%", session["user"]
                )
            elif param_name == "HOME":
                job_to_submit = job_to_submit.replace(
                    "%" + param_name + "%",
                    config.Config.USER_HOME + "/" + session["user"],
                )
            else:
                job_to_submit = job_to_submit.replace(
                    "%" + param_name + "%", param_value
                )

    payload = base64.b64encode(job_to_submit.encode()).decode()
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
