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
my_jobs = Blueprint("my_jobs", __name__, template_folder="templates")


@my_jobs.route("/my_jobs", methods=["GET"])
@login_required
def index():
    get_job_for_user = get(
        config.Config.FLASK_ENDPOINT + "/api/scheduler/jobs",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        params={"user": session["user"]},
        verify=False,
    )  # nosec
    if get_job_for_user.status_code == 200:
        return render_template(
            "my_jobs.html",
            user=session["user"],
            jobs=get_job_for_user.json()["message"],
            page="my_jobs",
        )
    else:
        flash("Unable to retrieve your job", "error")
        return render_template(
            "my_jobs.html", user=session["user"], jobs={}, page="my_jobs"
        )


@my_jobs.route("/my_jobs/delete", methods=["GET"])
@login_required
def delete_job():
    job_id = request.args.get("job_id", False)
    if job_id is False:
        return redirect("/my_jobs")

    delete_job = delete(
        config.Config.FLASK_ENDPOINT + "/api/scheduler/job",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
        data={"job_id": job_id},
        verify=False,
    )  # nosec
    if delete_job.status_code == 200:
        flash(
            "Request to delete job was successful. The job will be removed from the queue shortly",
            "success",
        )
    else:
        flash("Unable to delete this job: " + delete_job.json()["message"], "error")
    return redirect("/my_jobs")
