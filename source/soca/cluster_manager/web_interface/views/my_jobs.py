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
from decorators import login_required, feature_flag
from utils.datamodels.hpc.scheduler import get_schedulers
from utils.http_client import SocaHttpClient


logger = logging.getLogger("soca_logger")
my_jobs = Blueprint("my_jobs", __name__, template_folder="templates")


@my_jobs.route("/my_jobs", methods=["GET"])
@login_required
@feature_flag(flag_name="HPC", mode="view")
def index():
    _scheduler_id = request.args.get("scheduler_id", "all")
    _queue = request.args.get("queue", "")
    _user = request.args.get("user", session["user"])

    _scheduler = get_schedulers()
    _scheduler_list = [scheduler.identifier for scheduler in _scheduler]

    _get_jobs_info = SocaHttpClient(
        endpoint="/api/scheduler/jobs",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).get(params={"user": _user, "scheduler_id": _scheduler_id, "queue": _queue})

    logger.debug(f"Get Job  Info {_get_jobs_info}")
    if _get_jobs_info.get("success") is True:
        _jobs = _get_jobs_info.get("message").get("jobs", [])
        _sched_errors = _get_jobs_info.get("message").get("scheduler_errors", [])
        if _sched_errors:
            flash(
                f"Unable to retrieve jobs for scheduler(s): {', '.join(_sched_errors)}. See logs for additional details.",
                "error",
            )
    else:
        flash(
            "Unable to retrieve jobs on all schedulers. Verify user/scheduler/queue parameters and check logs for more details",
            "error",
        )
        _jobs = []

    return render_template(
        "my_jobs.html",
        jobs=_jobs,
        scheduler_list=_scheduler_list,
        page="my_jobs",
    )


@my_jobs.route("/my_jobs/delete", methods=["GET"])
@login_required
@feature_flag(flag_name="HPC", mode="view")
def delete_job():
    _job_id = request.args.get("job_id", "")
    _scheduler_id = request.args.get("scheduler_id", "")
    if not _job_id or not _scheduler_id:
        flash("scheduler_id and job_id must be specified")
        return redirect("/my_jobs")

    _delete_job = SocaHttpClient(
        endpoint="/api/scheduler/job",
        headers={"X-SOCA-USER": session["user"], "X-SOCA-TOKEN": session["api_key"]},
    ).delete(data={"job_id": _job_id, "scheduler_id": _scheduler_id})

    if _delete_job.get("success") is True:
        flash(
            "Request to delete job was successful. The job will be removed from the queue shortly",
            "success",
        )
    else:
        logger.info(
            f"Unable to delete {_job_id=} for {_scheduler_id=} due to {_delete_job.get('message')}"
        )
        flash(
            f"Unable to delete this job {_job_id} for scheduler {_scheduler_id}. See logs for additional details.",
            "error",
        )
    return redirect("/my_jobs")
