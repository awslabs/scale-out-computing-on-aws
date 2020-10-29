import logging
import config
from flask import render_template, Blueprint, request, redirect, session, flash
from requests import get, delete
from decorators import login_required

logger = logging.getLogger("application")
my_jobs = Blueprint('my_jobs', __name__, template_folder='templates')


@my_jobs.route("/my_jobs", methods=["GET"])
@login_required
def index():
    get_job_for_user = get(config.Config.FLASK_ENDPOINT + "/api/scheduler/jobs",
                           headers={"X-SOCA-USER": session["user"],
                                    "X-SOCA-TOKEN": session["api_key"]},
                         params={"user": session["user"]},
                         verify=False)
    if get_job_for_user.status_code == 200:
        return render_template("my_jobs.html", user=session["user"], jobs=get_job_for_user.json()["message"], page="my_jobs")
    else:
        flash("Unable to retrieve your job", "error")
        return render_template("my_jobs.html", user=session["user"], jobs={}, page="my_jobs")


@my_jobs.route("/my_jobs/delete", methods=["GET"])
@login_required
def delete_job():
    job_id = request.args.get("job_id", False)
    if job_id is False:
        return redirect("/my_jobs")

    delete_job = delete(config.Config.FLASK_ENDPOINT + "/api/scheduler/job",
                              headers={"X-SOCA-USER": session["user"],
                                       "X-SOCA-TOKEN": session["api_key"]},
                              params={"job_id": job_id},
                              verify=False)
    if delete_job.status_code == 200:
        flash("Request to delete job was successful. The job will be removed from the queue shortly", "success")
    else:
        flash("Unable to delete this job: " + delete_job.json()["message"], "error")
    return redirect("/my_jobs")