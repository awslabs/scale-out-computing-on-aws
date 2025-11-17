# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

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
from models import db, ApplicationProfiles
from decorators import login_required, admin_only
import base64
from datetime import datetime, timezone
import json
from utils.datamodels.hpc.scheduler import get_schedulers
from utils.http_client import SocaHttpClient

logger = logging.getLogger("soca_logger")
admin_applications = Blueprint(
    "admin_applications", __name__, template_folder="templates"
)


@admin_applications.route("/admin/applications", methods=["GET"])
@login_required
@admin_only
def index():
    logger.info("List all applications")
    _list_all_applications = SocaHttpClient(
        endpoint="/api/applications/list_applications",
        headers={
            "X-SOCA-TOKEN": session.get("api_key",""),
            "X-SOCA-USER": session.get("user",""),
        },
    ).get()
    if _list_all_applications.get("success") is False:
        logger.error(
            f"Unable to list applications because of {_list_all_applications.get('message')}"
        )
        flash(
            "Unable to list applications. See logs for additional details.",
            "error",
        )
        return redirect("/admin/applications")
    else:
        application_profiles = _list_all_applications.get("message")

    return render_template(
        "admin/applications.html",
        page="application",
        profile_interpreter="",
        schedulers=get_schedulers(),
        application_profiles=application_profiles,
        action="create",
    )


@admin_applications.route("/admin/applications/edit", methods=["GET"])
@login_required
@admin_only
def edit():
    _application_id = request.get("application_id", "")
    logger.info(f"Edit application: {_application_id=}")

    _list_all_applications = SocaHttpClient(
        endpoint="/api/applications/list_applications",
        headers={
            "X-SOCA-TOKEN": session.get("api_key",""),
            "X-SOCA-USER": session.get("user",""),
        },
    ).get()
    if _list_all_applications.get("success") is False:
        logger.error(
            f"Unable to list applications because of {_list_all_applications.get('message')}"
        )
        flash(
            "Unable to list applications. See logs for additional details.",
            "error",
        )
        return redirect("/admin/applications")

    else:
        _application_profile = None
        for _app in _list_all_applications.get("message"):
            if _app.id == _application_id:
                _application_profile = _app
                break
        
        if not _application_profile:
            logger.error(f"Application ID: {_application_id} not found")
            flash(f"Application ID: {_application_id} not found")
            return redirect("/admin/applications")
        else:
            try:
                profile_form = base64.b64decode(_application_profile.profile_form).decode()
            except Exception as err:
                logger.error(f"Unable to decode profile_form due to {err}")
                flash("Unable to edit application. See logs for additional details.")
                return redirect("/admin/applications")
            
            try:
                profile_job = base64.b64decode(_application_profile.profile_job).decode()
                profile_job = json.dumps(profile_job)[1:-1]
            except Exception as err:
                logger.error(f"Unable to decode profile_job due to {err}")
                flash("Unable to edit application. See logs for additional details.")
                return redirect("/admin/applications")
            
            profile_interpreter = _application_profile.profile_interpreter
            profile_name = _application_profile.profile_name

    return render_template(
        "admin/applications.html",
        user=session["user"],
        app_id=_application_id,
        profile_form=profile_form,
        profile_job=profile_job,
        profile_name=profile_name,
        profile_interpreter=profile_interpreter,
        schedulers=get_schedulers(),
        application_profiles=_list_all_applications,
        page="application",
        action="edit",
    )


@admin_applications.route("/admin/applications/create", methods=["post"])
@login_required
@admin_only
def create_application():
    _create_application = SocaHttpClient(
        "/api/applications/application",
        headers={
            "X-SOCA-TOKEN": session.get("api_key",""),
            "X-SOCA-USER": session.get("user",""),
        },
    ).post(
        data={
            "submit_job_script": request.form.get("submit_job_script", ""),
            "submit_job_form": request.form.get("submit_job_form", ""),
            "submit_job_interpreter": request.form.get("submit_job_interpreter", ""),
            "profile_name": request.form.get("profile_name", ""),
            "thumbnail_b64": request.form.get("thumbnail_b64", ""),
        }
    )
    flash(
        _create_application.get("message"),
        "success" if _create_application.get("success") is True else "error",
    )
    return redirect("/admin/applications")


@admin_applications.route("/admin/applications/edit", methods=["POST"])
@login_required
@admin_only
def edit_application():
    _update_application = SocaHttpClient(
        "/api/applications/application",
        headers={
            "X-SOCA-TOKEN": session.get("api_key",""),
            "X-SOCA-USER": session.get("user",""),
        },
    ).put(
        data={
            "submit_job_script": request.form.get("submit_job_script", ""),
            "submit_job_form": request.form.get("submit_job_form", ""),
            "submit_job_interpreter": request.form.get("submit_job_interpreter", ""),
            "profile_name": request.form.get("profile_name", ""),
            "thumbnail_b64": request.form.get("thumbnail_b64", ""),
            "application_id": request.form.get("application_id", ""),
        }
    )
    flash(
        _update_application.get("message"),
        "success" if _update_application.get("success") is True else "error",
    )
    return redirect("/admin/applications")


@admin_applications.route("/admin/applications/delete", methods=["post"])
@login_required
@admin_only
def delete_application():
    _delete_application = SocaHttpClient(
        "/api/applications/application",
        headers={
            "X-SOCA-TOKEN": session.get("api_key",""),
            "X-SOCA-USER": session.get("user",""),
        },
    ).delete(data={"application_id": request.form.get("application_id", "")})
    flash(
        _delete_application.get("message"),
        "success" if _delete_application.get("success") is True else "error",
    )
    return redirect("/admin/applications")


@admin_applications.route("/admin/applications/export", methods=["GET"])
@login_required
@admin_only
def export_application():
    _application_id = request.args.get("application_id", "")
    logger.info(f"About to submit export request for {_application_id=}")
    _get_json = SocaHttpClient(
        endpoint="/api/applications/export",
        headers={
            "X-SOCA-TOKEN": session.get("api_key",""),
            "X-SOCA-USER": session.get("user",""),
        },
    ).get(params={"application_id": _application_id})
    if _get_json.get("success") is True:
        return Response(
            json.dumps(_get_json.get("message")),
            mimetype="application/json",
            headers={
                "Content-Disposition": f"attachment;filename=soca_app_id_{_application_id}.json"
            },
        )
    else:
        flash(f"No output received, {_application_id=} may not exist")
        return redirect("/admin/applications")


@admin_applications.route("/admin/applications/import", methods=["POST"])
@login_required
@admin_only
def import_application():
    _app_profile = request.files.get("app_profile")
    _profile_name = request.form.get("profile_name")
    if not _app_profile:
        flash("app_profile file is missing.")
        return redirect("/admin/applications")
    
    if not _profile_name:
        flash("profile_name is missing.")
        return redirect("/admin/applications")
    
    _import_app = SocaHttpClient(
        "/api/applications/import",
        headers={
            "X-SOCA-TOKEN": session.get("api_key",""),
            "X-SOCA-USER": session.get("user",""),
        },
    ).post(
        data={"profile_name": _profile_name},
        files={
            "app_profile": (
                _app_profile.filename,
                _app_profile.stream,
                _app_profile.content_type,
            )
        }
    )

    flash(
        _import_app.get("message"), "success" if _import_app.get("success") else "error"
    )
    return redirect("/admin/applications")
