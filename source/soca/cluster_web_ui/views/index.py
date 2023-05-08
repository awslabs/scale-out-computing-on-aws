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
import cognito_auth
from decorators import login_required
from flask import (
    render_template,
    request,
    redirect,
    session,
    flash,
    Blueprint,
    current_app,
)
from requests import post, get

logger = logging.getLogger("application")
index = Blueprint("index", __name__, template_folder="templates")


@index.route("/ping", methods=["GET"])
def ping():
    return "Alive", 200


@index.route("/", methods=["GET"])
@login_required
def home():
    user = session["user"]
    sudoers = session["sudoers"]
    return render_template("index.html", user=user, sudoers=sudoers)


@index.route("/login", methods=["GET"])
def login():
    redirect = request.args.get("fwd", None)
    if redirect is None:
        return render_template("login.html", redirect=False)
    else:
        return render_template("login.html", redirect=redirect)


@index.route("/logout", methods=["GET"])
@login_required
def logout():
    session_data = ["user", "sudoers", "api_key"]
    for param in session_data:
        session.pop(param, None)
    return redirect("/")


@index.route("/robots.txt", methods=["GET"])
def robots():
    # in case SOCA is accidentally set to wide open, this prevents the website from being indexed on Search Engines
    return "Disallow: /"


@index.route("/auth", methods=["POST"])
def authenticate():
    user = request.form.get("user")
    password = request.form.get("password")
    redirect_path = request.form.get("redirect")
    logger.info("Received login request for : " + str(user))
    if user is not None and password is not None:
        check_auth = post(
            config.Config.FLASK_ENDPOINT + "/api/ldap/authenticate",
            headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
            data={"user": user, "password": password},
            verify=False,
        )  # nosec
        logger.info(check_auth)
        if check_auth.status_code != 200:
            flash(check_auth.json()["message"])
            return redirect("/login")
        else:
            session["user"] = user.lower()
            logger.info("User authenticated, checking sudo permissions")
            check_sudo_permission = get(
                config.Config.FLASK_ENDPOINT + "/api/ldap/sudo",
                headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                params={"user": user},
                verify=False,
            )  # nosec
            if check_sudo_permission.status_code == 200:
                session["sudoers"] = True
            else:
                session["sudoers"] = False

            if redirect_path is not None:
                return redirect(redirect_path)
            else:
                return redirect("/")

    else:
        return redirect("/login")


@index.route("/oauth", methods=["GET"])
def oauth():
    next_url = request.args.get("state")
    sso_auth = cognito_auth.sso_authorization(request.args.get("code"))
    cognito_root_url = config.Config.COGNITO_ROOT_URL
    if sso_auth["success"] is True:
        logger.info("User authenticated, checking sudo permissions")
        check_sudo_permission = get(
            config.Config.FLASK_ENDPOINT + "/api/ldap/sudo",
            headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
            params={"user": session["user"]},
            verify=False,
        )  # nosec
        if check_sudo_permission.status_code == 200:
            session["sudoers"] = True
        else:
            session["sudoers"] = False

        if next_url:
            return redirect(cognito_root_url + next_url)
        else:
            return redirect(cognito_root_url)
    else:
        if sso_auth["message"] == "user_not_found":
            flash("This user does not seems to have an account on SOCA", "error")
        else:
            flash(str(sso_auth["message"]), "error")
        return redirect("/login")
