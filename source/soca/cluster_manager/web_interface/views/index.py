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
    send_from_directory,
)
from requests import post, get
from utils.http_client import SocaHttpClient
from utils.validators import Validators
from urllib.parse import urlparse

logger = logging.getLogger("soca_logger")
index = Blueprint("index", __name__, template_folder="templates")


@index.route("/ping", methods=["GET"])
def ping():
    session.clear()
    return "Alive", 200


@index.route("/api/api.json", methods=["GET"])
def api_json():
    return send_from_directory("api/v1", "api.json")


@index.route("/api/doc", methods=["GET"])
def api_docs():
    _default_api_doc_provider = "rapidoc"
    api_doc_provider = request.args.get("ui", _default_api_doc_provider)
    if api_doc_provider not in ["rapidoc", "swagger"]:
        api_doc_provider = _default_api_doc_provider

    return render_template("api_doc.html", api_doc_provider=api_doc_provider)


@index.route("/", methods=["GET"])
@login_required
def home():
    sudoers = session["sudoers"]
    _custom_links = config.Config.INDEX_PAGE_CUSTOM_LINKS
    _valid_links = []
    if Validators.is_list(value=_custom_links):
        for link in _custom_links:
            if "url" not in link or "text" not in link:
                logger.warning(
                    "One of your custom links is missing required keys 'url' or 'text', ignoring ... "
                )
                continue

            _parsed_url = urlparse(link.get("url"))
            if _parsed_url.scheme.lower() not in ["http", "https"]:
                logger.warning(
                    f"{link.get('url')} is not an HTTP or HTTPS url, ignoring ... "
                )
                continue

            if not _parsed_url.netloc:
                logger.warning(
                    f"{link.get('url')} does not seems to have any netloc, ignoring ... "
                )
                continue

            _valid_links.append(link)
    else:
        _custom_links = []
        logger.warning(
            "config.Config.INDEX_PAGE_CUSTOM_LINKS is not a valid list ignoring ... "
        )

    return render_template("index.html", sudoers=sudoers, custom_links=_valid_links)


@index.route("/login", methods=["GET"])
def login():
    redirect_url = request.args.get("fwd", None)
    _custom_links = config.Config.LOGIN_PAGE_CUSTOM_LINKS
    _valid_links = []
    if Validators.is_list(value=_custom_links):
        for link in _custom_links:
            if "url" not in link or "text" not in link:
                logger.warning(
                    "One of your custom links is missing required keys 'url' or 'text', ignoring ... "
                )
                continue

            _parsed_url = urlparse(link.get("url"))
            if _parsed_url.scheme.lower() not in ["http", "https"]:
                logger.warning(
                    f"{link.get('url')} is not an HTTP or HTTPS url, ignoring ... "
                )
                continue

            if not _parsed_url.netloc:
                logger.warning(
                    f"{link.get('url')} does not seems to have any netloc, ignoring ... "
                )
                continue

            _valid_links.append(link)
    else:
        _custom_links = []
        logger.warning(
            "config.Config.LOGIN_PAGE_CUSTOM_LINKS is not a valid list ignoring ... "
        )

    if redirect_url is None:
        return render_template("login.html", custom_links=_valid_links, redirect=False)
    else:
        return render_template("login.html", custom_links=_valid_links, redirect=redirect_url)


@index.route("/logout", methods=["GET"])
@login_required
def logout():
    session.clear()
    return redirect("/")


@index.route("/robots.txt", methods=["GET"])
def robots():
    # in case SOCA is accidentally set to wide open, this prevents the website from being indexed on Search Engines
    session.clear()
    return "Disallow: /"


@index.route("/auth", methods=["POST"])
def authenticate():
    user = request.form.get("user")
    password = request.form.get("password")
    redirect_path = request.form.get("redirect")
    logger.info(f"Received login request for: {user}")
    if user is not None and password is not None:
        check_auth = SocaHttpClient(
            endpoint="/api/ldap/authenticate",
            headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
        ).post(data={"user": user, "password": password})
        logger.info(f"Check Auth for {user} response: {check_auth}")
        if not check_auth.success:
            flash(check_auth.message)
            return redirect("/login")
        else:
            session["user"] = user.lower()
            logger.info("User authenticated, checking sudo permissions")
            check_sudo_permission = SocaHttpClient(
                endpoint="/api/ldap/sudo",
                headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
            ).get(params={"user": user})

            if check_sudo_permission.success:
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
            headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
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
        flash(str(sso_auth["message"]), "error")
        return redirect("/login")
