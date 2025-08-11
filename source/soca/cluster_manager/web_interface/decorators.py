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

import urllib
from functools import wraps
import config
from models import ApiKeys
from flask import request, redirect, session, flash, abort
from requests import get, post
import logging
from utils.http_client import SocaHttpClient
import feature_flags

logger = logging.getLogger("soca_logger")


def validate_token(user, token, check_sudo=False):
    # Validate if token supplied is used by Flask or if the pair of username/token is valid
    if token == config.Config.API_ROOT_KEY:
        return True
    else:
        if user is None or token is None:
            return False
        else:
            if check_sudo:
                if ApiKeys.query.filter_by(
                    token=token, user=user, scope="sudo", is_active=True
                ).first():
                    return True
                else:
                    return False
            else:
                if ApiKeys.query.filter_by(
                    token=token, user=user, is_active=True
                ).first():
                    return True
                else:
                    return False


def validate_password(user, password, check_sudo=False):
    # Validate if pair or username/password is valid
    if user is None or password is None:
        return False
    else:
        # password are not stored in DB. We determine successfully login via LDAP bind
        check_auth = SocaHttpClient(
            endpoint="/api/ldap/authenticate",
            headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
        ).post(data={"user": user, "password": password})

        if check_auth.status_code == 200:
            if check_sudo:
                check_sudo_permission = SocaHttpClient(
                    endpoint="/api/ldap/sudo",
                    headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                ).get(param={"user": user})

                if check_sudo_permission.status_code == 200:
                    return True
                else:
                    return False
            else:
                return True
        else:
            return False


# Enable/Disable feature
def feature_flag(flag_name, mode):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):

            def _deny_access(message):
                if mode == "view":
                    flash(message, "error")
                    return redirect("/")
                return {"success": False, "message": message}, 400

            _feature = feature_flags.FEATURE_FLAGS.get(flag_name, {})
            _current_user = session.get("user") or request.headers.get("X-SOCA-USER")
            logger.debug(f"Checking {_current_user} permission to {_feature}")

            if not isinstance(_feature, dict):
                return _deny_access("Invalid feature flag configuration")

            # Global flag
            if not _feature.get("enabled", False):
                return _deny_access("Feature not available on this SOCA cluster")

            _denied_users = _feature.get("denied_users", [])
            _allowed_users = _feature.get("allowed_users", [])

            # Explicit Deny
            if _current_user in _denied_users:
                return _deny_access(
                    "Feature not available for you on this SOCA cluster"
                )

            # Enabled is True, allowed_users list is set but user not in list
            if _allowed_users and _current_user not in _allowed_users:
                return _deny_access(
                    "Feature not available for you on this SOCA cluster"
                )

            # All other use cases, return True
            return f(*args, **kwargs)

        return wrapped

    return decorator


# Restricted API can only be accessed using Flask Root API key
# In other words, @restricted_api can only be triggered by the web application
def restricted_api(f):
    @wraps(f)
    def restricted_resource(*args, **kwargs):
        token = request.headers.get("X-SOCA-TOKEN", None)
        if validate_token("", token):
            return f(*args, **kwargs)
        else:
            return {"success": False, "message": "Not authorized"}, 401

    return restricted_resource


# Admin API can only be accessed by a token/user who has "sudo" permission or using Flask root API key
def admin_api(f):
    @wraps(f)
    def admin_resource(*args, **kwargs):
        user = request.headers.get("X-SOCA-USER", None)
        token = request.headers.get("X-SOCA-TOKEN", None)
        if validate_token(user, token, check_sudo=True):
            return f(*args, **kwargs)

        return {"success": False, "message": "Not authorized"}, 401

    return admin_resource


# This is the only decorator that accept X-SOCA-PASSWORD. Used to query /api/user/api_key
def retrieve_api_key(f):
    @wraps(f)
    def get_key(*args, **kwargs):
        user = request.headers.get("X-SOCA-USER", None)
        password = request.headers.get("X-SOCA-PASSWORD", None)
        token = request.headers.get("X-SOCA-TOKEN", None)
        if token == config.Config.API_ROOT_KEY:
            return f(*args, **kwargs)

        # Ensure request can only retrieve her/his own key
        get_key_for_user = request.args.get("user", None)
        if get_key_for_user != user:
            return {"success": False, "message": "Not authorized"}, 401
        else:
            if validate_password(user, password, check_sudo=False):
                return f(*args, **kwargs)

        return {"success": False, "message": "Not authorized"}, 401

    return get_key


# Private API can only be accessed with a valid pair of token or web app
def private_api(f):
    @wraps(f)
    def private_resource(*args, **kwargs):
        user = request.headers.get("X-SOCA-USER", None)
        token = request.headers.get("X-SOCA-TOKEN", None)
        if token == config.Config.API_ROOT_KEY:
            return f(*args, **kwargs)
        get_request_for_user = request.args.get("user", None)
        if validate_token(user, token, check_sudo=False):
            return f(*args, **kwargs)
        return {"success": False, "message": "Not authorized"}, 401

    return private_resource


# Views require a valid login
def login_required(f):
    @wraps(f)
    def validate_account():
        if "user" in session:
            if "api_key" in session:
                # If a new API key has been issued,
                check_existing_key = ApiKeys.query.filter_by(
                    user=session["user"], is_active=True
                ).first()
                if check_existing_key:
                    if check_existing_key.token != session["api_key"]:
                        # Update API Key in session
                        session["api_key"] = check_existing_key.token
                    else:
                        # API Key exist and is already up-to-date
                        pass
                else:
                    session.pop("api_key")
                    return redirect("/")

                #  Make sure the scope still align with SUDO permissions (eg: when admin grant/revoke sudo)
                if session["sudoers"] is True and check_existing_key.scope == "user":
                    # SUDO permissions were revoked for the user
                    session["sudoers"] = False

                if session["sudoers"] is False and check_existing_key.scope == "sudo":
                    # SUDO permissions were granted to the user
                    session["sudoers"] = True

            else:
                # Retrieve current API key for the user or create a new one
                check_user_key = SocaHttpClient(
                    "/api/user/api_key",
                    headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                ).get(params={"user": session["user"]})
                if check_user_key.success:
                    session["api_key"] = check_user_key.message

            return f()
        else:
            if config.Config.ENABLE_SSO is True:
                data = {
                    "redirect_uri": config.Config.COGNITO_CALLBACK_URL,
                    "client_id": config.Config.COGNITO_APP_ID,
                    "response_type": "code",
                    "state": request.path,
                }
                oauth_url = (
                    config.Config.COGNITO_OAUTH_AUTHORIZE_ENDPOINT
                    + "?"
                    + urllib.parse.urlencode(data)
                )
                return redirect(oauth_url)
            else:
                request_to_forward = request.path
                if request_to_forward == "/":
                    return redirect("/login")
                else:
                    return redirect("/login?fwd=" + request_to_forward)

    return validate_account


# Views restricted to admin
def admin_only(f):
    @wraps(f)
    def check_admin():
        if "sudoers" in session:
            if session["sudoers"] is True:
                return f()
            else:
                flash("Sorry this page requires admin privileges.", "error")
                return redirect("/")
        else:
            return redirect("/login")

    return check_admin


def disabled(f):
    @wraps(f)
    def disable_feature(*args, **kwargs):
        if "api" in request.path:
            return {
                "success": False,
                "message": "This API has been disabled by your Administrator",
            }, 401
        else:
            flash(
                "Sorry this feature has been disabled by your Administrator.", "error"
            )
            return redirect("/")

    return disable_feature
