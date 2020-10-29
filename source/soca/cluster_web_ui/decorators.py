import urllib
from functools import wraps
import config
from models import ApiKeys
from flask import request, redirect, session, flash
from requests import get
import logging
logger = logging.getLogger("api")


# Restricted API can only be accessed using Flask Root API key
# In other words, @restricted_api can only be triggered by the web application
def restricted_api(f):
    @wraps(f)
    def restricted_resource(*args, **kwargs):
        token = request.headers.get("X-SOCA-TOKEN", None)
        if token == config.Config.API_ROOT_KEY:
                return f(*args, **kwargs)
        return {"success": False, "message": "Not authorized"}, 401
    return restricted_resource


# Admin API can only be accessed by a token who as "sudo" permission or using Flask root API key
def admin_api(f):
    @wraps(f)
    def admin_resource(*args, **kwargs):
        user = request.headers.get("X-SOCA-USER", None)
        token = request.headers.get("X-SOCA-TOKEN", None)
        if token == config.Config.API_ROOT_KEY:
                return f(*args, **kwargs)

        if user is None or token is None:
            return {"success": False, "message": "Not Authorized"}, 401
        else:
            token_has_sudo = ApiKeys.query.filter_by(token=token,
                                                     user=user,
                                                     scope="sudo",
                                                     is_active=True).first()
            if token_has_sudo:
                return f(*args, **kwargs)
            else:
                return {"success": False, "message": "Not authorized"}, 401
    return admin_resource


# Private API can only be accessed with a valid pair of user/token or web app
def private_api(f):
    @wraps(f)
    def private_resource(*args, **kwargs):
        user = request.headers.get("X-SOCA-USER", None)
        token = request.headers.get("X-SOCA-TOKEN", None)
        if token == config.Config.API_ROOT_KEY:
            return f(*args, **kwargs)

        token_is_valid = ApiKeys.query.filter_by(token=token,
                                                 user=user,
                                                 is_active=True).first()
        if token_is_valid:
            return f(*args, **kwargs)
        else:
            return {"success": False, "message": "Not authorized"}, 401

    return private_resource


# Views require a valid login
def login_required(f):
    @wraps(f)
    def validate_account():
        if "user" in session:
            if "api_key" in session:
                # If a new API key has been issued,
                check_existing_key = ApiKeys.query.filter_by(user=session["user"], is_active=True).first()
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
                check_user_key = get(config.Config.FLASK_ENDPOINT + "/api/user/api_key",
                                     headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                                     params={"user": session["user"]},
                                     verify=False).json()
                session["api_key"] = check_user_key["message"]

            return f()
        else:
            if config.Config.ENABLE_SSO is True:
                data = {'redirect_uri': config.Config.COGNITO_CALLBACK_URL,
                        'client_id': config.Config.COGNITO_APP_ID,
                        'response_type': 'code',
                        'state': request.path}
                oauth_url = config.Config.COGNITO_OAUTH_AUTHORIZE_ENDPOINT + '?' + urllib.parse.urlencode(data)
                return redirect(oauth_url)
            else:
                request_to_forward = request.path
                if request_to_forward == "/":
                    return redirect('/login')
                else:
                    return redirect('/login?fwd='+request_to_forward)

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
            return redirect('/login')

    return check_admin