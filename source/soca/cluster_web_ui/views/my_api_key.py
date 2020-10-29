import logging
import config
from flask import render_template, Blueprint, request, redirect, session, flash
from requests import get, delete
from decorators import login_required

logger = logging.getLogger("application")
my_api_key = Blueprint('my_api_key', __name__, template_folder='templates')

@my_api_key.route("/my_api_key", methods=["GET"])
@login_required
def index():
    check_user_key = get(config.Config.FLASK_ENDPOINT + "/api/user/api_key",
                         headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                         params={"user": session["user"]},
                         verify=False)
    if check_user_key.status_code == 200:
        user_token = check_user_key.json()["message"]
    else:
        user_token = "UNKNOWN"
        flash("Unable to retrieve API key for user", "error")

    return render_template("my_api_key.html",
                           user=session["user"],
                           user_token=user_token,
                           master_host=request.host_url)


@my_api_key.route("/reset_api_key", methods=["POST"])
@login_required
def reset_key():
    user = request.form.get("user", None)
    if user is not None:
        invalidate_user_key = delete(config.Config.FLASK_ENDPOINT + '/api/user/api_key',
                                     headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                                     data={"user": user},
                                     verify=False)
        logger.info(str(request) + ": invalidate_user_key: Status: " + str(invalidate_user_key.status_code))
        logger.debug("invalidate_user_key: Content: " + str(invalidate_user_key._content))

        if invalidate_user_key.status_code == 200:
            session.pop("api_key", None)
            return redirect("/my_api_key")
        else:
            logger.error("Error while trying to reset Trace: " + str(invalidate_user_key))
            return redirect("/my_api_key")

    else:
        return redirect("/my_api_key")