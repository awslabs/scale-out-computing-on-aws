import logging
import config
from flask import render_template, Blueprint, request, redirect, session, flash
from requests import get, post, put
from decorators import login_required
import ast
import string
import random

logger = logging.getLogger("application")
my_account = Blueprint('my_account', __name__, template_folder='templates')


@my_account.route("/my_account", methods=["GET"])
@login_required
def index():
    get_user_ldap_group = get(config.Config.FLASK_ENDPOINT + "/api/ldap/group",
                               headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                               params={"group": session["user"]},
                              verify=False)

    get_user_ldap_users = get(config.Config.FLASK_ENDPOINT + "/api/ldap/users",
                              headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                              verify=False)

    if get_user_ldap_group.status_code == 200:
        group_members = get_user_ldap_group.json()["message"]["members"]
    else:
        group_members = ["No Member yet"]

    if get_user_ldap_users.status_code == 200:
        all_users = get_user_ldap_users.json()["message"].keys()
    else:
        all_users = []

    return render_template("my_account.html",
                           user=session["user"],
                           group_members=group_members,
                           all_users=all_users)


@my_account.route('/manage_group', methods=['POST'])
@login_required
def manage_group():
    group = session["user"]
    user = request.form.get('user')
    action = request.form.get('action')
    update_group = put(config.Config.FLASK_ENDPOINT + "/api/ldap/group",
                       headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                             data={"group": group,
                                   "user": user,
                                   "action": action},
                       verify=False)

    if update_group.status_code == 200:
        flash("Group update successfully", "success")
    else:
        flash('Unable to update group: ' + update_group.json()["message"], "error")

    return redirect('/my_account')

@my_account.route("/reset_password", methods=["POST"])
@login_required
def reset_key():
    password = request.form.get("password", None)
    password_verif = request.form.get("password_verif", None)
    admin_reset = request.form.get("admin_reset", None)
    if admin_reset == "yes":
        # Admin can generate a temp password on behalf of the user
        user = request.form.get("user", None)
        if user is None:
            return redirect("/admin/users")
        elif user == session["user"]:
            flash("You can not reset your own password using this tool. Please visit 'My Account' section for that", "error")
            return redirect("/admin/users")
        else:
            password = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(8))
            change_password = post(config.Config.FLASK_ENDPOINT + '/api/user/reset_password',
                                       headers={"X-SOCA-TOKEN": session["api_key"],
                                                "X-SOCA-USER": session["user"]},
                                       data={"user": user,
                                             "password": password},
                                       verify=False)
            if change_password.status_code == 200:
                flash("Password for " + user + " has been changed to " + password + "<hr> User is recommended to change it using 'My Account' section", "success")
                return redirect("/admin/users")
            else:
                flash("Unable to reset password. Error: " + str(change_password._content), "error")
                return redirect("/admin/users")
    else:
        if password is not None:
            # User can change their own password
            if password == password_verif:
                change_password = post(config.Config.FLASK_ENDPOINT + '/api/user/reset_password',
                                       headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY,
                                                "X-SOCA-USER": session["user"]},
                                       data={"user": session["user"],
                                             "password": password},
                                       verify=False)

                if change_password.status_code == 200:
                    flash("Your password has been changed succesfully.", "success")
                    return redirect("/my_account")
                else:
                    flash("Unable to reset your password. Error: " +str(change_password._content), "error")
                    return redirect("/my_account")
            else:
                flash("Password does not match", "error")
                return redirect("/my_account")
        else:
            return redirect("/my_account")