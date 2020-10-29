import logging
import config
from flask import render_template, Blueprint, request, redirect, session, flash
from requests import get, post, delete
from models import ApiKeys
from decorators import login_required, admin_only
import subprocess

logger = logging.getLogger("application")
admin_users = Blueprint('admin_users', __name__, template_folder='templates')



@admin_users.route('/admin/users', methods=['GET'])
@login_required
@admin_only
def index():
    get_all_users = get(config.Config.FLASK_ENDPOINT + "/api/ldap/users",
                        headers={"X-SOCA-TOKEN": session["api_key"],
                                 "X-SOCA-USER": session["user"]},
                        verify=False).json()

    all_users = get_all_users["message"].keys()
    try:
        get_all_shells = subprocess.check_output(["cat", "/etc/shells"])
        all_shells = get_all_shells.decode("utf-8").split("\n")[:-1] # remove last empty
    except Exception as err:
        logger.error("Unable to retrieve shells installed on the system")
        all_shells = ["/bin/bash"]
    return render_template('admin/users.html', user=session['user'], all_users=sorted(all_users), all_shells=all_shells)


@admin_users.route('/admin/manage_sudo', methods=['POST'])
@login_required
@admin_only
def manage_sudo():
    user = request.form.get('user', None)
    action = request.form.get('action', None)
    if user == session["user"]:
        flash("You can not manage your own Admin permissions.", "error")
        return redirect("/admin/users")

    if action in ["grant", "revoke"]:
        if user is not None:
            if action == "grant":
                give_sudo = post(config.Config.FLASK_ENDPOINT + "/api/ldap/sudo",
                                       headers={"X-SOCA-TOKEN": session["api_key"],
                                                "X-SOCA-USER": session["user"]},
                                       data={"user": user},
                                 verify=False
                                 )
                if give_sudo.status_code == 200:
                    flash("Admin permissions granted", "success")
                else:
                    flash("Error: " + give_sudo.json()["message"], "error")
                return redirect("/admin/users")

            else:
                # Revoke SUDO
                remove_sudo = delete(config.Config.FLASK_ENDPOINT + "/api/ldap/sudo",
                                 headers={"X-SOCA-TOKEN": session["api_key"],
                                          "X-SOCA-USER": session["user"]},
                                 data={"user": user},
                                     verify=False
                                     )
                if remove_sudo.status_code == 200:
                    flash("Admin permissions revoked", "success")
                else:
                    flash("Error: " + remove_sudo.json()["message"], "error")

                return redirect("/admin/users")

        else:
            return redirect("/admin/users")
    else:
        return redirect("/admin/users")


@admin_users.route('/admin/create_user', methods=['POST'])
@login_required
@admin_only
def create_new_account():
        user = str(request.form.get('user'))
        password = str(request.form.get('password'))
        email = str(request.form.get('email'))
        sudoers = request.form.get('sudo', None)
        shell = request.form.get('shell', '/bin/bash')
        uid = request.form.get('uid', None)  # 0 if not specified. Will automatically generate uid
        gid = request.form.get('gid', None)  # 0 if not specified. Will automatically generate gid
        create_new_user = post(config.Config.FLASK_ENDPOINT + "/api/ldap/user",
                               headers={"X-SOCA-TOKEN": session["api_key"],
                                        "X-SOCA-USER": session["user"]},
                               data={"user": user,
                                     "password": password,
                                     "email": email,
                                     "sudoers": 0 if sudoers is None else 1,
                                     "shell": shell,
                                     "uid": 0 if not uid else uid,
                                     "gid": 0 if not gid else gid},
                               verify=False
                               )
        if create_new_user.status_code == 200:
            # Create API key
            create_user_key = get(config.Config.FLASK_ENDPOINT + '/api/user/api_key',
                                  headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                                  params={"user": user},
                                  verify=False)
            if create_user_key.status_code == 200:
                if create_user_key.json()["success"] is False:
                    flash("User created but unable to generate API token: " + create_user_key.json()["message"], "error")
                else:
                    flash("User " + user + " has been created successfully", "success")
            else:
                flash("User created but unable to generate API token: " + str(create_user_key.text), "error")

            return redirect('/admin/users')
        else:
            flash("Unable to create new user. API returned error: " + str(create_new_user.text), "error")
            return redirect('/admin/users')


@admin_users.route('/admin/delete_user', methods=['POST'])
@login_required
@admin_only
def delete_account():
    user = str(request.form.get('user_to_delete'))
    if session['user'] == user:
        flash("You cannot delete your own account.", "error")
        return redirect('/admin/users')

    delete_user = delete(config.Config.FLASK_ENDPOINT + "/api/ldap/user",
                             headers={"X-SOCA-TOKEN": session["api_key"],
                                      "X-SOCA-USER": session["user"]},
                             data={"user": user},
                         verify=False
                         ).json()

    if delete_user["success"] is True:
        flash('User: ' + user + ' has been deleted correctly', "success")
    else:
        flash('Could not delete user: ' + user + '. Check trace: ' + str(delete_user), "error")

    return redirect('/admin/users')