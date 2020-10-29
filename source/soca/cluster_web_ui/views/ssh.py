import logging
from decorators import login_required
import config
import subprocess
import datetime
from flask import send_file, render_template, Blueprint, session, redirect, request, flash
import read_secretmanager
import os
logger = logging.getLogger("application")

ssh = Blueprint('ssh', __name__, template_folder='templates')

@ssh.route('/ssh', methods=['GET'])
@login_required
def home():
    scheduler_ip = read_secretmanager.get_soca_configuration()['SchedulerPublicIP']
    return render_template('ssh.html', user=session["user"], scheduler_ip=scheduler_ip, timestamp=datetime.datetime.utcnow().strftime("%s"))


@ssh.route('/ssh/get_key', methods=['GET'])
@login_required
def get_key():
    type = request.args.get("type", None)
    ts = request.args.get("ts", None)

    if ts is None:
        return redirect("/ssh")

    if type is None or type not in ["pem", "ppk"]:
        return redirect("/ssh")

    user = session['user']
    user_private_key_path = config.Config.USER_HOME + "/" + user + "/.ssh/id_rsa"
    if type == "pem":
        return send_file(user_private_key_path,
                         as_attachment=True,
                         attachment_filename=user + '_soca_privatekey.pem')
    else:
        user_private_key_path_ppk = '/apps/soca/' + read_secretmanager.get_soca_configuration()['ClusterId'] + '/cluster_web_ui/' + config.Config.SSH_PRIVATE_KEY_LOCATION + '/' + user + '_soca_privatekey.ppk'
        generate_ppk = ['/apps/soca/' + read_secretmanager.get_soca_configuration()['ClusterId'] + '/cluster_web_ui/unix/puttygen', user_private_key_path,
                        '-o',
                        user_private_key_path_ppk]

        create_zip = subprocess.call(generate_ppk)
        if int(create_zip) != 0:
            flash("Unable to create the download archive, please try again", "error")
            logger.error("Unable to create zip. " + str(generate_ppk) + " : " + str(create_zip))
            return redirect("/ssh")

        if os.path.exists(user_private_key_path_ppk):
            return send_file(user_private_key_path_ppk,
                             as_attachment=True,
                             attachment_filename=user + '_soca_privatekey.ppk')
        else:
            flash("Unable to locate  the download archive, please try again", "error")
            logger.error("Unable to locate zip. " + str(generate_ppk) + " : " + str(create_zip))
            return redirect("/ssh")




