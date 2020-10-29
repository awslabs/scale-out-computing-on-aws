import logging
from flask import render_template, session, Blueprint
from decorators import login_required
import read_secretmanager
logger = logging.getLogger("application")
sftp = Blueprint('sftp', __name__, template_folder='templates')


@sftp.route('/sftp', methods=['GET'])
@login_required
def home():
    scheduler_ip = read_secretmanager.get_soca_configuration()['SchedulerPublicIP']
    return render_template('sftp.html',
                           scheduler_ip=scheduler_ip,
                           user=session["user"])
