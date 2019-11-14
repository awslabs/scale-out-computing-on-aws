from flask import Flask, render_template, session, redirect, request, flash
from flask_wtf.csrf import CSRFProtect
import datetime
import logging
import collections
import generic.parameters as parameters
from datetime import timedelta
from generic import auth, dcv, qstat
from api.get_ppk_key import get_ppk_key
from api.get_pem_key import get_pem_key
from api.dcv_management import dcv_management
import api.openldap as openldap
import boto3
import os

app = Flask(__name__)
csrf = CSRFProtect(app)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=1)
# Flask_secret_key is created by socawebui.sh
app.config['SECRET_KEY'] = os.environ['FLASK_SECRET_KEY']
app.config['SESSION_COOKIE_SECURE'] = True
app.register_blueprint(get_ppk_key)
app.register_blueprint(get_pem_key)
app.register_blueprint(dcv_management)
client = boto3.client('ec2')

def session_info():
    return {'username': session['username'].lower(),
            'sudoers': session['sudoers']
            }

@app.route('/', methods=['GET'])
@auth.login_required
def index():
    username = session_info()['username']
    sudoers = session_info()['sudoers']
    return render_template('index.html', username=username, sudoers=sudoers)


@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')


@app.route('/logout', methods=['GET'])
def logout():
    session.pop('username', None)
    return redirect('/')

@app.route('/auth', methods=['POST'])
def authenticate():
    username = request.form.get('username')
    password = request.form.get('password')
    if username is not None and password is not None:
        check_auth = openldap.validate_ldap(username.lower(), password)
        if check_auth['success'] is False:
            flash(check_auth['message'])
            return redirect('/login')
        else:
            return redirect('/')

    else:
        return redirect('/login')

@app.route('/remotedesktop', methods=['GET'])
@auth.login_required
def remotedesktop():
    username = session_info()['username']
    sudoers = session_info()['sudoers']
    user_sessions = dcv.check_user_session(username)
    max_number_of_sessions = parameters.authorized_dcv_session_count()
    # List of instances not available for DCV. Adjust as needed
    blacklist = ['t1', 't2', 'm1','m4', 'm5.large', 'c3', 'p2', 'p3', 'r3', 'r4', 'metal', 'nano', 'micro']
    all_instances_available = client._service_model.shape_for('InstanceType').enum
    all_instances = [p for p in all_instances_available if not any(substr in p for substr in blacklist)]
    return render_template('remotedesktop.html', user_sessions=user_sessions, username=username, view='remotedesktop',
                           all_instances=all_instances, max_number_of_sessions=max_number_of_sessions, sudoers=sudoers)

@app.route('/ssh', methods=['GET'])
@auth.login_required
def ssh():
    username = session_info()['username']
    sudoers = session_info()['sudoers']
    scheduler_ip = parameters.get_aligo_configuration()['SchedulerPublicIP']
    app.logger.warning(username + ' checking ssh')
    return render_template('ssh.html', username=username, scheduler_ip=scheduler_ip, sudoers=sudoers)


@app.route('/qstat', methods=['GET'])
@auth.login_required
def job_queue():
    username = session_info()['username']
    sudoers = session_info()['sudoers']
    jobs = qstat.get_user_queue(username)
    return render_template('qstat.html', username=username, jobs=jobs, view='qstat', sudoers=sudoers)

@app.route('/howto-job', methods=['GET'])
@auth.login_required
def howto_job():
    username = session_info()['username']
    sudoers = session_info()['sudoers']
    return render_template('howto_job.html', username=username, sudoers=sudoers)

@app.route('/howto-queue', methods=['GET'])
@auth.login_required
def howto_queue():
    username = session_info()['username']
    sudoers = session_info()['sudoers']
    return render_template('howto_queue.html', username=username, sudoers=sudoers)

@app.route('/budget', methods=['GET'])
@auth.login_required
def budget():
    username = session_info()['username']
    sudoers = session_info()['sudoers']
    return render_template('budget.html', username=username, sudoers=sudoers)

@app.route('/dashboard', methods=['GET'])
@auth.login_required
def dashboard():
    analytics_dashboard = parameters.get_aligo_configuration()['ESDomainEndpoint']
    username = session_info()['username']
    sudoers = session_info()['sudoers']
    analytics_url = 'https://' + analytics_dashboard + '/_plugin/kibana/'
    return render_template('dashboard.html', username=username, analytics_url=analytics_url, sudoers=sudoers)

@app.route('/sftp', methods=['GET'])
@auth.login_required
def sftp():
    username = session_info()['username']
    sudoers = session_info()['sudoers']
    scheduler_ip = parameters.get_aligo_configuration()['SchedulerPublicIP']
    return render_template('sftp.html', scheduler_ip=scheduler_ip, username=username, sudoers=sudoers)

@app.route('/users', methods=['GET'])
@auth.login_required
def users():
    username = session_info()['username']
    sudoers = session_info()['sudoers']
    all_users = openldap.get_all_users()
    return render_template('users.html', username=username, sudoers=sudoers, all_users=all_users)

@app.route('/create_new_account', methods=['POST'])
@auth.login_required
def create_new_account():
    if session_info()['sudoers'] is True:
        username = str(request.form.get('username'))
        password = str(request.form.get('password'))
        email = str(request.form.get('email'))
        sudoers = request.form.get('sudo')
        create_new_user = openldap.create_new_user(username, password, sudoers, email)
        if int(create_new_user['exit_code']) == 0:
            msg = {'success': True,
                   'message': 'User: ' + username + ' has been created correctly'}
        else:
            msg = {'success': False,
                   'message': 'Could not create user: ' + username + '. Check trace: ' + str(create_new_user)}

        flash(msg)
        return redirect('/users')

    else:
        return redirect('/')

@app.route('/delete_account', methods=['POST'])
@auth.login_required
def delete_account():
    if session_info()['sudoers'] is True:
        username = str(request.form.get('user_to_delete'))
        if session_info()['username'] == username:
            msg = {'success': False,
                   'message': 'You cannot delete your own account.'}
            flash(msg)
            return redirect('/users')

        delete_account = openldap.delete_user(username)
        if int(delete_account['exit_code']) == 0:
            msg = {'success': True,
                   'message': 'User: ' + username + ' has been deleted correctly'}
        else:
            msg = {'success': False,
                   'message': 'Could not delete user: ' + username + '. Check trace: ' + str(delete_account)}

        flash(msg)
        return redirect('/users')

    else:
        return redirect('/')

@app.route('/ping', methods=['GET'])
def check_alive():
    return 'Check Alive', 200


@app.errorhandler(404)
def page_not_found(e):
    return redirect('/')


if __name__ == '__main__':
    gunicorn_logger = logging.getLogger('gunicorn.error')
    app.logger.handlers = gunicorn_logger.handlers
    app.logger.setLevel(gunicorn_logger.level)
    app.run(debug=False, host='0.0.0.0', port=8443, ssl_context='adhoc')
