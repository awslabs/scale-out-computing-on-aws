import logging
import config
from flask import render_template, Blueprint, request, redirect, session, flash, Response
from requests import post, get, delete
from decorators import login_required
import boto3
from models import db, DCVSessions
import uuid
import random
import string
import base64
import datetime
import read_secretmanager
import re

logger = logging.getLogger("api_log")
remote_desktop = Blueprint('remote_desktop', __name__, template_folder='templates')
client = boto3.client('ec2')

@remote_desktop.route('/remote_desktop', methods=['GET'])
@login_required
def index():
    user_sessions = {}
    for session_info in DCVSessions.query.filter_by(user=session["user"], is_active=True).all():
        session_number = session_info.session_number
        session_state = session_info.session_state
        session_password = session_info.session_password
        session_uuid = session_info.session_uuid
        session_name = session_info.session_name
        job_id = session_info.job_id

        get_job_info = get(config.Config.FLASK_ENDPOINT + "/api/scheduler/job",
                           headers={"X-SOCA-USER": session["user"],
                                    "X-SOCA-TOKEN": session["api_key"]},
                           params={"job_id": job_id},
                           verify=False)

        check_session = DCVSessions.query.filter_by(job_id=job_id).all()
        if len(check_session) > 1:
            flash("More than 1 entry on the DB was found for this job ("+job_id+"). Most likely this is because this db was copied from a different cluster. Please remove the entry for the DB first")
            return redirect("/remote_desktop")
        else:
            for job_info in check_session:
                if get_job_info.status_code == 200:
                    # Job in queue, edit only if state is running
                    job_state = get_job_info.json()["message"]["job_state"]
                    if job_state == "R" and job_info.session_state != "running":
                        exec_host = (get_job_info.json()["message"]["exec_host"]).split("/")[0]
                        job_info.session_host = exec_host
                        job_info.session_state = "running"
                        db.session.commit()

                elif get_job_info.status_code == 210:
                    # Job is no longer in the queue
                    job_info.is_active = False
                    job_info.deactivated_on = datetime.datetime.utcnow()
                    db.session.commit()
                else:
                    flash("Unknown error for session " + str(session_number) + " assigned to job " + str(job_id) + " with error " + str(get_job_info.text), "error")

            user_sessions[session_number] = {
                "url": 'https://' + read_secretmanager.get_soca_configuration()['LoadBalancerDNSName'] + '/' + job_info.session_host + '/?authToken=' + session_password + '#' + session_uuid ,
                "session_state": session_state,
                "session_name": session_name}

    max_number_of_sessions = config.Config.DCV_MAX_SESSION_COUNT
    # List of instances not available for DCV. Adjust as needed
    blacklist = ['metal', 'nano', 'micro']
    all_instances_available = client._service_model.shape_for('InstanceType').enum
    all_instances = [p for p in all_instances_available if not any(substr in p for substr in blacklist)]
    return render_template('remote_desktop.html',
                           user=session["user"],
                           user_sessions=user_sessions,
                           terminate_idle_session=config.Config.DCV_TERMINATE_IDLE_SESSION,
                           page='remote_desktop',
                           all_instances=all_instances,
                           max_number_of_sessions=max_number_of_sessions)


@remote_desktop.route('/remote_desktop/create', methods=['POST'])
@login_required
def create():
    parameters = {}
    for parameter in ["walltime", "instance_type", "session_number", "instance_ami", "base_os", "scratch_size", "session_name"]:
        if not request.form[parameter]:
            parameters[parameter] = False
        else:
            parameters[parameter] = request.form[parameter]

    session_uuid = str(uuid.uuid4())
    session_password = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(80))
    command_dcv_create_session = "create-session --owner " + session["user"] + " " + session_uuid

    # sanitize session_name, limit to 255 chars
    if parameters["session_name"] is False:
        session_name = 'Desktop' + str(parameters["session_number"])
    else:
        session_name = re.sub(r'\W+', '', parameters["session_name"])[:255]
        if session_name == "":
            # handle case when session name specified by user only contains invalid char
            session_name = 'Desktop' + str(parameters["session_number"])

    params = {'pbs_job_name': session_name,
              'pbs_queue': 'desktop',
              'pbs_project': 'remotedesktop',
              'instance_type': parameters["instance_type"],
              'instance_ami': "#PBS -l instance_ami=" + parameters["instance_ami"] if parameters["instance_ami"] is not False else "",
              'base_os': "#PBS -l base_os=" + parameters["base_os"] if parameters["base_os"] is not False else "",
              'scratch_size': "#PBS -l scratch_size=" + parameters["scratch_size"] if parameters["scratch_size"] is not False else "",
              'session_password': session_password,
              'session_password_b64': (base64.b64encode(session_password.encode('utf-8'))).decode('utf-8'),
              'walltime': parameters["walltime"],
              'terminate_idle_session': str(config.Config.DCV_TERMINATE_IDLE_SESSION)}

    job_to_submit = '''#!/bin/bash
#PBS -N ''' + params['pbs_job_name'] + '''
#PBS -q ''' + params['pbs_queue'] + '''
#PBS -P ''' + params['pbs_project'] + '''
#PBS -l walltime=''' + params['walltime'] + '''
#PBS -l instance_type=''' + params['instance_type'] + '''
''' + params['instance_ami'] + '''
''' + params['base_os'] + '''
''' + params['scratch_size'] + '''

cd $PBS_O_WORKDIR

# Create the DCV Session
DCV="/bin/dcv"
echo "DCV detected $DCV" >> dcv.log 2>&1
$DCV ''' + command_dcv_create_session + ''' >> dcv.log 2>&1
    
# Query dcvsimpleauth with add-user
echo "''' + params['session_password_b64'] + '''" | base64 --decode | ''' + config.Config.DCV_SIMPLE_AUTH + ''' add-user --user ''' + session["user"] + ''' --session ''' + session_uuid + ''' --auth-dir ''' + config.Config.DCV_AUTH_DIR + ''' >> dcv.log 2>&1

# Uncomment if you want to disable Gnome Lock Screen (require webui restart)
# GSETTINGS=$(which gsettings)
# $GSETTINGS set org.gnome.desktop.lockdown disable-lock-screen true
# $GSETTINGS set org.gnome.desktop.session idle-delay 0

# Keep job open
while true
    echo "===============================" >> dcv.log 2>&1
    terminate_idle_session=''' + params["terminate_idle_session"] + '''
    echo "terminate_idle_session: $terminate_idle_session" >> dcv.log 2>&1
    do
        session_keepalive=$($DCV list-sessions | grep ''' + session_uuid + ''' | wc -l)
        if [[ $session_keepalive -ne 1 ]];
            then
                exit 0
        else
            if [[ $terminate_idle_session -ne 0 ]];
                then
                    now=$(date "+%s")
                    terminate_idle_session_in_seconds=$(( terminate_idle_session * 3600 ))
                    dcv_create_time=$(dcv describe-session ''' + session_uuid + ''' -j | grep -oP '"creation-time" : "(.*)"' | awk '{print $3}' | tr -d '"')
                    dcv_create_time_epoch=$(date -d "$dcv_create_time" +"%s")
                    dcv_last_disconnect_datetime=$(dcv describe-session ''' + session_uuid + ''' -j | grep -oP '"last-disconnection-time" : "(.*)"' | awk '{print $3}' | tr -d '"')
                    dcv_last_disconnect_epoch=$(date -d "$dcv_last_disconnect_datetime" +"%s")
                    if [[ -z "$dcv_last_disconnect_datetime" ]];
                        then
                        # No previous connection detected, default to create_time
                        echo "Session has not been used yet ..." >> dcv.log 2>&1
                        disconnect_session_after=$(( dcv_create_time_epoch + terminate_idle_session_in_seconds ))
                    else
                        disconnect_session_after=$(( dcv_last_disconnect_epoch + terminate_idle_session_in_seconds ))
                    fi
                    
                    echo "dcv_create_time: $dcv_create_time" >> dcv.log 2>&1
                    echo "dcv_create_time_epoch: $dcv_create_time_epoch" >> dcv.log 2>&1
                    echo "dcv_last_disconnect_datetime: $dcv_last_disconnect_datetime" >> dcv.log 2>&1
                    echo "dcv_last_disconnect_epoch: $dcv_last_disconnect_epoch" >> dcv.log 2>&1
                    echo "terminate_idle_session_in_seconds: $terminate_idle_session_in_seconds" >> dcv.log 2>&1
                    echo "disconnect_session_after: $disconnect_session_after" >> dcv.log 2>&1
                    echo "now: $now"  >> dcv.log 2>&1
                    
                    if [[ $disconnect_session_after < $now ]];
                       then
                           echo "session was inactive for too long, terminate session ..." >> dcv.log 2>&1
                           exit 0
                    fi
            fi
            sleep 1200  
        fi
done
    '''

    payload = base64.b64encode(job_to_submit.encode()).decode()
    send_to_to_queue = post(config.Config.FLASK_ENDPOINT + "/api/scheduler/job",
                            headers={"X-SOCA-TOKEN": session["api_key"],
                                     "X-SOCA-USER": session["user"]},
                            data={"payload": payload, },
                            verify=False)

    if send_to_to_queue.status_code == 200:
        job_id = str(send_to_to_queue.json()["message"])
        flash("Your session has been initiated (job number " + job_id + "). It will be ready within 20 minutes.", "success")
        new_session = DCVSessions(user=session["user"],
                                  job_id=job_id,
                                  session_number=parameters["session_number"],
                                  session_name=session_name,
                                  session_state="pending",
                                  session_host=False,
                                  session_password=session_password,
                                  session_uuid=session_uuid,
                                  is_active=True,
                                  created_on=datetime.datetime.utcnow())
        db.session.add(new_session)
        db.session.commit()
    else:
        flash("Error during job submission: " + str(send_to_to_queue.json()["message"]), "error")
    return redirect("/remote_desktop")


@remote_desktop.route('/remote_desktop/delete', methods=['GET'])
@login_required
def delete_job():
    dcv_session = request.args.get("session", None)
    if dcv_session is None:
        flash("Invalid DCV sessions", "error")
        return redirect("/remote_desktop")

    check_session = DCVSessions.query.filter_by(user=session["user"],
                                                session_number=dcv_session,
                                                is_active=True).first()
    if check_session:
        job_id = check_session.job_id
        delete_job = delete(config.Config.FLASK_ENDPOINT + "/api/scheduler/job",
                            headers={"X-SOCA-TOKEN": session["api_key"],
                                     "X-SOCA-USER": session["user"]},
                            params={"job_id": job_id},
                            verify=False)
        if delete_job.status_code == 200:
            check_session.is_active = False
            db.session.commit()
            flash("DCV session is about to be terminated. Job may still be visible in the queue for a couple of minutes before being completely removed.", "success")
        else:
            flash("Unable to delete associated job id (" +str(job_id) + "). " + str(delete_job.json()["message"]), "error")
    else:
        flash("Unable to retrieve this session", "error")

    return redirect("/remote_desktop")


@remote_desktop.route('/remote_desktop/client', methods=['GET'])
@login_required
def generate_client():
    dcv_session = request.args.get("session", None)
    if dcv_session is None:
        flash("Invalid DCV sessions", "error")
        return redirect("/remote_desktop")

    check_session = DCVSessions.query.filter_by(user=session["user"], session_number=dcv_session, is_active=True).first()
    if check_session:
        session_file = '''
[version]
format=1.0

[connect]
host=''' + read_secretmanager.get_soca_configuration()['LoadBalancerDNSName'] + '''
port=443
weburlpath=/''' + check_session.session_host + '''
sessionid=''' + check_session.session_uuid + '''
user=''' + session["user"] + '''
authToken=''' + check_session.session_password + '''
'''
        return Response(
            session_file,
            mimetype='text/txt',
            headers={'Content-disposition': 'attachment; filename=' + session['user'] + '_soca_' + str(dcv_session) + '.dcv'})

    else:
        flash("Unable to retrieve this session. This session may have been terminated.", "error")
        return redirect("/remote_desktop")

