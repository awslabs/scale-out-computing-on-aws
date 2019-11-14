import boto3
import datetime
import collections
import os
import sys
import uuid
import string
import random
import base64
import yaml
import glob
import subprocess
import generic.parameters as parameters
import json
from pwd import getpwnam
from os import path
def run_command(cmd, type):
    try:
        if type == "check_output":
            command = subprocess.check_output(cmd)
        elif type == "call":
            command = subprocess.call(cmd)
        else:
            print("Command not Defined")
            exit(1)
        return command
    except subprocess.CalledProcessError as e:
        return ""

def build_dcv_connect_client(user, session_number):
    yaml_file = 'dcv_'+user+'_' + str(session_number) +'.yml'
    session_data = open_yaml(parameters.get_parameter('dcv', 'session_location')+'/'+yaml_file)
    session_file = '''
[version]
format=1.0
    
[connect]
host='''+parameters.get_aligo_configuration()['LoadBalancerDNSName']+'''
port=443
weburlpath=/'''+session_data['host']+'''
sessionid=''' + session_data['session_id']+'''
user=''' + user + '''
authToken='''+session_data['session_password']+'''
    '''
    return session_file


def build_qsub(session_owner, session_number, walltime, instance_type):
    session_id = str(uuid.uuid4())
    command_dcv_create = parameters.get_parameter('dcv', 'bin') + " create-session --user  " + session_owner + " --owner " + session_owner + " " + session_id
    session_password = ''.join(random.choice(string.ascii_uppercase + string.digits + string.ascii_lowercase) for _ in range(80))
    params = {'pbs_job_name': 'Desktop' + str(session_number),
              'pbs_queue': 'desktop',
              'pbs_project': 'gui',
              'instance_type': instance_type,
              'dcv_create_session': command_dcv_create,
              'session_password': session_password,
              'session_password_b64': (base64.b64encode(session_password.encode('utf-8'))).decode('utf-8'),
              'walltime': walltime}

    qsub_command = '''<<eof
#PBS -N ''' + params['pbs_job_name'] + '''
#PBS -q ''' + params['pbs_queue'] + '''
#PBS -P ''' + params['pbs_project'] + '''
#PBS -l walltime=''' + params['walltime'] + '''
#PBS -l instance_type=''' + params['instance_type'] + '''
#PBS -e /dev/null
#PBS -o /dev/null
# Create the DCV Session
''' + params['dcv_create_session'] + '''
            
# Query dcvsimpleauth with add-user
echo ''' + params['session_password_b64'] + ''' | base64 --decode | /usr/libexec/dcvsimpleextauth.py add-user --user ''' + session_owner + ''' --session ''' + session_id + ''' --auth-dir ''' + parameters.get_parameter('dcv', 'auth_dir') + '''

# Disable Gnome Lock Screen 
/usr/bin/gsettings set org.gnome.desktop.lockdown disable-lock-screen true
   
# Keep job open
while true
    do
        session_keepalive=`/usr/bin/dcv list-sessions | grep ''' + session_id + ''' | wc -l`
        if [ $session_keepalive -ne 1 ]
            then
                exit 0
        fi
        sleep 3600
    done
eof
'''
    yaml_config = parameters.get_parameter('dcv', 'session_location') + '/dcv_' + session_owner + '_' + str(session_number) + '.yml'
    if path.exists(yaml_config):
        print(yaml_config + ' already exist.')
        return False

    launch_job_session = run_command(['su', session_owner, '-c', '/opt/pbs/bin/qsub ' + qsub_command], "check_output")
    job_id = ((launch_job_session.decode('utf-8')).rstrip().lstrip()).split('.')[0]
    dcv_session_data = dict(
        job_id=job_id,
        host='tbd',
        state='pending',
        session_id=session_id,
        session_password=session_password,
        session_number=int(session_number)
    )

    with open(yaml_config, 'w') as outfile:
        yaml.dump(dcv_session_data, outfile, default_flow_style=False)

    os.chmod(yaml_config, 0o700)
    return True


def check_user_session(user):
    print('check_user_session')
    existing_sessions = {}
    for file_name in glob.glob(parameters.get_parameter('dcv', 'session_location')+'/*'):
        if user in file_name:
            ignore = False
            session_info = open_yaml(file_name)
            try:
                existing_sessions[int(session_info['session_number'])] = session_info
            except:
                print("No session number detected for " + str(file_name) + ". This may not be a DCV file")
                ignore = True
            if ignore is False:
                session_job_id = session_info['job_id']
                print(session_job_id + ' detected')
                try:
                    check_job_status = json.loads(run_command([parameters.get_parameter('pbs', 'qstat'), '-f', session_job_id, '-F', 'json'], 'check_output').decode('utf-8'))
                    for job, job_data in check_job_status['Jobs'].items():
                        if 'exec_host' in job_data.keys():
                            exec_host = job_data['exec_host'].split('/')[0]
                            update_yaml(file_name, exec_host)
                except Exception as e:
                    clean_session(user, session_info['session_number'])

    print(existing_sessions)
    return existing_sessions


def open_yaml(yaml_file):
    with open(yaml_file) as f:
        session_info = yaml.safe_load(f)
    return session_info


def update_yaml(yaml_file, exec_host):
    session_info = open_yaml(yaml_file)

    if session_info['host'] == 'tbd':
        session_info['host'] = exec_host
        session_info['state'] = 'running'
        session_info['yaml_file'] = yaml_file
        session_info['url'] =  'https://' + parameters.get_aligo_configuration()['LoadBalancerDNSName'] + '/' + exec_host + '/?authToken=' + session_info['session_password'] + '#' + session_info['session_id']

        with open(yaml_file, "w") as f:
            yaml.dump(session_info, f, default_flow_style=False)
        os.chmod(yaml_file, 0o700)


def demote(user):
    def set_ids():
        user_uid = getpwnam(user).pw_uid
        user_gid = getpwnam(user).pw_gid
        os.setgid(user_gid)
        os.setuid(user_uid)
    return set_ids


def clean_session(user, session_number):
    print('clean session')
    for file_name in glob.glob(parameters.get_parameter('dcv', 'session_location')+'/*'):
        if user in file_name:
            if str(session_number) in file_name:
                with open(file_name) as f:
                    session_info = yaml.safe_load(f)

                print('remove auth_dir/session_name on remote host and qdel job')
                commands = [ parameters.get_parameter('dcv', 'bin')+' close-session ' + session_info['session_id'],
                            'rm -rf ' + parameters.get_parameter('dcv', 'auth_dir') + '/' + session_info['session_id'],
                            parameters.get_parameter('pbs', 'qdel')+ ' ' + session_info['job_id']]

                proc = subprocess.Popen(["ssh " + session_info['host']],preexec_fn=demote(user),stdin=subprocess.PIPE, stdout=subprocess.PIPE,universal_newlines=True,bufsize=0,shell=True)
                proc.stdin.write('\n'.join(commands))
                proc.stdin.close()
                print('remove yaml')
                os.remove(file_name)
    return True
