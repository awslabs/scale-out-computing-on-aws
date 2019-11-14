import uuid
import base64
import subprocess
import argparse
import getpass
import os
import sys
sys.path.append(os.path.dirname(__file__))
import configuration


def run_command(cmd):
    try:
        command = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, stderr = command.communicate()
        return stdout
    except subprocess.CalledProcessError as e:
        exit(1)


def build_qsub(session_owner, session_password, queue,  walltime=False):
    session_id = str(uuid.uuid4())
    command_dcv_create = parameters['dcv_bin'] + " create-session " + session_id + "  --user=" + session_owner + ' --owner=' + session_owner
    params = {'pbs_job_name': 'Desktop',
              'pbs_queue': queue,
              'pbs_project': 'gui',
              'dcv_create_session': command_dcv_create,
              'session_password': session_password,
              'session_password_b64': base64.b64encode(session_password.encode('utf-8')).decode('utf-8') ,#py3
              'walltime': '999:99:99' if walltime is False else walltime}

    qsub_command = '''<<eof
#PBS -N ''' + params['pbs_job_name'] + '''
#PBS -q ''' + params['pbs_queue'] + '''
#PBS -P ''' + params['pbs_project'] + '''
#PBS -l walltime=''' + params['walltime'] + '''
#PBS -e /dev/null
#PBS -o /dev/null
# Create the DCV Session
''' + params['dcv_create_session'] + '''

# Query dcvsimpleauth with add-user
echo ''' + params['session_password_b64'] + ''' | base64 --decode | /usr/libexec/dcvsimpleextauth.py add-user --user ''' + session_owner + ''' --session ''' + session_id + ''' --auth-dir ''' + parameters['dcv_auth_dir'] + '''

# Disable Gnome Lock Screen 
# /usr/bin/gsettings set org.gnome.desktop.lockdown disable-lock-screen true

# Connection String
mkdir -p ~/.dcv/
HOSTNAME=`hostname -s`
echo "https://'''+parameters['alb_dns']+'''/$HOSTNAME/?authToken='''+params['session_password']+'''#'''+session_id+'''" >> ~/.dcv/"$PBS_JOBID".txt
# Keep job alive
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
    launch_job_session = run_command('/opt/pbs/bin/qsub ' + qsub_command).decode('utf-8')
    job_id = (launch_job_session.rstrip().lstrip()).split('.')[0]
    print('**** JOB ID: ' + str(job_id))
    print('**** HOW TO ACCESS YOUR SESSION')
    print('When your job is running, open ~/.dcv/'+str((launch_job_session.rstrip().lstrip()))+'.txt to get the connection string')


if __name__ == "__main__":
    aligo_configuration = configuration.get_aligo_configuration()
    parameters = {'dcv_bin': '/usr/bin/dcv',
                  'dcv_auth_dir': '/var/run/dcvsimpleextauth',
                  'alb_dns': aligo_configuration['LoadBalancerDNSName'],
                  '2d': 'desktop2d',
                  '3d': 'desktop3d'}
    parser = argparse.ArgumentParser()
    user = getpass.getuser()
    parser.add_argument('-p', '--password', nargs='?', required=True, help='DCV Session password')
    parser.add_argument('-w', '--walltime', nargs='?', help='Session walltime 00:00:00 format')
    arg = parser.parse_args()
    build_qsub(user,
               arg.password,
               'desktop2d')
