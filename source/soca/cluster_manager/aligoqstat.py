import subprocess
import argparse
import getpass
import json
import subprocess
import sys
from ast import literal_eval
from datetime import datetime

from prettytable import PrettyTable


def run_command(cmd):
    try:
        command = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, stderr = command.communicate()
        return literal_eval(stdout.decode('utf-8')) # clear possible escape char
    except subprocess.CalledProcessError as e:
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user', nargs='?', help='Retrieve jobs for a specific user')
    parser.add_argument('-q', '--queue', nargs='?', help='Retrieve all jobs behind a specific queue')
    parser.add_argument('-j', '--job', nargs='?', help='Specific job id')
    parser.add_argument('-s', '--state', nargs='?', help='Retrieve jobs using specific state')
    parser.add_argument('-w', '--wide', action='store_const', const=True, help='Display all exec host')
    parser.add_argument('-d', '--desktop', action='store_const', const=True, help='Display Graphical sessions')
    parser.add_argument('-f', '--format', nargs='?', help='json format')
    arg = parser.parse_args()
    table_output = PrettyTable(['Job ID', 'Queue', 'Owner', 'Job State', 'Exec hosts', 'Job Name','NDS', 'TSK', 'Start Time','Submit Time'])
    qstat_output = run_command('/opt/pbs/bin/qstat -f -F json')
    desktop_queue = ['desktop']
    job_id_order = []
    output = []
    dict_output = {}
    job_order = 0
    if not 'Jobs' in qstat_output.keys():
        print('INFO: No jobs detected.')
        sys.exit(0)

    for job, job_data in qstat_output['Jobs'].items():
        try:
            ignore = False
            job_id = job.split('.')[0]
            job_owner = job_data['Job_Owner'].split('@')[0]
            job_queue = job_data['queue']
            job_state = job_data['job_state']

            if arg.user == None:
                if job_owner != getpass.getuser():
                    # When arg.user is specify, ignore all job which don't match the requested user owner
                    ignore = True
                else:
                    # If job belongs to user, ignore only if desktop GUI and --desktop is not set
                    if arg.desktop is None:
                        if job_queue in desktop_queue:
                            ignore = True
            else:
                if arg.user == 'all':
                    pass
                else:
                    if job_owner != arg.user:
                        # When arg.user is specify, ignore all job which don't match the requested user owner
                        ignore = True

            if arg.queue is not None:
                if arg.queue != job_queue:
                    ignore = True

            if arg.state is not None:
                if (arg.state).lower() != job_state.lower():
                    ignore = True

            if arg.job is not None:
                if (arg.job) != job_id:
                    ignore = True

            if 'exec_vnode' in job_data.keys():
                if arg.wide is True:
                    exec_vnode = job_data['exec_vnode']
                else:
                    exec_vnode = job_data['exec_vnode'].split('+')[0]
            else:
                exec_vnode = '-'

            if job_state.lower() != 'r':
                stime = '-'
                stime_epoch = '-'
            else:
                stime = job_data['stime']
                stime_epoch = (datetime.strptime(stime, '%a %b %d %H:%M:%S %Y')).strftime('%s')

            if ignore is False:
                job_id_order.append(job_id)
                job_order += 1
                dict_output[job_id] = {
                            'get_job_id': job_id,
                            'get_job_queue_name': job_queue,
                            'get_job_owner': job_owner,
                            'get_job_state': job_state,
                            'get_execution_hosts': exec_vnode,
                            'get_job_name': job_data['Job_Name'],
                            'get_job_nodect': job_data['Resource_List']['nodect'],
                            'get_job_ncpus': job_data['Resource_List']['ncpus'],
                            'get_job_start_time': stime,
                            'get_job_start_time_epoch': stime_epoch,
                            'get_job_queue_time': job_data['qtime'],
                            'get_job_queue_time_epoch': (datetime.strptime(job_data['qtime'], '%a %b %d %H:%M:%S %Y')).strftime('%s'),
                            'get_job_project': job_data['project'],
                            'get_job_submission_directory': job_data['Variable_List']['PBS_O_WORKDIR'],
                            'get_job_resource_list': job_data['Resource_List'],
                            'get_job_order_in_queue': job_order
                        }
        except Exception as err:
            #print(err)
            pass
    if arg.format == 'json':
        table_output = dict_output
        print(json.dumps(table_output))
    else:
        if len(dict_output) == 0:
            print('INFO: No jobs detected.')
        else:
            for id in job_id_order:
                table_output.add_row([dict_output[id]['get_job_id'],
                                      dict_output[id]['get_job_queue_name'],
                                      dict_output[id]['get_job_owner'],
                                      dict_output[id]['get_job_state'],
                                      dict_output[id]['get_execution_hosts'],
                                      dict_output[id]['get_job_name'],
                                      dict_output[id]['get_job_nodect'],
                                      dict_output[id]['get_job_ncpus'],
                                      dict_output[id]['get_job_start_time'],
                                      dict_output[id]['get_job_queue_time']])
            print(table_output)

