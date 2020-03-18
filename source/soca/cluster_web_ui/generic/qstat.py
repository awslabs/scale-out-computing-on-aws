import ast
import collections
import os
import subprocess


def run_command(command):
    try:
        return subprocess.check_output(command.split())
    except subprocess.CalledProcessError as e:
        print("command '{}' return with error (code {}): {}".format(e.cmd, e.returncode, e.output))


def get_user_queue(username):
    qstat_aligo_cmd = '/apps/soca/' + os.environ["SOCA_CONFIGURATION"] + '/python/latest/bin/python3 unix/aligoqstat -w -f json -u ' + username
    try:
        qstat_output = ast.literal_eval(run_command(qstat_aligo_cmd).decode('utf-8'))
        qstat = {k: v for k, v in qstat_output.items() if
             v['get_job_owner'] == username}
    except:
        qstat = {}

    return collections.OrderedDict(sorted(qstat.items()))
