'''
This hook reject the job if the user is not allowed to use the queue
Doc:
> https://awslabs.github.io/scale-out-computing-on-aws/tutorials/manage-queue-acls/

create hook check_queue_acls event=queuejob
import hook check_queue_acls application/x-python default /apps/soca/%SOCA_CONFIGURATION/cluster_hooks/queuejob/check_queue_acls.py

Note: If you make any change to this file, you MUST re-execute the import command.
If you are installing this file manually, make sure to replace %SOCA_CONFIGURATION path below
'''

import os
import sys
import pbs
if "/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.7/site-packages" not in sys.path:
    sys.path.append("/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.7/site-packages")
import yaml


def find_users_in_ldap_group(group_dn):
    cmd = "ldapsearch -x -b " + group_dn + " -LLL | grep memberUid | awk '{print $2}'"
    users_in_group = os.popen(cmd).read()
    pbs.logmsg(pbs.LOG_DEBUG, 'queue_acl: find_users_in_ldap_group' + str(users_in_group))
    return list(filter(None, users_in_group.split('\n')))


e = pbs.event()
j = e.job
job_owner = str(e.requestor)
job_queue = "normal" if str(j.queue) == "" else str(j.queue)
pbs.logmsg(pbs.LOG_DEBUG, 'queue_acl: job_queue ' + str(job_queue))

# Validate queue_mapping YAML is not malformed
try:
    queue_settings_file = "/apps/soca/%SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml"
    queue_reader = open(queue_settings_file, "r")
    docs = yaml.safe_load(queue_reader)
except Exception as err:
    message = "Job cannot be submitted. Unable to read " + queue_settings_file + ". Double chek the YAML syntax is correct and you don't have any invalid indent.\n Error: " + str(err)
    e.reject(message)

# Validate Queue ACLs
for doc in docs.values():
    for k, v in doc.items():
        queues = v['queues']
        if job_queue in queues:
            allowed_users = []
            excluded_users = []

            if 'allowed_users' not in v.keys():
                e.reject("allowed_users is not specified on " + queue_settings_file + ". See https://awslabs.github.io/scale-out-computing-on-aws/tutorials/manage-queue-acls/ for examples")

            if 'excluded_users' not in v.keys():
                e.reject("excluded_users is not specified on " + queue_settings_file + ". See https://awslabs.github.io/scale-out-computing-on-aws/tutorials/manage-queue-acls/ for examples")

            # ensure expected keys are valid lists
            if isinstance(v['allowed_users'], list) is not True:
                e.reject("allowed_users (" + queue_settings_file + ") must be a list. Detected: " +str(type(v['allowed_users'])))
            if isinstance(v['excluded_users'], list) is not True:
                e.reject("excluded_users (" + queue_settings_file + ") must be a list. Detected: " + str(type(v['excluded_users'])))

            # Retrieve list of users that can submit job to the queue
            if 'allowed_users' in v.keys():
                for user in v['allowed_users']:
                    if "cn=" in user.lower():
                        allowed_users = allowed_users + find_users_in_ldap_group(user)
                    else:
                        allowed_users.append(user)
                #pbs.logmsg(pbs.LOG_DEBUG, 'queue_acl: allowed_users  ' + str(allowed_users))

            else:
                message = "allowed_users directive not detected on " + str(queue_settings_file)
                e.reject(message)

            # Retrieve list of users that cannot submit job to the queue
            if 'excluded_users' in v.keys():
                for user in v['excluded_users']:
                    if "cn=" in user.lower():
                        excluded_users = allowed_users + find_users_in_ldap_group(user)
                    else:
                        excluded_users.append(user)
                    #pbs.logmsg(pbs.LOG_DEBUG, 'queue_acl: excluded_users  ' + str(excluded_users))
            else:
                message = "excluded_users directive not detected on " + str(queue_settings_file)
                e.reject(message)

            # Then verify user is authorized to submit a job to the queue
            if excluded_users.__len__() == 0 and allowed_users.__len__() == 0:
                e.accept()
            else:
                if excluded_users[0] == "*" and job_owner not in allowed_users:
                    message = job_owner + " is not authorized to use submit this job on the queue " + job_queue + ". Contact your HPC admin and update " + queue_settings_file
                    e.reject(message)

                if job_owner in allowed_users:
                    e.accept()

                if job_owner in excluded_users:
                    message = job_owner + " is not authorized to use submit this job on the queue " + job_queue + ". Contact your HPC admin and update " + queue_settings_file
                    e.reject(message)

