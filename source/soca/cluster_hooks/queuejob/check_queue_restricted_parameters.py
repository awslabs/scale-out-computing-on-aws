'''
This hook reject the job if the user is not allowed to use the queue
Doc:
> https://awslabs.github.io/scale-out-computing-on-aws/tutorials/manage-queue-restricted-parameters/

create hook check_queue_restricted_parameters event=queuejob
import hook check_queue_restricted_parameters application/x-python default /apps/soca/%SOCA_CONFIGURATION/cluster_hooks/queuejob/check_queue_restricted_parameters.py

Note: If you make any change to this file, you MUST re-execute the import command.
If you are installing this file manually, make sure to replace %SOCA_CONFIGURATION path below
'''

import sys
import pbs
if "/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.7/site-packages" not in sys.path:
    sys.path.append("/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.7/site-packages")
import yaml


e = pbs.event()
j = e.job
job_owner = str(e.requestor)
job_queue = "normal" if str(j.queue) == "" else str(j.queue)
pbs.logmsg(pbs.LOG_DEBUG, 'queue_acl: job_queue  ' + str(job_queue))

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
            if 'restricted_parameters' not in v.keys():
                e.reject("restricted_parameters is not specified on " + queue_settings_file + ". See https://awslabs.github.io/scale-out-computing-on-aws/tutorials/manage-queue-restricted-parameters/ for examples")

            if isinstance(v['restricted_parameters'], list) is not True:
                e.reject("restricted_parameters (" + queue_settings_file + ") must be a list. Detected: " + str(type(v['restricted_parameters'])))

            restricted_parameters = v['restricted_parameters']
            # Ensure restricted resources configure by cluster admins can't be replaced by users
            for resource_requested in j.Resource_List.keys():
                if resource_requested in restricted_parameters:
                    message = resource_requested + " is a restricted parameter and can't be configure by the user. Contact your HPC admin and update " + queue_settings_file
                    e.reject(message)

