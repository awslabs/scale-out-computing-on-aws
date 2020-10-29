'''
This hook reject the job if the user is not allowed to use the queue
Doc:
> https://awslabs.github.io/scale-out-computing-on- aws/tutorials/manage-queue-instance-types/

create hook check_queue_instance_types event=queuejob
import hook check_queue_instance_types application/x-python default /apps/soca/%SOCA_CONFIGURATION/cluster_hooks/queuejob/check_queue_instance_types.py

Note: If you make any change to this file, you MUST re-execute the import command.
If you are installing this file manually, make sure to replace %SOCA_CONFIGURATION path below
'''

import sys
import pbs
if "/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.7/site-packages" not in sys.path:
    sys.path.append("/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.7/site-packages")
import yaml


def is_allowed_instance_type(instance_type, allowed_instance_types, excluded_instance_types):
    #A very basic sanity check on instance_type provided by user
    if '.' in instance_type:
        family = instance_type.split('.')[0]
    else:
        return False

    all_instances_allowed = True if len(allowed_instance_types) == 0 else False
    no_instances_excluded = True if len(excluded_instance_types) == 0 else False

    if all_instances_allowed and no_instances_excluded:
       return True

    #check if on exclude list
    for excluded_type in excluded_instance_types:
        if instance_type == excluded_type:
            return False
        elif '.' not in excluded_type and family == excluded_type:
            return False

    #check if on allowed list
    for allowed_type in allowed_instance_types:
        if instance_type == allowed_type:
            return True
        elif '.' not in allowed_type and family == allowed_type:
            return True

    #if all instances are allowed default to true otherwise false
    if all_instances_allowed:
        return True
    else:
        return False

      
e = pbs.event()
j = e.job
job_owner = str(e.requestor)
job_queue = "normal" if str(j.queue) == "" else str(j.queue)
pbs.logmsg(pbs.LOG_DEBUG, 'queue_acl: job_queue  ' + str(job_queue))
if 'instance_type' in j.Resource_List:
    instance_type = j.Resource_List['instance_type']
else:
    instance_type = None

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

            if 'allowed_instance_types' not in v.keys():
                e.reject("allowed_instance_types is not specified on " + queue_settings_file + ". See https://awslabs.github.io/scale-out-computing-on-aws/tutorials/manage-queue-instance-types/ for examples")

            if 'excluded_instance_types' not in v.keys():
                e.reject("excluded_instance_types is not specified on " + queue_settings_file + ". See https://awslabs.github.io/scale-out-computing-on-aws/tutorials/manage-queue-instance-types/ for examples")


            # ensure expected keys are valid lists
            if isinstance(v['allowed_instance_types'], list) is not True:
                e.reject("allowed_instance_types (" + queue_settings_file + ") must be a list. Detected: " + str(type(v['allowed_instance_types'])))
            if isinstance(v['excluded_instance_types'], list) is not True:
                e.reject("excluded_instance_types (" + queue_settings_file + ") must be a list. Detected: " + str(type(v['excluded_instance_types'])))

            allowed_instance_types = v['allowed_instance_types']
            excluded_instance_types = v['excluded_instance_types']

            if instance_type:
                 is_valid_instance = is_allowed_instance_type(instance_type, allowed_instance_types, excluded_instance_types)
            else:
                 #if no instance tpe in resource list default is used which is assumed to be valid.
                 is_valid_instance = True

            # first, make sure the instance_type selection is valid (if any)
            if not is_valid_instance:
                message = instance_type + " is not allowed for queue " + job_queue + ". Approved instance types/families are :" +','.join(allowed_instance_types) + " .Contact your HPC admin and update " + queue_settings_file
                e.reject(message)
