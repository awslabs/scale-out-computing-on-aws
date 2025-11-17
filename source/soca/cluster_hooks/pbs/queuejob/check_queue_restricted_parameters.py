######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

"""
This hook reject the job if the user is not allowed to use the queue
Doc:
> https://awslabs.github.io/scale-out-computing-on-aws-documentation/documentation/security/manage-queue-restricted-parameters/

create hook check_queue_restricted_parameters event=queuejob
import hook check_queue_restricted_parameters application/x-python default /opt/soca/%SOCA_CLUSTER_ID/cluster_hooks/pbs/queuejob/check_queue_restricted_parameters.py

Note: If you make any change to this file, you MUST re-execute the import command.
If you are installing this file manually, make sure to replace %SOCA_CLUSTER_ID path below
"""
import sys
import sysconfig

# Automatically add SOCA_PYTHON/site-packages to sys.path to allow OpenPBS Hooks to load any custom library installed via SOCA_PYTHON (boto3 ...)
site_packages = sysconfig.get_paths()["purelib"]
if site_packages not in sys.path:
    sys.path.append(site_packages)

import pbs
import yaml

e = pbs.event()
j = e.job
job_owner = str(e.requestor)
job_queue = "normal" if str(j.queue) == "" else str(j.queue)
pbs.logmsg(pbs.LOG_DEBUG, "queue_acl: job_queue  " + str(job_queue))
queue_settings_file = (
    "/opt/soca/%SOCA_CLUSTER_ID/cluster_manager/orchestrator/settings/queue_mapping.yml"
)

# Validate queue_mapping YAML is not malformed

try:
    with open(queue_settings_file) as f:
        docs = yaml.safe_load(f)

    # Validate Queue ACLs
    for doc in docs.values():
        for k, v in doc.items():
            queues = v["queues"]
            if job_queue in queues:
                if "restricted_parameters" not in v.keys():
                    e.reject(
                        f"restricted_parameters is not specified on {queue_settings_file}. See https://awslabs.github.io/scale-out-computing-on-aws-documentation/documentation/security/manage-queue-restricted-parameters/ for examples"
                    )

                if isinstance(v["restricted_parameters"], list) is not True:
                    e.reject(
                        f"restricted_parameters ({queue_settings_file}) must be a list. Detected: {str(type(v['restricted_parameters']))}"
                    )

                restricted_parameters = v["restricted_parameters"]
                # Ensure restricted resources configure by cluster admins can't be replaced by users
                for resource_requested in j.Resource_List.keys():
                    if resource_requested in restricted_parameters:
                        e.reject(
                            f"{resource_requested} is a restricted parameter and can't be configured by the user. Contact your SOCA admin and update {queue_settings_file}"
                        )

except Exception as err:
    e.reject(
        f"Job cannot be submitted. Unable to read {queue_settings_file}. Double check the YAML syntax is correct and you don't have any invalid indent.\n Error: {err}"
    )

except SystemExit:
    pass
