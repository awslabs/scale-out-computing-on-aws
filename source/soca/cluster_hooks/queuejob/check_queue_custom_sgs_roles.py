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
This hook reject the job if the user specify invalid security group or IAM roles
Doc:
> https://awslabs.github.io/scale-out-computing-on-aws/security/use-custom-sgs-roles/

create hook check_queue_custom_sgs_roles event=queuejob
import hook check_queue_custom_sgs_roles application/x-python default /apps/soca/%SOCA_CONFIGURATION/cluster_hooks/queuejob/check_queue_custom_sgs_roles.py

Note: If you make any change to this file, you MUST re-execute the import command.
If you are installing this file manually, make sure to replace %SOCA_CONFIGURATION path below
"""

import sys
import pbs

if (
    "/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.9/site-packages"
    not in sys.path
):
    sys.path.append(
        "/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.9/site-packages"
    )
import yaml


e = pbs.event()
j = e.job
job_owner = str(e.requestor)
job_queue = "normal" if str(j.queue) == "" else str(j.queue)
pbs.logmsg(pbs.LOG_DEBUG, "check_queue_custom_sgs_roles: job_queue " + str(job_queue))

# Validate queue_mapping YAML is not malformed
try:
    queue_settings_file = (
        "/apps/soca/%SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml"
    )
    queue_reader = open(queue_settings_file, "r")
    docs = yaml.safe_load(queue_reader)
except Exception as err:
    message = (
        "Job cannot be submitted. Unable to read "
        + queue_settings_file
        + ". Double check the YAML syntax is correct and you don't have any invalid indent.\n Error: "
        + str(err)
    )
    e.reject(message)

security_groups = (
    j.Resource_List["security_groups"] if "security_groups" in j.Resource_List else None
)
instance_profile = (
    j.Resource_List["instance_profile"]
    if "instance_profile" in j.Resource_List
    else None
)

if instance_profile is None and security_groups is None:
    e.accept()
else:
    # Validate Queue IAM/SG permissions
    for doc in docs.values():
        for k, v in doc.items():
            queues = v["queues"]
            if job_queue in queues:
                try:
                    allowed_security_group_ids = list(v["allowed_security_group_ids"])
                    allowed_instance_profiles = list(v["allowed_instance_profiles"])
                except Exception as err:
                    e.reject(
                        "allowed_security_group_ids or allowed_instance_profiles is missing on "
                        + queue_settings_file
                        + " or are not valid Python lists"
                    )

                if security_groups is not None:
                    for sg_id in str(security_groups).split("+"):
                        if sg_id not in allowed_security_group_ids:
                            e.reject(
                                "Security group "
                                + sg_id
                                + " is not authorized for this queue. Please enable it on "
                                + queue_settings_file
                                + ". List of valid SG for this queue: "
                                + str(allowed_security_group_ids)
                            )

                if instance_profile is not None:
                    if str(instance_profile) not in allowed_instance_profiles:
                        e.reject(
                            "IAM instance profile "
                            + instance_profile
                            + " is not authorized for this queue. Please enable it on "
                            + queue_settings_file
                            + ". List of instance profiles for this queue: "
                            + str(allowed_instance_profiles)
                        )
