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
This hook rejects the job if the user is not allowed to use the queue
Doc:
> https://awslabs.github.io/scale-out-computing-on-aws-documentation/documentation/security/manage-queue-acls/

create hook check_queue_acls event=queuejob
import hook check_queue_acls application/x-python default /opt/soca/%SOCA_CLUSTER_ID/cluster_hooks/pbs/queuejob/check_queue_acls.py

Note: If you make any change to this file, you MUST re-execute the import command.
If you are installing this file manually, make sure to replace %SOCA_CLUSTER_ID path below
"""

import sys
import sysconfig

# Automatically add SOCA_PYTHON/site-packages to sys.path to allow OpenPBS Hooks to load any custom library installed via SOCA_PYTHON (boto3 ...)
site_packages = sysconfig.get_paths()["purelib"]
if site_packages not in sys.path:
    sys.path.append(site_packages)

import os
import pbs
import yaml
import boto3
import ast
from typing import Optional

e = pbs.event()
j = e.job
job_owner = str(e.requestor)
job_queue = "normal" if str(j.queue) == "" else str(j.queue)


pbs.logmsg(pbs.LOG_DEBUG, f"check_queue_acls: owner: {job_owner} job_queue {job_queue}")


def read_environment_file(filename: Optional[str] = "/etc/environment") -> dict:
    """
    Read /etc/environment file and return a dict
    """
    pbs.logmsg(
        pbs.LOG_DEBUG, "check_queue_acls: read_etc_environment_file: reading env file"
    )

    try:
        with open(filename, "r") as _file:
            _environment = _file.read().split("\n")
            _environment_dict = {}
            for _line in _environment:
                if _line.startswith("#"):
                    continue
                if _line != "" and "=" in _line:
                    _line = _line.split("=")
                    _environment_dict[_line[0].replace("export ", "")] = _line[1]
                    pbs.logmsg(
                        pbs.LOG_DEBUG,
                        f"check_queue_acls: read_environment_file: Found an env: {_line[0]} => {_line[1]}",
                    )
            pbs.logmsg(
                pbs.LOG_DEBUG,
                f"check_queue_acls: read_environment_file: Total env: {_environment_dict}",
            )
            return _environment_dict
    except Exception as _err:
        pbs.logmsg(
            pbs.LOG_DEBUG, f"check_queue_acls: read_environment_file Exception: {_err}"
        )
        e.reject(
            f"check_queue_acls: Problem reading configuration. Please consult the HPC Administrator"
        )
        return {}


def get_secretsmanager_secret(secret_name: str) -> str:
    """
    Get a secret from Secrets Manager
    """
    pbs.logmsg(
        pbs.LOG_DEBUG,
        f"check_queue_acls: get_secretsmanager_secret: fetching from Secrets Manger {secret_name}",
    )

    try:
        _response = secrets_client.get_secret_value(SecretId=secret_name)
        return _response.get("SecretString", "")
    except Exception as _err:
        pbs.logmsg(
            pbs.LOG_DEBUG,
            f"check_queue_acls: get_secretsmanager_secret Exception: {_err}",
        )
        # We purposely don't reveal too much to the end-user here
        e.reject(
            f"check_queue_acls: Problem reading configuration. Please consult the HPC Administrator"
        )
        return ""


def find_users_in_ldap_group(group_dn: str) -> list:
    # Determine if we are in AD mode
    pbs.logmsg(pbs.LOG_DEBUG, "check_queue_acls: find_users_in_ldap_group: " + group_dn)

    # Query parameter store for our UserDirectory Provider
    _user_directory_provider: str = ""

    try:
        _ssm_result = ssm_client.get_parameter(
            Name=f"/soca/{cluster_id}/UserDirectoryProvider"
        )
        _user_directory_provider = _ssm_result.get("Parameter", {}).get("Value", "")
        pbs.logmsg(
            pbs.LOG_DEBUG,
            "check_queue_acls: find_users_in_ldap_group: UserDirectoryProvider: "
            + _user_directory_provider,
        )
    except Exception as _err:
        pbs.logmsg(
            pbs.LOG_DEBUG,
            "check_queue_acls: find_users_in_ldap_group: Unable to query UserDirectoryProvider",
        )
        e.reject(
            "check_queue_acls: Unable to query SSM. Please consult the HPC Administrator"
        )
        return []

    if _user_directory_provider in [
        "aws_ds_managed_activedirectory",
        "existing_active_directory",
    ]:
        pbs.logmsg(
            pbs.LOG_DEBUG,
            f"check_queue_acls: find_users_in_ldap_group: Detected Active Directory via UserDirectoryProvider {_user_directory_provider}",
        )

        _ad_bind_information: dict = ast.literal_eval(
            get_secretsmanager_secret(
                secret_name=f"/soca/{cluster_id}/UserDirectoryServiceAccount"
            )
        )

        ad_user: str = _ad_bind_information.get("username", "")
        ad_password: str = _ad_bind_information.get("password", "")
        ad_domain_name: str = ad_user.split("@")[1]

        pbs.logmsg(
            pbs.LOG_DEBUG,
            f"check_queue_acls: find_users_in_ldap_group: Domain: {ad_domain_name}  / ad_user: {ad_user}",
        )
        # Perform a nested AD group membership search
        ldapsearch = (
            "ldapsearch -x -h "
            + ad_domain_name
            + ' -D "'
            + ad_user
            + '" -w "'
            + ad_password
            + '" -b "'
            + group_dn
            + f"'(& (objectCategory=user)(memberOf:1.2.840.113556.1.4.1941:={group_dn}))'"
            + " \"sAMAccountName\" | grep ^sAMAccountName | awk '{print $2}'"
        )
        pbs.logmsg(
            pbs.LOG_DEBUG,
            "check_queue_acls: generated ldapsearch command: "
            + ldapsearch.replace(ad_password, "<REDACTED_PASSWORD>"),
        )
    else:
        # OpenLdap
        pbs.logmsg(
            pbs.LOG_DEBUG,
            "check_queue_acls: find_users_in_ldap_group: Detected OpenLDAP",
        )
        ldapsearch = (
            "ldapsearch -x -b " + group_dn + " -LLL | grep memberUid | awk '{print $2}'"
        )
        pbs.logmsg(
            pbs.LOG_DEBUG,
            "check_queue_acls: generated ldapsearch command: " + ldapsearch,
        )

    # Run the query and return the results as a list
    users_in_group = os.popen(ldapsearch).read()  # nosec
    pbs.logmsg(
        pbs.LOG_DEBUG,
        "check_queue_acls: find_users_in_ldap_group" + str(users_in_group),
    )
    return list(filter(None, users_in_group.split("\n")))


# Main entry point

local_env: dict = read_environment_file(filename="/etc/environment")

# These come from the /etc/environment vars but have to be read in manually
# as PBS doesn't pass environment
cluster_id: str = local_env.get("SOCA_CLUSTER_ID", "")
aws_region: str = local_env.get("AWS_DEFAULT_REGION", "")
soca_home: str = local_env.get("SOCA_HOME", f"/opt/soca/{cluster_id}")
queue_settings_file: str = (
    f"{soca_home}/cluster_manager/orchestrator/settings/queue_mapping.yml"
)

pbs.logmsg(
    pbs.LOG_DEBUG,
    f"check_queue_acl: PyYAML version: {yaml.__version__} ; {cluster_id=} ; {aws_region=} ; {soca_home=}",
)

# Required AWS clients
secrets_client = boto3.client("secretsmanager", region_name=aws_region)
ssm_client = boto3.client("ssm", region_name=aws_region)


try:
    with open(queue_settings_file) as f:
        docs = yaml.safe_load(f)

except SystemExit:
    pass

except Exception as err:
    message = (
        "Job cannot be submitted. Unable to read "
        + queue_settings_file
        + ". Check the YAML syntax. Error: "
        + str(err)
    )
    e.reject(message)

# Validate Queue ACLs

try:
    if job_owner in ["Scheduler", "PBS_Server", "pbs_mom"]:
        e.accept()

    for _queue_type_name in docs.values():
        for k, v in _queue_type_name.items():
            _queue_names: list = v.get("queues", [])
            pbs.logmsg(
                pbs.LOG_DEBUG,
                f"check_queue_acls: queues {_queue_names}",
            )

            if not isinstance(_queue_names, list):
                e.reject(
                    f"Configuration error. queues must be a list. Detected: {str(type(_queue_names))} in {_queue_type_name}"
                )

            if job_queue not in _queue_names:
                pbs.logmsg(
                    pbs.LOG_DEBUG,
                    f"check_queue_acls: job queue {job_queue} not found in {_queue_names} - skipping entry",
                )
                # Skip to the next entry
                continue

            # A dict containing the users we find
            _users_lookup: dict = {"allowed_users": [], "excluded_users": []}

            for _key in _users_lookup.keys():
                if _key not in v.keys():
                    e.reject(
                        f"The required key ({_key})"
                        + " is not specified in "
                        + queue_settings_file
                        + ". See https://awslabs.github.io/scale-out-computing-on-aws-documentation/documentation/security/manage-queue-acls/ for examples"
                    )

                if isinstance(v[_key], list) is not True:
                    e.reject(
                        f"{_key} must be of type (list). Detected: {str(type(v[_key]))}"
                    )

                # Our previous checks now get us to a known list
                for _user in v.get(_key, []):
                    if not isinstance(_user, str):
                        e.reject(
                            f"{_key} must be a list of strings. Detected: {str(type(_user))}"
                        )

                    if "cn=" in _user.lower():
                        _users_lookup[_key] += find_users_in_ldap_group(group_dn=_user)
                    else:
                        _users_lookup[_key].append(_user)

            # Now determine if the user is authorized to submit a job to this queue
            pbs.logmsg(
                pbs.LOG_DEBUG,
                f"check_queue_acls: Processing user auth - {job_owner=} . Allowed: {_users_lookup['allowed_users']} / Excluded: {_users_lookup['excluded_users']}",
            )

            if (
                len(_users_lookup.get("excluded_users", [])) == 0
                and len(_users_lookup.get("allowed_users", [])) == 0
            ):
                pbs.logmsg(
                    pbs.LOG_DEBUG,
                    f"check_queue_acls: no user restrictions detected for queue {job_queue} - allowing job",
                )
                e.accept()

            else:

                # Various checks of auth

                # 0. User is specified in both. This is a configuration error that is rejected
                if job_owner in _users_lookup.get(
                    "allowed_users", []
                ) and job_owner in _users_lookup.get("excluded_users", []):
                    pbs.logmsg(
                        pbs.LOG_DEBUG,
                        f"check_queue_acls: user {job_owner} is specified in both allowed_users and excluded_users for queue {job_queue} - rejecting job",
                    )
                    e.reject(
                        f"Configuration error. User {job_owner} is specified in both allowed_users and excluded_users for queue {job_queue}. Please update {queue_settings_file} and retry"
                    )

                # 1. Do we have a default-deny style queue where users must be explicitly allowed?
                if _users_lookup.get("excluded_users", [])[
                    0
                ] == "*" and job_owner not in _users_lookup.get("allowed_users", []):
                    pbs.logmsg(
                        pbs.LOG_DEBUG,
                        "check_queue_acls: user is not authorized (NOT in allowed_users with a default deny) - denying job",
                    )
                    message = (
                        job_owner
                        + " is not authorized to submit jobs to the queue "
                        + job_queue
                        + ". Contact your HPC admin and update "
                        + queue_settings_file
                    )
                    e.reject(message)

                # 2. Job_owner is in the allowed_user setting
                if job_owner in _users_lookup.get("allowed_users", []):
                    pbs.logmsg(
                        pbs.LOG_DEBUG,
                        "check_queue_acls: user is authorized (in allowed_users) - allowing job",
                    )
                    e.accept()

                # 3. Job_owner is in the excluded_users setting
                if job_owner in _users_lookup.get("excluded_users", []):
                    message = (
                        job_owner
                        + " is not authorized to use submit jobs to the queue "
                        + job_queue
                        + ". Contact your HPC admin and update "
                        + queue_settings_file
                    )
                    pbs.logmsg(
                        pbs.LOG_DEBUG,
                        "check_queue_acls: user is not authorized (in excluded_users) - denying job",
                    )
                    e.reject(message)

except SystemExit:
    pass

except Exception as err:
    message = (
        "Job cannot be submitted. Unable to read "
        + queue_settings_file
        + ". Double check the YAML syntax is correct and you don't have any invalid indent.\n Error: "
        + str(err)
    )
    e.reject(message)
