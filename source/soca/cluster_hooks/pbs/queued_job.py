# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
This hook reject the job if at least one check is failing:

create hook validate_job_submit event=queuejob
import hook validate_job_submit application/x-python default /opt/edh/<EDH_CLUSTER_ID>/cluster_hooks/pbs/queued_job.py

Note: If you make any change to this file, you MUST re-execute the import command.
"""
import sys
import sysconfig
import pbs
import traceback
import os


def pbs_logmsg(message: str, level=pbs.LOG_DEBUG, exit: bool = False):
    if not message:
        sys.exit("Missing message")
    pbs.logmsg(level, message)
    if exit is True:
        sys.exit(1)


# SOCA Python Env (utils etc) rely on env variables under /etc/environment
# We can't source it via pbs hook, so we need to parse and export it manually for the current session

pbs_logmsg(
    message="SOCA QueuedJob Hook Validator: Loading /etc/environment to source all required variables"
)

required_env_variables = ["EDH_CLUSTER_ID", "AWS_DEFAULT_REGION", "SOCA_DEBUG"]
try:
    with open("/etc/environment") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            key = key.replace("export", "").replace("EXPORT", "").strip()
            value = value.strip().strip('"').strip("'")
            if key in required_env_variables:
                pbs_logmsg(message=f"Setting up env variable: {key} -> {value}")
                os.environ[key] = value
except FileNotFoundError:
    pbs_logmsg(
        message=f"SOCA QueuedJob Hook Validator: Unable to load /etc/environment, exiting ...",
        exit=True,
    )
except Exception as err:
    pbs_logmsg(
        message=f"SOCA QueuedJob Hook Validator: Unable to load /etc/environment due to {err}, exiting ...",
        exit=True,
    )


pbs_logmsg(message=f"SOCA QueuedJob Hook Validator: Starting Hook")

# Automatically add SOCA_PYTHON/site-packages to sys.path to allow OpenPBS Hooks to load any custom library installed via SOCA_PYTHON (boto3 ...)
site_packages = sysconfig.get_paths().get("purelib", None)
if not site_packages:
    pbs_logmsg(
        message=f"SOCA QueuedJob Hook Validator:  Unable to find site-package for your python env",
        exit=True,
    )

if site_packages not in sys.path:
    sys.path.append(site_packages)

# Add SOCA environment to load SocaHpcHooksValidator
SOCA_CLUSTER_ID = os.environ.get("EDH_CLUSTER_ID", None)
if SOCA_CLUSTER_ID is None:
    pbs_logmsg(
        message=f"SOCA QueuedJob Hook Validator:  Unable to find EDH_CLUSTER_ID env variable",
        exit=True,
    )

if f"/opt/edh/{SOCA_CLUSTER_ID}/cluster_manager" not in sys.path:
    sys.path.append(f"/opt/edh/{SOCA_CLUSTER_ID}/cluster_manager")

#  Import SOCA Utils. Must be done after loading the environment
from utils.hpc.scheduler_hooks import SocaHpcHooksValidator
from utils.config import SocaConfig

_fetch_hook_list = SocaConfig(key="/configuration/HPC/hooks/").get_value()
if _fetch_hook_list.get("success") is False:
    pbs_logmsg(
        message=f"SOCA QueuedJob Hook Validator:  Unable to retrieve /configuration/HPC/hooks from SSM Parameter Store",
        exit=True,
    )

else:
    # raw_hook_list has full key name such as /configuration/HPC/hooks/check_budget
    # hook_list is a dict with key name such as check_budget
    raw_hook_list = _fetch_hook_list.get("message")
    hook_list = {
        key.removeprefix("/configuration/HPC/hooks/"): value
        for key, value in raw_hook_list.items()
    }

pbs_logmsg(message=f"Found Hook list on /configuration/HPC/hooks -> {hook_list}")

# Retrieve PBS event
e = pbs.event()
j = e.job
job_owner = str(e.requestor)
job_queue = "normal" if str(j.queue) == "" else str(j.queue)
job_project = None if j.project is None else str(j.project)
requested_resources = j.Resource_List.keys()

# Skip hook for system accounts
if job_owner in ["Scheduler", "PBS_Server", "pbs_mom"]:
    e.accept()

# note: Resource_Lists are pbs_resource, no dict. so don't use get()
if "instance_types" in requested_resources:
    job_instance_type = j.Resource_List["instance_types"] # newer and recommended
elif "instance_type" in requested_resources:
    job_instance_type = j.Resource_List["instance_type"]  # legacy
else:
    job_instance_type = None


job_security_groups = (
    j.Resource_List["security_groups"]
    if "security_groups" in requested_resources
    else None
)
job_instance_profile = (
    j.Resource_List["instance_profile"]
    if "instance_profile" in requested_resources
    else None
)

pbs_logmsg(
    message=f"SOCA QueuedJob Hook Validator: {job_owner} : {job_queue} with {hook_list}",
)

try:
    _hook = SocaHpcHooksValidator(
        job_owner=job_owner, job_queue=job_queue, job_project=job_project
    )

    # -- Validate Queue ACLs ---
    if hook_list.get("check_queue_acls", False):
        _validate_queue_acls = _hook.validate_queue_acls()
        if _validate_queue_acls.get("success") is False:
            e.reject(_validate_queue_acls.get("message"))

    # --- Validate Restricted Parameters ---
    if hook_list.get("check_restricted_parameters", False):
        _validate_restricted_parameters = _hook.validate_restricted_parameters(
            job_parameters=requested_resources
        )
        if _validate_restricted_parameters.get("success") is False:
            e.reject(_validate_restricted_parameters.get("message"))

    # --- Validate Budget associated to given projects ---
    if hook_list.get("check_budget", False):
        _validate_budget = _hook.validate_project_budget()
        if _validate_budget.get("success") is False:
            e.reject(_validate_budget.get("message"))

    # --- Validate Instance Type ---
    if (
        hook_list.get("check_instance_types", False) is True
        and job_instance_type is not None
    ):
        # Note: if instance_type is not specified at job submission, SOCA will use the default value specified on queue_settings.yml
        # Another round of validation via SocaHpcJob will be performed pre-capacity provisioning to validate instance type
        _validate_instance_types = _hook.validate_instance_types(
            instance_types=job_instance_type.split("+")
        )
        if _validate_instance_types.get("success") is False:
            e.reject(_validate_instance_types.get("message"))

    # --- Validate Custom Security Groups ---
    if (
        hook_list.get("check_custom_security_groups", False) is True
        and job_security_groups is not None
    ):
        _validate_custom_sgs_roles = _hook.validate_security_groups(
            security_groups=job_security_groups.split("+")
        )
        if _validate_custom_sgs_roles.get("success") is False:
            e.reject(_validate_custom_sgs_roles.get("message"))

    # -- Validate Custom IAM roles ----
    if (
        hook_list.get("check_custom_iam_instance_profile", False) is True
        and job_instance_profile is not None
    ):
        _validate_custom_iam_roles = _hook.validate_iam_instance_profile(
            instance_profile_name=job_instance_profile
        )
        if _validate_custom_iam_roles.get("success") is False:
            e.reject(_validate_custom_iam_roles.get("message"))

    # All validations passed
    e.accept()

except ValueError as err:
    tb = sys.exc_info()[2]
    line_no = tb.tb_lineno
    pbs_logmsg(message=f"SocaHpcHooksValidator ValueError {traceback.format_exc()}")
    # reject is what is being shown to the users
    e.reject(f"SocaHpcHooksValidator returned ValueError at line {line_no}: {err}")

except Exception as err:
    tb = sys.exc_info()[2]
    line_no = tb.tb_lineno
    pbs_logmsg(
        message=f"SocaHpcHooksValidator General Exception {traceback.format_exc()}",
    )
    # reject is what is being shown to the users
    e.reject(
        f"SocaHpcHooksValidator returned General Exception at line {line_no}: {err}"
    )
