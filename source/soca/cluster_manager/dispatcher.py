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
SOCA DYNAMIC CLUSTER MANAGER
This script retrieve all queued jobs, calculate PBS resources required to launch each job
and provision EC2 capacity if all resources conditions are met.
"""
import argparse
import datetime
import fnmatch
import json
import logging
import os
import re
import subprocess
import sys
import socket
import boto3
import pytz
import yaml
from botocore.exceptions import ClientError

sys.path.append(os.path.dirname(__file__))
import configuration
import add_nodes


def run_command(cmd, cmd_type: str):
    try:
        if cmd_type == "check_output":
            command = subprocess.check_output(cmd)
        elif cmd_type == "call":
            command = subprocess.call(cmd)
        else:
            print("Command not Defined")
            exit(1)
        return command
    except subprocess.CalledProcessError as e:
        return ""


def get_lock(process_name):
    get_lock._lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    pid = os.getpid()
    try:
        get_lock._lock_socket.bind("\0" + process_name)
        # print(f'Obtained the lock {process_name} - PID {pid}')
        return True
    except socket.error:
        logpush(f"lock {process_name} exists. Exiting PID {pid}", "info")
        return str(pid)


def fair_share_job_id_order(sorted_queued_job, user_fair_share):
    """
        Generate the job order to provision based on fair share score

        example:
        sorted_queued_job = [
            {'get_job_id': 1, 'get_job_owner': 'mcrozes'},
            {'get_job_id': 2, 'get_job_owner': 'mcrozes'},
            {'get_job_id': 3, 'get_job_owner': 'mcrozes'},
            {'get_job_id': 4, 'get_job_owner': 'test'},
            {'get_job_id': 5, 'get_job_owner': 'test'},
        ]
        user_fair_share = {'mcrozes': 100,
                           'test': 50}

        Result:
        Next User is mcrozes
    Next User is test
    Next User is mcrozes
    Next User is test
    Next User is mcrozes
    Next User is test
    [1, 4, 2, 5, 3]

    """

    job_ids_to_start = []
    order = 0
    while order <= sorted_queued_job.__len__():
        sorted_user_fair_share = sorted(
            user_fair_share.items(), key=lambda kv: kv[1], reverse=True
        )
        logpush("Fair Share Score: " + str(sorted_user_fair_share))

        next_user = sorted_user_fair_share[0][0]
        logpush("Next User is " + next_user)

        next_user_jobs = [
            i["get_job_id"]
            for i in sorted_queued_job
            if i["get_job_owner"] == next_user
        ]
        logpush("Next Job for user is " + str(next_user_jobs))
        for job_id in next_user_jobs:
            if job_id in job_ids_to_start:
                if next_user_jobs.__len__() == 1:
                    # User don't have any more queued jobs
                    del user_fair_share[next_user]
            else:
                job_ids_to_start.append(job_id)
                user_fair_share[next_user] = (
                    user_fair_share[next_user] + fair_share_running_job_malus
                )
                break

        order += 1

    logpush("jobs id re-order based on fairshare: " + str(job_ids_to_start))
    return job_ids_to_start


def fair_share_score(queued_jobs, running_jobs, queue):
    user_score = {}
    now = int((datetime.datetime.now()).strftime("%s"))

    # First, apply malus for users who already have running job
    for r_job_data in running_jobs:
        if r_job_data["get_job_owner"] not in user_score.keys():
            user_score[r_job_data["get_job_owner"]] = (
                fair_share_start_score + fair_share_running_job_malus
            )
        else:
            user_score[r_job_data["get_job_owner"]] = (
                user_score[r_job_data["get_job_owner"]] + fair_share_running_job_malus
            )

    for q_job_data in queued_jobs:
        if "stack_id" in q_job_data["get_job_resource_list"].keys():
            # If job is queued and in the process of start (provision capacity), we apply the running job malus
            job_bonus_score = fair_share_running_job_malus

        else:
            # Begin FairShare Formula
            timestamp_submission = q_job_data["get_job_queue_time_epoch"]
            resource_name = q_job_data["get_job_resource_list"].keys()
            license = 0

            for license_name in fnmatch.filter(resource_name, "*_lic*"):
                logpush(
                    "Job use the following licenses:"
                    + str(license_name)
                    + " - "
                    + str(q_job_data["get_job_resource_list"][license_name])
                )
                license += int(q_job_data["get_job_resource_list"][license_name])

            required_resource = int(q_job_data["get_job_nodect"]) + license
            logpush("Job Required Resource Bonus " + str(required_resource))

            # Example dynamic bonus score
            # c1 = 0.5
            # c2 = 1.7
            # job_bonus_score = required_resource * (c1 * ((int(now) - int(timestamp_submission))/3600/24) ** c2)

            # Linear
            c1 = 1
            c2 = 0
            job_bonus_score = 1

            logpush(
                "Job "
                + str(q_job_data["get_job_id"])
                + " queued for "
                + str((int(now) - int(timestamp_submission)) / 60)
                + " minutes: bonus %.2f" % job_bonus_score
            )

            # END
        if q_job_data["get_job_owner"] not in user_score.keys():
            user_score[q_job_data["get_job_owner"]] = (
                fair_share_start_score + job_bonus_score
            )
        else:
            user_score[q_job_data["get_job_owner"]] = (
                user_score[q_job_data["get_job_owner"]] + job_bonus_score
            )

    # Remove user with no queued job
    for user, score in list(
        user_score.items()
    ):  # cast to list as we change the size of the dict on the fly w/ py3
        if [i["get_job_owner"] for i in queued_jobs if i["get_job_owner"] == user]:
            pass
        else:
            del user_score[user]

    return user_score


def logpush(message, status="info"):
    if status == "error":
        logger.error(message)
    else:
        logger.info(message)


def get_jobs_infos(queue):
    command = [
        system_cmds["python"],
        system_cmds["socaqstat"],
        "-f",
        "json",
        "-u",
        "all",
        "-q",
        queue,
    ]
    output = run_command(command, "check_output")
    try:
        sanitize_input = output.decode("utf-8")
        for match in re.findall(r'"project":(\d+),', sanitize_input, re.MULTILINE):
            # Clear case where project starts with digits to prevent leading zero errors
            print(
                f'Detected "project":{match}, > Will be replaced to prevent int leading zero error'
            )
            sanitize_input = sanitize_input.replace(
                f'"project":{match},', f'"project":"{match}",'
            )

        return json.loads(sanitize_input)
    except Exception as e:
        # no job
        return {}


def check_if_queue_started(queue_name):
    queue_start = run_command(
        [system_cmds["qmgr"], "-c", "print queue " + queue_name + " started"],
        "check_output",
    )
    queue_enabled = run_command(
        [system_cmds["qmgr"], "-c", "print queue " + queue_name + " enabled"],
        "check_output",
    )
    if "True" in str(queue_start) and "True" in str(queue_enabled):
        return True
    else:
        return False


# BEGIN FLEXLM FUNCTIONS
def check_available_licenses(commands, license_to_check):
    output = {}
    if commands.__len__() == 0:
        return {}

    for pbs_resource, flexlm_cmd in commands.items():
        if pbs_resource in license_to_check:
            try:
                available_licenses = run_command(flexlm_cmd.split(), "check_output")
                output[pbs_resource] = int(available_licenses.rstrip())
            except subprocess.CalledProcessError as e:
                logpush(
                    "command '{}' return with error (code {}): {}".format(
                        e.cmd, e.returncode, e.output
                    ),
                    "error",
                )
                exit(1)

    return output


# END FLEXLM FUNCTIONS


def clean_cloudformation_stack():
    pass
    # handle specific use case where
    # user submit job with SPOT instance
    # stack created, spot instance requested
    # spot instance can't be fulfilled
    # user delete job from the queue
    # stack will stay forever. Instead, we need to describe all stacks and delete them if they are assigned to a job that no longer exist


def capacity_being_provisioned(stack_id, job_id, job_select_resource, scaling_mode):
    # This function is only called if we detect a queued job with an already assigned Compute Node
    try:
        logpush("Checking existing cloudformation " + str(stack_id))
        check_stack_status = cloudformation.describe_stacks(StackName=stack_id)
        if check_stack_status["Stacks"][0]["StackStatus"] == "CREATE_COMPLETE":
            logpush(
                job_id
                + " is queued but CI has been specified and CloudFormation has been created."
            )
            if scaling_mode == "multiple_jobs":
                response = cloudformation.describe_stack_resources(StackName=stack_id)
                for resource in response["StackResources"]:
                    if resource["ResourceType"] == "AWS::EC2::SpotFleet":
                        spotfleet = resource["PhysicalResourceId"]
                        now = pytz.utc.localize(datetime.datetime.utcnow())
                        now_minus_ten_minutes = (
                            now - datetime.timedelta(minutes=10)
                        ).strftime("%Y-%m-%dT%H:%M:%SZ")
                        response = ec2.describe_spot_fleet_request_history(
                            SpotFleetRequestId=spotfleet,
                            EventType="fleetRequestChange",
                            StartTime=now_minus_ten_minutes,
                            MaxResults=1,
                        )
                        spot_fleet_last_activity = response["HistoryRecords"][0][
                            "Timestamp"
                        ]
                        if now > (
                            spot_fleet_last_activity + datetime.timedelta(minutes=10)
                        ):
                            logpush(
                                job_id
                                + " Spotfleet last activity was more than 10 mins ago but job has not started yet, rollback compute_node value"
                            )
                            new_job_select = (
                                job_select_resource.split(":compute_node")[0]
                                + ":compute_node=tbd"
                            )
                            qalter_cmd = [
                                system_cmds["qalter"],
                                "-l",
                                "stack_id=",
                                "-l",
                                "select=" + new_job_select,
                                str(job_id),
                            ]
                            run_command(qalter_cmd, "call")
                        else:
                            return True
                        break
                    if resource["ResourceType"] == "AWS::AutoScaling::AutoScalingGroup":
                        asg = resource["PhysicalResourceId"]
                        response = autoscaling.describe_scaling_activities(
                            AutoScalingGroupName=asg, MaxRecords=1
                        )
                        asg_last_activity_end_time = response["Activities"][0][
                            "EndTime"
                        ]
                        now = pytz.utc.localize(datetime.datetime.utcnow())
                        if now > (
                            asg_last_activity_end_time + datetime.timedelta(minutes=10)
                        ):
                            logpush(
                                job_id
                                + " asg last activity was more than 10 minutes ago but job has not started yet, rollback compute_node value"
                            )
                            new_job_select = (
                                job_select_resource.split(":compute_node")[0]
                                + ":compute_node=tbd"
                            )
                            qalter_cmd = [
                                system_cmds["qalter"],
                                "-l",
                                "stack_id=",
                                "-l",
                                "select=" + new_job_select,
                                str(job_id),
                            ]
                            run_command(qalter_cmd, "call")
                        else:
                            return True
                        break
            else:
                stack_creation_time = check_stack_status["Stacks"][0]["CreationTime"]
                now = pytz.utc.localize(datetime.datetime.utcnow())
                if now > (stack_creation_time + datetime.timedelta(minutes=30)):
                    logpush(
                        job_id
                        + " Stack has been created for more than 30 minutes. Because job has not started by then, rollback compute_node value"
                    )
                    new_job_select = (
                        job_select_resource.split(":compute_node")[0]
                        + ":compute_node=tbd"
                    )
                    qalter_cmd = [
                        system_cmds["qalter"],
                        "-l",
                        "stack_id=",
                        "-l",
                        "select=" + new_job_select,
                        str(job_id),
                    ]
                    run_command(qalter_cmd, "call")
                    cloudformation.delete_stack(StackName=stack_id)
                else:
                    logpush(
                        job_id
                        + " Stack has been created for less than 30 minutes. Let's wait a bit before killing the CI and resetting the compute_node value"
                    )
                    return True

        elif check_stack_status["Stacks"][0]["StackStatus"] == "CREATE_IN_PROGRESS":
            logpush(
                job_id
                + " is queued but has a valid CI assigned. However CloudFormation stack is not completed yet so we exit the script."
            )
            return True

        elif check_stack_status["Stacks"][0]["StackStatus"] in [
            "CREATE_FAILED",
            "ROLLBACK_COMPLETE",
            "ROLLBACK_FAILED",
        ]:
            logpush(
                job_id
                + " is queued but has a valid CI assigned. However CloudFormation stack is "
                + str(check_stack_status["Stacks"][0]["StackStatus"])
                + ".  Because job has not started by then, rollback compute_node value and delete stack"
            )
            new_job_select = (
                job_select_resource.split(":compute_node")[0] + ":compute_node=tbd"
            )
            run_command(
                [
                    system_cmds["qalter"],
                    "-l",
                    "stack_id=",
                    "-l",
                    "select=" + new_job_select,
                    str(job_id),
                ],
                "call",
            )
            run_command(
                [
                    system_cmds["qalter"],
                    "-l",
                    "error_message=Associated_CloudFormation_Stack_has_failed_to_create_with_status_"
                    + check_stack_status["Stacks"][0]["StackStatus"],
                    str(job_id),
                ],
                "call",
            )
            cloudformation.delete_stack(StackName=stack_id)
        else:
            pass

    except:
        # Stack does not exist (job could not start for whatever reason but compute has been provisioned
        logpush(
            job_id
            + " is queued with a valid compute Unit. However we did not detect any cloudformation stack. To ensure job can start, we rollback compute_node to default value in order for hosts to be re-provisioned"
        )
        # Rollback compute_node value to default 'TBD' to retry job
        new_job_select = (
            job_select_resource.split(":compute_node")[0] + ":compute_node=tbd"
        )
        qalter_cmd = [
            system_cmds["qalter"],
            "-l",
            "stack_id=",
            "-l",
            "select=" + new_job_select,
            str(job_id),
        ]
        run_command(qalter_cmd, "call")

    return False


def available_capacity(job_hash):
    free_cpus = 0
    pbsnodes_args = " -a -F json"
    pbsnodes_output = {}
    try:
        pbsnodes_output = json.loads(
            (
                run_command(
                    (system_cmds["pbsnodes"] + pbsnodes_args).split(), "check_output"
                )
            ).decode("utf-8")
        )
        if "nodes" in pbsnodes_output.keys():
            for hostname, host_data in pbsnodes_output["nodes"].items():
                if (
                    (host_data["state"] == "free")
                    and (
                        host_data["resources_available"]["compute_node"]
                        == "job" + job_hash
                    )
                    and (
                        datetime.datetime.now().timestamp()
                        > host_data["last_state_change_time"] + 60
                    )
                ):
                    if "ncpus" in host_data["resources_assigned"].keys():
                        free_cpus += int(
                            host_data["resources_available"]["ncpus"]
                        ) - int(host_data["resources_assigned"]["ncpus"])
                    else:
                        free_cpus += int(host_data["resources_available"]["ncpus"])
            return free_cpus
    except AttributeError:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        if (
            len(pbsnodes_output) == 0
        ):  # pbsnodes_output could return an empty string when there are no nodes in the cluster
            pass
        else:
            logpush(
                "Error occurred: {}, {}, {}".format(exc_type, fname, exc_tb.tb_lineno)
            )
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logpush(
            "Error occurred: {}, {}, {}, error: {}".format(
                exc_type, fname, exc_tb.tb_lineno, e
            )
        )

    return 0


# END EC2 FUNCTIONS


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config", nargs="?", required=True, help="Path to a configuration file"
    )
    parser.add_argument(
        "-t",
        "--type",
        nargs="?",
        required=True,
        help="queue type - ex: graphics, compute .. Open YML file for more info",
    )
    arg = parser.parse_args()
    queue_type = arg.type

    # Try to get a lock; if another dispatcher for the same queue is running, this instance will exit
    process_lock = get_lock("{} {}".format(__file__, queue_type))
    if process_lock is not True:
        print(
            "Dispatcher.py for this queue is already is already running with process id "
            + process_lock
            + ". Stop it first"
        )
        sys.exit(1)

    if "SOCA_CONFIGURATION" not in os.environ:
        print(
            "SOCA_CONFIGURATION not found, make sure to source /etc/environment first"
        )
        sys.exit(1)

    soca_configuration = configuration.get_soca_configuration()

    # Begin Pre-requisite
    system_cmds = {
        "qstat": "/opt/pbs/bin/qstat",
        "qmgr": "/opt/pbs/bin/qmgr",
        "qalter": "/opt/pbs/bin/qalter",
        "qdel": "/opt/pbs/bin/qdel",
        "pbsnodes": "/opt/pbs/bin/pbsnodes",
        "socaqstat": "/apps/soca/"
        + os.environ["SOCA_CONFIGURATION"]
        + "/cluster_manager/socaqstat.py",
        "python": "/apps/soca/"
        + os.environ["SOCA_CONFIGURATION"]
        + "/python/latest/bin/python3",
    }

    # AWS Clients
    ses = boto3.client("ses", config=configuration.boto_extra_config())
    ec2 = boto3.client("ec2", config=configuration.boto_extra_config())
    cloudformation = boto3.client(
        "cloudformation", config=configuration.boto_extra_config()
    )
    autoscaling = boto3.client("autoscaling", config=configuration.boto_extra_config())

    # Variables
    queue_parameter_values = {}
    queues = False
    queues_only_parameters = [
        "allowed_users",
        "excluded_users",
        "excluded_instance_types",
        "allowed_instance_types",
        "restricted_parameters",
        "allowed_security_group_ids",
        "allowed_instance_profiles",
    ]
    restricted_job_resources = [
        "select",
        "ncpus",
        "ngpus",
        "place",
        "nodect",
        "queues",
        "compute_node",
        "stack_id",
        "max_running_jobs",
        "max_provisioned_instances",
        "scaling_mode",
    ]  # dispatcher cannot edit these job values
    asg_name = None
    fair_share_running_job_malus = -60
    fair_share_start_score = 100

    # Retrieve Default Queue parameters
    queue_settings_file = (
        "/apps/soca/"
        + os.environ["SOCA_CONFIGURATION"]
        + "/cluster_manager/settings/queue_mapping.yml"
    )
    try:
        stream_resource_mapping = open(queue_settings_file, "r")
        docs = yaml.load_all(stream_resource_mapping, Loader=yaml.FullLoader)
        for doc in docs:
            for items in doc.values():
                for type, info in items.items():
                    if type == queue_type:
                        queues = info["queues"]
                        for parameter_key, parameter_value in info.items():
                            if parameter_key in queues_only_parameters:
                                # specific queue resources which are not job resources
                                pass
                            else:
                                queue_parameter_values[parameter_key] = parameter_value
            stream_resource_mapping.close()
    except Exception as err:
        print("Unable to read {} with error: {}".format(queue_settings_file, err))
        sys.exit(1)

    # Generate FlexLM mapping
    license_mapping_file = (
        "/apps/soca/"
        + os.environ["SOCA_CONFIGURATION"]
        + "/cluster_manager/settings/licenses_mapping.yml"
    )
    try:
        stream_flexlm_mapping = open(license_mapping_file, "r")
        docs = yaml.load_all(stream_flexlm_mapping, Loader=yaml.FullLoader)
        custom_flexlm_resources = {}
        for doc in docs:
            for k, v in doc.items():
                for license_name, license_output in v.items():
                    custom_flexlm_resources[license_name] = license_output
        stream_flexlm_mapping.close()
    except Exception as err:
        print("Unable to read {} with error: {}".format(license_mapping_file, err))
        sys.exit(1)
    # End Pre-requisite

    if queues is False:
        print("No queues  detected either on the queue_mapping.yml. Exiting ...")
        exit(1)

    for queue_name in queues:
        log_file = logging.FileHandler(
            "/apps/soca/"
            + os.environ["SOCA_CONFIGURATION"]
            + "/cluster_manager/logs/"
            + queue_name
            + ".log",
            "a",
        )
        formatter = logging.Formatter(
            "[%(asctime)s] [%(lineno)d] [%(levelname)s] [%(message)s]"
        )
        log_file.setFormatter(formatter)
        logger = logging.getLogger("tcpserver")
        for hdlr in logger.handlers[:]:  # remove all old handlers
            logger.removeHandler(hdlr)

        logger.addHandler(log_file)  # set the new handler
        logger.setLevel(logging.DEBUG)
        skip_queue = False
        limit_running_jobs = False
        get_jobs = get_jobs_infos(queue_name)
        if "queue_mode" in queue_parameter_values.keys():
            queue_mode = queue_parameter_values["queue_mode"]
        else:
            # default to fifo
            queue_mode = "fifo"

        if "scaling_mode" in queue_parameter_values.keys():
            scaling_mode = queue_parameter_values["scaling_mode"]
        else:
            # default to single_job
            scaling_mode = "single_job"

        logpush(
            "Queue provisioning: {}, scaling mode: {}".format(queue_mode, scaling_mode)
        )

        if check_if_queue_started(queue_name) is False:
            logpush("Queue does not seems to be enabled")
            skip_queue = True

        if scaling_mode == "multiple_jobs":
            queued_jobs_in_hash = []
            queued_jobs = []
            queued_jobs_being_provisioned_in_hash = []
            queued_jobs_being_provisioned = []
            running_jobs_in_hash = []
            running_jobs = []
            for job_hash, job_data in get_jobs.items():
                queued_jobs_in_hash = [
                    job_data[k]
                    for k, v in job_data.items()
                    if v["get_job_state"] == "Q"
                ]
                queued_jobs += queued_jobs_in_hash
                queued_jobs_being_provisioned_in_hash = [
                    job_data[k]
                    for k, v in job_data.items()
                    if v["get_job_state"] == "Q"
                    and "compute_node" in v["get_job_resource_list"]["select"]
                ]
                queued_jobs_being_provisioned += queued_jobs_being_provisioned_in_hash
                running_jobs_in_hash = [
                    job_data[k]
                    for k, v in job_data.items()
                    if v["get_job_state"] == "R"
                ]
                running_jobs += running_jobs_in_hash

            if queued_jobs.__len__() == 0:
                skip_queue = True

            if skip_queue is False:
                logpush(
                    "================================================================"
                )
                logpush(
                    "Detected Default Parameters for this queue: "
                    + str(queue_parameter_values)
                )

                job_list = []
                # Validate queue_mode
                if queue_mode == "fairshare":
                    user_fair_share = fair_share_score(
                        queued_jobs, running_jobs, queue_name
                    )
                    logpush("User Fair Share: " + str(user_fair_share))
                    job_id_order_based_on_fairshare = fair_share_job_id_order(
                        sorted(queued_jobs, key=lambda k: k["get_job_order_in_queue"]),
                        user_fair_share,
                    )
                    logpush(
                        "Job_id_order_based_on_fairshare: "
                        + str(job_id_order_based_on_fairshare)
                    )
                    job_list = job_id_order_based_on_fairshare
                elif queue_mode == "fifo":
                    for job in sorted(
                        queued_jobs, key=lambda k: k["get_job_order_in_queue"]
                    ):
                        job_list.append(job["get_job_id"])
                else:
                    logpush("queue mode must either be fairshare or fifo")
                    exit(1)

                hash_cpu_ct = 0
                job_parameter_values = {}
                stack_id = ""
                for job_hash, hash_data in get_jobs.items():
                    logpush("Iterating for job_hash: " + str(job_hash))
                    # Identify job ids that belong to the current job_hash
                    jobs_in_hash = []
                    for job_id in job_list:
                        if job_id in hash_data.keys():
                            jobs_in_hash.append(job_id)
                    # Identify Instance types and ht_support (both are unique to each job_hash) then calculate weighted capacity and memory available for each instance
                    # Pick the first job_id in the job_hash as an example
                    job_id = jobs_in_hash[0]
                    job_data = hash_data[job_id]
                    # Add job instance type and ht_support to job parameters
                    job_parameter_values["instance_type"] = job_data[
                        "get_job_instance_type"
                    ]
                    job_parameter_values["ht_support"] = job_data["get_job_ht_support"]
                    if "instance_ami" in job_data["get_job_resource_list"].keys():
                        job_parameter_values["instance_ami"] = job_data[
                            "get_job_resource_list"
                        ]["instance_ami"]
                    # Add queue parameters to the job parameters
                    for queue_param in queue_parameter_values.keys():
                        if queue_param not in job_parameter_values.keys():
                            job_parameter_values[queue_param] = queue_parameter_values[
                                queue_param
                            ]
                    # Checking for required parameters
                    if "instance_type" not in job_parameter_values.keys():
                        logpush(
                            "No instance type detected either on the queue_mapping.yml or at job submission. Exiting ..."
                        )
                        exit(1)

                    if "terminate_when_idle" not in job_parameter_values.keys():
                        logpush(
                            "scaling_mode is set to multiple_jobs but terminate_when_idle is not specified in the queue_mapping.yml or at job submission. Exiting ..."
                        )
                        exit(1)

                    if "instance_ami" not in job_parameter_values.keys():
                        logpush(
                            "No instance_ami type detected either on the queue_mapping.yml .. defaulting to base os"
                        )
                        job_parameter_values["instance_ami"] = soca_configuration[
                            "CustomAMI"
                        ]

                    user_instance_types = job_parameter_values["instance_type"].split(
                        "+"
                    )
                    instance_types = []
                    memory_required_instances = []
                    vcpus_required_instances = []
                    cores_required_instances = []
                    weighted_capacity = []
                    instances_attributes = ec2.describe_instance_types(
                        InstanceTypes=user_instance_types
                    )
                    # Note: describe_instance_types doesn't maintain order for user_instance_types
                    # Extract InstanceType and corresponding DefaultVCpus/DefaultCores to have consistent weighted_capacity
                    for item in instances_attributes["InstanceTypes"]:
                        instance_types.append(item["InstanceType"])
                        memory_required_instances.append(
                            item["MemoryInfo"]["SizeInMiB"]
                        )
                        vcpus_required_instances.append(
                            item["VCpuInfo"]["DefaultVCpus"]
                        )
                        cores_required_instances.append(
                            item["VCpuInfo"]["DefaultCores"]
                        )
                    if job_parameter_values["ht_support"].lower() == "false":
                        weighted_capacity = cores_required_instances
                    else:
                        weighted_capacity = vcpus_required_instances
                    # logpush("debug - instance_types are: " + str(instance_types) + ' weighted_capacity is: ' + str(weighted_capacity))

                    # Start iterating on jobs_in_hash
                    job_count = 0
                    for job_id in jobs_in_hash:
                        job_count += 1
                        if job_count > 300:
                            logpush("Reached 300 jobs for this iteration")
                            break
                        job_data = hash_data[job_id]
                        skip_job = False
                        if job_data["get_job_state"] == "Q":
                            logpush("Found queued job: " + job_id)
                            check_compute_unit = re.search(
                                r"compute_node=(\w+)",
                                job_data["get_job_resource_list"]["select"],
                            )
                            if check_compute_unit:
                                job_data["get_job_resource_list"][
                                    "compute_node"
                                ] = check_compute_unit.group(1)
                                try:
                                    if (
                                        capacity_being_provisioned(
                                            job_data["get_job_resource_list"][
                                                "stack_id"
                                            ],
                                            job_id,
                                            job_data["get_job_resource_list"]["select"],
                                            scaling_mode,
                                        )
                                        is True
                                    ):
                                        logpush(
                                            "Skipping "
                                            + str(job_id)
                                            + " as this job already has a valid compute node"
                                        )
                                        skip_job = True
                                except KeyError:
                                    # in certain very rare case, stack_id is not present, in this case we just ignore as the stack will automatically be generated
                                    pass

                            job_required_resource = job_data["get_job_resource_list"]
                            license_requirement = {}

                            licenses_required = []
                            resource_name = job_required_resource.keys()
                            for license_name in fnmatch.filter(resource_name, "*_lic*"):
                                if license_name not in licenses_required:
                                    licenses_required.append(license_name)

                            license_available = check_available_licenses(
                                custom_flexlm_resources, licenses_required
                            )
                            logpush("Licenses Available: " + str(license_available))

                            # Add queue parameters to the job parameters
                            for queue_param in queue_parameter_values.keys():
                                if queue_param not in job_parameter_values.keys():
                                    job_parameter_values[
                                        queue_param
                                    ] = queue_parameter_values[queue_param]

                            for res in job_required_resource:
                                if res == "ncpus":
                                    if int(job_required_resource[res]) > int(
                                        min(weighted_capacity)
                                    ):
                                        run_command(
                                            [
                                                system_cmds["qalter"],
                                                "-l",
                                                "error_message=Job_requires_ncpus_"
                                                + str(job_required_resource[res])
                                                + "_but_minimum_weighted_capacity_for_corresponding_instances_is_"
                                                + str(min(weighted_capacity))
                                                + "_Please_delete_the_job_and_resubmit_with_updated_resource_requirements",
                                                str(job_id),
                                            ],
                                            "call",
                                        )
                                        logpush(
                                            "Error: Job "
                                            + str(job_id)
                                            + " requires "
                                            + str(job_required_resource[res])
                                            + " ncpus but minimum weighted_capacity for corresponding instances is: "
                                            + str(min(weighted_capacity))
                                            + ". Job may not run!. Please delete the job and resubmit with updated resource requirements"
                                        )
                                        logpush("Skipping job: " + str(job_id))
                                        skip_job = True

                                if res == "mem":
                                    job_required_mem = 0
                                    if "kb" in job_required_resource[res].lower():
                                        job_required_mem = (
                                            int(
                                                job_required_resource[res]
                                                .lower()
                                                .strip("kb")
                                            )
                                            / 1024
                                        )
                                    elif "mb" in job_required_resource[res].lower():
                                        job_required_mem = int(
                                            job_required_resource[res]
                                            .lower()
                                            .strip("mb")
                                        )
                                    elif "gb" in job_required_resource[res].lower():
                                        job_required_mem = (
                                            int(
                                                job_required_resource[res]
                                                .lower()
                                                .strip("gb")
                                            )
                                            * 1024
                                        )
                                    else:
                                        # Default memory specification is in bytes
                                        job_required_mem = (
                                            int(
                                                job_required_resource[res]
                                                .lower()
                                                .strip("b")
                                            )
                                            / 1024
                                            / 1024
                                        )
                                    if job_required_mem > int(
                                        min(memory_required_instances)
                                    ):
                                        run_command(
                                            [
                                                system_cmds["qalter"],
                                                "-l",
                                                "error_message=Job_requires_"
                                                + str(job_required_mem)
                                                + "_MiB_mem_but_minimum_available_memory_for_corresponding_instances_is_"
                                                + str(min(memory_required_instances))
                                                + "_MiB_Please_delete_the_job_and_resubmit_with_updated_resource_requirements",
                                                str(job_id),
                                            ],
                                            "call",
                                        )
                                        logpush(
                                            "Error: Job "
                                            + str(job_id)
                                            + " requires "
                                            + str(job_required_mem)
                                            + " MiB mem. Specified instance types for this job are: "
                                            + str(instance_types)
                                        )
                                        logpush(
                                            ".....: Available memory for corresponding instances is: "
                                            + str(sorted(memory_required_instances))
                                            + " MiB. Job may not run as it could start on the smallest instance!"
                                        )
                                        logpush(
                                            ".....: Please delete the job and update required resources accordingly"
                                        )
                                        logpush("Skipping job: " + str(job_id))
                                        skip_job = True

                                try:
                                    if fnmatch.filter([res], "*_lic*"):
                                        if (
                                            int(job_required_resource[res])
                                            <= license_available[res]
                                        ):
                                            # job can run
                                            license_requirement[res] = int(
                                                job_required_resource[res]
                                            )
                                        else:
                                            logpush(
                                                "Ignoring job_"
                                                + job_id
                                                + " as we we dont have enough: "
                                                + str(res)
                                            )
                                            license_error_message = (
                                                "Not enough licenses "
                                                + str(res)
                                                + ". You have requested "
                                                + str(job_required_resource[res])
                                                + " but there is only "
                                                + str(license_available[res])
                                                + " licenses available."
                                            )
                                            run_command(
                                                [
                                                    system_cmds["qalter"],
                                                    "-l",
                                                    "error_message='"
                                                    + license_error_message.replace(
                                                        " ", "_"
                                                    )
                                                    + "'",
                                                    str(job_id),
                                                ],
                                                "call",
                                            )
                                            logpush("Skipping job: " + str(job_id))
                                            skip_job = True
                                except:
                                    logpush(
                                        "One required PBS resource has not been specified on the JSON input for "
                                        + job_id
                                        + ": "
                                        + str(res)
                                        + " . Please update custom_flexlm_resources on "
                                        + str(arg.config)
                                    )
                                    logpush("Skipping job: " + str(job_id))
                                    skip_job = True

                            if skip_job is False:
                                for res in job_required_resource:
                                    if res in job_parameter_values.keys():
                                        logpush(
                                            "Override default: "
                                            + res
                                            + " value.  Job will use new value: "
                                            + str(job_required_resource[res])
                                        )

                                        if res == "scratch_size":
                                            if (
                                                isinstance(
                                                    job_required_resource[res], int
                                                )
                                                is not True
                                            ):
                                                logpush(
                                                    "scratch_size must be an integer. Ignoring "
                                                    + str(job_required_resource[res])
                                                )
                                                job_required_resource[res] = 0

                                        if res == "scratch_iops":
                                            if (
                                                isinstance(
                                                    job_required_resource[res], int
                                                )
                                                is not True
                                            ):
                                                logpush(
                                                    "scratch_iops must be an integer. Ignoring "
                                                    + str(job_required_resource[res])
                                                )
                                                job_required_resource[res] = 0

                                        job_parameter_values[
                                            res
                                        ] = job_required_resource[res]

                                    else:
                                        logpush(
                                            "No default value for "
                                            + res
                                            + ". Creating new entry with value: "
                                            + str(job_required_resource[res])
                                        )
                                        job_parameter_values[
                                            res
                                        ] = job_required_resource[res]

                                hash_cpu_ct += int(job_data["get_job_ncpus"]) * int(
                                    job_data["get_job_nodect"]
                                )
                                compute_unit = "job" + job_hash
                                stack_id = (
                                    os.environ["SOCA_CONFIGURATION"]
                                    + "-job-"
                                    + job_hash
                                )
                                # logpush(str(job_id) + " : compute_node=" + str(compute_unit) + " | stack_id=" +str(stack_id))
                                select = (
                                    job_required_resource["select"].split(
                                        ":compute_node"
                                    )[0]
                                    + ":compute_node="
                                    + str(compute_unit)
                                )
                                logpush(
                                    "Setting job: "
                                    + str(job_id)
                                    + " select variable: "
                                    + str(select)
                                )

                                run_command(
                                    [
                                        system_cmds["qalter"],
                                        "-l",
                                        "select=" + select,
                                        str(job_id),
                                    ],
                                    "call",
                                )
                                run_command(
                                    [
                                        system_cmds["qalter"],
                                        "-l",
                                        "stack_id=" + stack_id,
                                        str(job_id),
                                    ],
                                    "call",
                                )

                    # We've completed a full iteration on all queued jobs that belong to a certain job_hash
                    # Now, the script will provision the required resources for these jobs
                    logpush(
                        "Completed full iteration for job_hash: "
                        + str(job_hash)
                        + ". Total required capacity is: "
                        + str(hash_cpu_ct)
                    )

                    if hash_cpu_ct > 0:
                        # Limit number of running jobs if "max_running_jobs" is set for this queue
                        try:
                            if "max_running_jobs" in queue_parameter_values.keys():
                                if not isinstance(
                                    queue_parameter_values["max_running_jobs"], int
                                ):
                                    logpush("max_running_jobs must be an integer")
                                    sys.exit(1)
                                if int(queue_parameter_values["max_running_jobs"]) < 0:
                                    logpush(
                                        "max_running_jobs must be an integer greater than 0"
                                    )
                                    sys.exit(1)

                                # consider queued_job with valid compute_node as valid running job
                                all_running_jobs = len(running_jobs) + len(
                                    queued_jobs_being_provisioned
                                )
                                logpush("Running jobs detected {}".format(running_jobs))
                                logpush(
                                    "Max number of running jobs {}".format(
                                        queue_parameter_values["max_running_jobs"]
                                    )
                                )
                                if (
                                    hash_cpu_ct + all_running_jobs
                                    > queue_parameter_values["max_running_jobs"]
                                ):
                                    hash_cpu_ct = (
                                        queue_parameter_values["max_running_jobs"]
                                        - all_running_jobs
                                    )
                            else:
                                pass

                        except Exception as err:
                            exc_type, exc_obj, exc_tb = sys.exc_info()
                            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                            logpush(
                                "max_running_jobs: Error occurred when trying to determine if job can start: {}, {}, {}".format(
                                    exc_type, fname, exc_tb.tb_lineno
                                )
                            )
                            sys.exit(1)

                        # Check available resources and reduce hash_cpu_ct accordingly
                        # Uncomment if you want to reduce capacity to be requested
                        # Note available_capacity method considers vCPUs/cores available
                        # However, it doesn't look at job memory requirements and memory available on instances
                        # free_cpus = available_capacity(job_hash)
                        # if free_cpus > 0:
                        #    logpush('Found ' + str(free_cpus) + ' available capacity for job_hash: ' + str(job_hash)+ '. Reducing required capacity accordingly')
                        #    hash_cpu_ct -= free_cpus

                        if hash_cpu_ct > 0:
                            try:
                                # Check if we have an existing stack named as stack_id
                                check_stack_status = cloudformation.describe_stacks(
                                    StackName=stack_id
                                )
                                logpush(
                                    "Checking existing cloudformation stack_id: "
                                    + str(stack_id)
                                    + " status: "
                                    + str(
                                        check_stack_status["Stacks"][0]["StackStatus"]
                                    )
                                )
                                # Create a list of jobs to revert in case SpotFleet is not ready or CFN is in CREATE_IN_PROGRESS
                                job_ids_being_provisioned = []
                                for job_data in queued_jobs_being_provisioned:
                                    job_ids_being_provisioned.append(
                                        job_data["get_job_id"]
                                    )
                                jobs_to_revert = set(jobs_in_hash) - set(
                                    job_ids_being_provisioned
                                )
                                if (
                                    check_stack_status["Stacks"][0]["StackStatus"]
                                    == "CREATE_COMPLETE"
                                ):
                                    # This means we already have a CFN stack with the same hash, so we need to find out the ASG or SpotFleet ID
                                    # Then we need to increase the desired capacity for the new queued jobs
                                    response = cloudformation.describe_stack_resources(
                                        StackName=stack_id
                                    )
                                    for resource in response["StackResources"]:
                                        if (
                                            resource["ResourceType"]
                                            == "AWS::EC2::SpotFleet"
                                        ):
                                            spotfleet = resource["PhysicalResourceId"]
                                            response = ec2.describe_spot_fleet_requests(
                                                SpotFleetRequestIds=[spotfleet]
                                            )
                                            fulfilled_capacity = int(
                                                response["SpotFleetRequestConfigs"][0][
                                                    "SpotFleetRequestConfig"
                                                ]["FulfilledCapacity"]
                                            )
                                            target_capacity = int(
                                                response["SpotFleetRequestConfigs"][0][
                                                    "SpotFleetRequestConfig"
                                                ]["TargetCapacity"]
                                            )
                                            current_capacity = max(
                                                target_capacity, fulfilled_capacity
                                            )
                                            new_target_capacity = (
                                                current_capacity + hash_cpu_ct
                                            )
                                            spot_fleet_activity_status = response[
                                                "SpotFleetRequestConfigs"
                                            ][0]["ActivityStatus"]
                                            spot_fleet_request_state = response[
                                                "SpotFleetRequestConfigs"
                                            ][0]["SpotFleetRequestState"]
                                            if (
                                                (
                                                    spot_fleet_activity_status
                                                    == "fulfilled"
                                                    or spot_fleet_activity_status
                                                    == "pending_fulfillment"
                                                )
                                                and spot_fleet_request_state == "active"
                                            ):
                                                logpush(
                                                    "Updating TargetCapacity for SpotFleet: "
                                                    + spotfleet
                                                    + " to: "
                                                    + str(new_target_capacity)
                                                )
                                                resp = ec2.modify_spot_fleet_request(
                                                    SpotFleetRequestId=spotfleet,
                                                    TargetCapacity=new_target_capacity,
                                                )
                                            else:
                                                # Revert stack_id and compute_node so the jobs can be reconsidered in the next dispatcher iteration
                                                logpush(
                                                    "Spot Fleet can't be modified at this time... reverting stack_id and select for job_ids:  "
                                                    + str(jobs_to_revert)
                                                )
                                                for job_id in jobs_to_revert:
                                                    job_select_resource = hash_data[
                                                        job_id
                                                    ]["get_job_resource_list"]["select"]
                                                    new_job_select = (
                                                        job_select_resource.split(
                                                            ":compute_node"
                                                        )[0]
                                                        + ":compute_node=tbd"
                                                    )
                                                    run_command(
                                                        [
                                                            system_cmds["qalter"],
                                                            "-l",
                                                            "stack_id=",
                                                            "-l",
                                                            "select=" + new_job_select,
                                                            str(job_id),
                                                        ],
                                                        "call",
                                                    )
                                            break
                                        if (
                                            resource["ResourceType"]
                                            == "AWS::AutoScaling::AutoScalingGroup"
                                        ):
                                            asg = resource["PhysicalResourceId"]
                                            response = autoscaling.describe_auto_scaling_groups(
                                                AutoScalingGroupNames=[asg],
                                                MaxRecords=100,
                                            )
                                            new_target_capacity = (
                                                int(
                                                    response["AutoScalingGroups"][0][
                                                        "DesiredCapacity"
                                                    ]
                                                )
                                                + hash_cpu_ct
                                            )
                                            logpush(
                                                "Updating DesiredCapacity for ASG: "
                                                + asg
                                                + " to: "
                                                + str(new_target_capacity)
                                            )
                                            resp = (
                                                autoscaling.update_auto_scaling_group(
                                                    AutoScalingGroupName=asg,
                                                    MinSize=new_target_capacity,
                                                    MaxSize=new_target_capacity,
                                                    DesiredCapacity=new_target_capacity,
                                                )
                                            )
                                            break
                                elif (
                                    check_stack_status["Stacks"][0]["StackStatus"]
                                    == "CREATE_IN_PROGRESS"
                                ):
                                    # Revert stack_id and compute_node so the jobs can be reconsidered in the next dispatcher iteration
                                    logpush(
                                        "CFN status is CREATE_IN_PROGRESS... reverting stack_id and select for job_ids:  "
                                        + str(jobs_to_revert)
                                    )
                                    for job_id in jobs_to_revert:
                                        job_select_resource = hash_data[job_id][
                                            "get_job_resource_list"
                                        ]["select"]
                                        new_job_select = (
                                            job_select_resource.split(":compute_node")[
                                                0
                                            ]
                                            + ":compute_node=tbd"
                                        )
                                        run_command(
                                            [
                                                system_cmds["qalter"],
                                                "-l",
                                                "stack_id=",
                                                "-l",
                                                "select=" + new_job_select,
                                                str(job_id),
                                            ],
                                            "call",
                                        )

                            except ClientError as e:
                                if e.response["Error"]["Code"] == "ValidationError":
                                    # Stack doesn't exist -> create a new one
                                    logpush(
                                        "Unable to find a cfn stack for job_hash: "
                                        + job_hash
                                        + " ... Creating a new stack"
                                    )

                                    # Adding extra parameters to job_parameter_values
                                    job_parameter_values[
                                        "desired_capacity"
                                    ] = hash_cpu_ct
                                    job_parameter_values["queue"] = queue_name
                                    job_parameter_values["job_id"] = job_hash
                                    job_parameter_values["job_name"] = job_data[
                                        "get_job_name"
                                    ]  # May not be true for all jobs in the hash to have the same name
                                    job_parameter_values["job_owner"] = job_data[
                                        "get_job_owner"
                                    ]  # May not be true for all jobs in the hash to have the same owner
                                    job_parameter_values["job_project"] = job_data[
                                        "get_job_project"
                                    ]  # May not be true for all jobs in the hash to have the same project
                                    job_parameter_values["keep_forever"] = False
                                    job_parameter_values[
                                        "terminate_when_idle"
                                    ] = job_data["get_job_terminate_when_idle"]
                                    job_parameter_values["instance_type"] = "+".join(
                                        instance_types
                                    )
                                    job_parameter_values["ht_support"] = job_data[
                                        "get_job_ht_support"
                                    ]
                                    job_parameter_values[
                                        "weighted_capacity"
                                    ] = "+".join(
                                        str(item) for item in weighted_capacity
                                    )

                                    # create capacity
                                    create_new_asg = add_nodes.main(
                                        **job_parameter_values
                                    )
                                    if create_new_asg["success"] is True:
                                        compute_unit = create_new_asg["compute_node"]
                                        stack_id = create_new_asg["stack_name"]
                                        logpush(
                                            str(job_id)
                                            + " : compute_node="
                                            + str(compute_unit)
                                            + " | stack_id="
                                            + str(stack_id)
                                        )

                                        # flush error if any
                                        run_command(
                                            [
                                                system_cmds["qalter"],
                                                "-l",
                                                "error_message=",
                                                str(job_id),
                                            ],
                                            "call",
                                        )

                                        for (
                                            resource,
                                            count_to_substract,
                                        ) in license_requirement.items():
                                            license_available[resource] = (
                                                license_available[resource]
                                                - count_to_substract
                                            )
                                            logpush(
                                                "License available: "
                                                + str(license_available[resource])
                                            )

                                    else:
                                        sanitized_error = re.sub(
                                            r"\W+", "_", create_new_asg["message"]
                                        )
                                        sanitized_error = (
                                            create_new_asg["message"]
                                            .replace("'", "_")
                                            .replace("!", "_")
                                            .replace(" ", "_")
                                        )
                                        run_command(
                                            [
                                                system_cmds["qalter"],
                                                "-l",
                                                "error_message='"
                                                + sanitized_error
                                                + "'",
                                                str(job_id),
                                            ],
                                            "call",
                                        )
                                        logpush(
                                            "Error while trying to create ASG: "
                                            + str(create_new_asg)
                                        )

                                else:
                                    logpush(
                                        "Encountered an unexpected client error: "
                                        + str(e)
                                    )

                            except Exception as e:
                                exc_type, exc_obj, exc_tb = sys.exc_info()
                                fname = os.path.split(
                                    exc_tb.tb_frame.f_code.co_filename
                                )[1]
                                logpush(
                                    "Error occurred: {}, {}, {}, error: {}".format(
                                        exc_type, fname, exc_tb.tb_lineno, e
                                    )
                                )

                    # Reset hash_cpu_ct for the next job_hash
                    hash_cpu_ct = 0
        else:
            # scaling_mode == "single_job"
            # Check if there is any queued job with valid compute unit but has not started within 1 hour
            # If yes, all other jobs will be paused unless they don't rely on licenses
            for job_id, job_data in get_jobs.items():
                if job_data["get_job_state"] == "Q":
                    check_compute_unit = re.search(
                        r"compute_node=(\w+)",
                        job_data["get_job_resource_list"]["select"],
                    )
                    if check_compute_unit:
                        job_data["get_job_resource_list"][
                            "compute_node"
                        ] = check_compute_unit.group(1)
                        try:
                            if (
                                capacity_being_provisioned(
                                    job_data["get_job_resource_list"]["stack_id"],
                                    job_id,
                                    job_data["get_job_resource_list"]["select"],
                                    scaling_mode,
                                )
                                is True
                            ):
                                logpush(
                                    "Skipping "
                                    + str(job_id)
                                    + " as this job already has a valid compute node"
                                )
                                resource_name = job_data["get_job_resource_list"].keys()
                                # If you want to make sure ANY job cannot start if there is a queue job with a valid compute_node, then force skip_queue to True
                                if fnmatch.filter(resource_name, "*_lic*"):
                                    # Because applications are license dependant, we want to make sure we won't launch any new jobs until previous launched jobs are running and using the license
                                    logpush(
                                        "Job is being provisioned and has license requirement. We ignore all others job in queue to prevent license double usage due to race condition. Provisioning for "
                                        + queue_name
                                        + " will continue as soon as this job start running"
                                    )
                                    skip_queue = True

                        except KeyError:
                            # in certain very rare case, stack_id is not present, in this case we just ignore as the stack will automatically be generated
                            pass
                    else:
                        get_jobs[job_id]["get_job_resource_list"][
                            "compute_node"
                        ] = "tbd"

            queued_jobs = [
                get_jobs[k] for k, v in get_jobs.items() if v["get_job_state"] == "Q"
            ]
            queued_jobs_being_provisioned = [
                get_jobs[k]
                for k, v in get_jobs.items()
                if v["get_job_state"] == "Q"
                and "compute_node" in v["get_job_resource_list"]["select"]
            ]
            queued_jobs_not_being_provisioned = [
                get_jobs[k]
                for k, v in get_jobs.items()
                if v["get_job_state"] == "Q"
                and "compute_node" not in v["get_job_resource_list"]["select"]
            ]
            running_jobs = [
                get_jobs[k] for k, v in get_jobs.items() if v["get_job_state"] == "R"
            ]

            if queued_jobs.__len__() == 0:
                skip_queue = True

            if skip_queue is False:
                logpush(
                    "================================================================"
                )
                logpush(
                    "Detected Default Parameters for this queue: "
                    + str(queue_parameter_values)
                )
                licenses_required = []
                for job_data in queued_jobs:
                    resource_name = job_data["get_job_resource_list"].keys()
                    for license_name in fnmatch.filter(resource_name, "*_lic*"):
                        if license_name not in licenses_required:
                            licenses_required.append(license_name)

                license_available = check_available_licenses(
                    custom_flexlm_resources, licenses_required
                )
                logpush("Licenses Available: " + str(license_available))

                job_list = []
                # Validate queue_mode
                if queue_mode == "fairshare":
                    user_fair_share = fair_share_score(
                        queued_jobs, running_jobs, queue_name
                    )
                    logpush("User Fair Share: " + str(user_fair_share))
                    job_id_order_based_on_fairshare = fair_share_job_id_order(
                        sorted(queued_jobs, key=lambda k: k["get_job_order_in_queue"]),
                        user_fair_share,
                    )
                    logpush(
                        "Job_id_order_based_on_fairshare: "
                        + str(job_id_order_based_on_fairshare)
                    )
                    job_list = job_id_order_based_on_fairshare
                elif queue_mode == "fifo":
                    for job in sorted(
                        queued_jobs, key=lambda k: k["get_job_order_in_queue"]
                    ):
                        job_list.append(job["get_job_id"])
                else:
                    logpush("queue mode must either be fairshare or fifo")
                    exit(1)

                try:
                    # Limit number of instances that can be provisioned
                    if (
                        "max_provisioned_instances" in queue_parameter_values.keys()
                        and limit_running_jobs is False
                    ):
                        if not isinstance(
                            queue_parameter_values["max_provisioned_instances"], int
                        ):
                            logpush("max_provisioned_instances must be an integer")
                            sys.exit(1)
                        if int(queue_parameter_values["max_provisioned_instances"]) < 0:
                            logpush(
                                "max_provisioned_instances must be an integer greater than 0"
                            )
                            sys.exit(1)

                        # consider queued_job with valid compute_node as valid running job
                        provisioned_instances = sum(
                            int(job_info["get_job_nodect"]) for job_info in running_jobs
                        ) + sum(
                            int(job_info["get_job_nodect"])
                            for job_info in queued_jobs_being_provisioned
                        )

                        if (
                            provisioned_instances
                            >= queue_parameter_values["max_provisioned_instances"]
                        ):
                            logpush(
                                "Maximum number of provisioned instances reached, exiting ..."
                            )
                            for job_info in queued_jobs_not_being_provisioned:
                                run_command(
                                    [
                                        system_cmds["qalter"],
                                        "-l",
                                        "error_message=Number_of_concurrent_provisioned_instances_("
                                        + str(
                                            queue_parameter_values[
                                                "max_provisioned_instances"
                                            ]
                                        )
                                        + ")_or_queued_job_being_launched_reached",
                                        str(job_info["get_job_id"]),
                                    ],
                                    "call",
                                )
                            limit_running_jobs = True

                        elif (
                            provisioned_instances
                            + sum(
                                int(job_info["get_job_nodect"])
                                for job_info in queued_jobs_not_being_provisioned
                            )
                        ) > queue_parameter_values["max_provisioned_instances"]:
                            current_host_count = provisioned_instances
                            queued_jobs_to_be_started = []
                            for job in queued_jobs_not_being_provisioned:
                                new_host_count = current_host_count + int(
                                    job["get_job_nodect"]
                                )
                                if (
                                    queue_parameter_values["max_provisioned_instances"]
                                    >= new_host_count
                                ):
                                    # break here if you want to enforce FIFO and not optimize the number of job that can run
                                    current_host_count = new_host_count
                                    queued_jobs_to_be_started.append(job["get_job_id"])

                            logpush(
                                "Current provisioned {} + capacity queued  {}  will exceed the number of instances that can be provisioned {}. We will limit the number of queued job that can be processed to {}".format(
                                    current_host_count,
                                    sum(
                                        int(job_info["get_job_nodect"])
                                        for job_info in queued_jobs_not_being_provisioned
                                    ),
                                    queue_parameter_values["max_provisioned_instances"],
                                    queued_jobs_to_be_started,
                                )
                            )

                            for job_id in set(job_list) - set(
                                queued_jobs_to_be_started
                            ):
                                if (
                                    "compute_node"
                                    not in get_jobs[job_id]["get_job_resource_list"][
                                        "select"
                                    ]
                                ):
                                    run_command(
                                        [
                                            system_cmds["qalter"],
                                            "-l",
                                            "error_message=Number_of_concurrent_provisioned_instances_("
                                            + str(
                                                queue_parameter_values[
                                                    "max_provisioned_instances"
                                                ]
                                            )
                                            + ")_or_queued_job_being_launched_reached",
                                            str(job_id),
                                        ],
                                        "call",
                                    )

                            job_list = queued_jobs_to_be_started
                            logpush("New job_list: " + str(job_list))

                        else:
                            pass

                except Exception as err:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    logpush(
                        "max_provisioned_instances: Error occurred when trying to determine if job can start: {}, {}, {}".format(
                            exc_type, fname, exc_tb.tb_lineno
                        )
                    )
                    sys.exit(1)

                # Limit number of concurrent running jobs if "max_running_jobs" is set for this queue
                try:
                    if "max_running_jobs" in queue_parameter_values.keys():
                        if not isinstance(
                            queue_parameter_values["max_running_jobs"], int
                        ):
                            logpush("max_running_jobs must be an integer")
                            sys.exit(1)
                        if int(queue_parameter_values["max_running_jobs"]) < 0:
                            logpush(
                                "max_running_jobs must be an integer greater than 0"
                            )
                            sys.exit(1)

                        # consider queued_job with valid compute_node as valid running job
                        all_running_jobs = len(running_jobs) + len(
                            queued_jobs_being_provisioned
                        )
                        logpush("Running jobs detected {}".format(running_jobs))
                        logpush(
                            "Max number of running jobs {}".format(
                                queue_parameter_values["max_running_jobs"]
                            )
                        )
                        if (
                            all_running_jobs
                            >= queue_parameter_values["max_running_jobs"]
                        ):
                            logpush(
                                "Maximum number of running job or queued job with computenode assigned reached, exiting ..."
                            )
                            for job_info in queued_jobs_not_being_provisioned:
                                run_command(
                                    [
                                        system_cmds["qalter"],
                                        "-l",
                                        "error_message=Number_of_concurrent_running_jobs_("
                                        + str(
                                            queue_parameter_values["max_running_jobs"]
                                        )
                                        + ")_or_queued_job_being_launched_reached",
                                        str(job_info["get_job_id"]),
                                    ],
                                    "call",
                                )
                            limit_running_jobs = True

                        elif (
                            all_running_jobs + len(queued_jobs)
                            > queue_parameter_values["max_running_jobs"]
                        ):
                            queued_jobs_to_be_started = (
                                queue_parameter_values["max_running_jobs"]
                                - all_running_jobs
                            )
                            logpush(
                                "Current running ({}) + queued jobs ({})  will exceed the number of authorized running_jobs. We will limit the number of queued job that can be processed to {}".format(
                                    all_running_jobs,
                                    len(queued_jobs),
                                    queued_jobs_to_be_started,
                                )
                            )
                            queued_job_with_valid_compute_node = 0
                            job_count = 0
                            for job_id in job_list:
                                job = get_jobs[job_id]
                                if job_count == queued_jobs_to_be_started:
                                    break
                                else:
                                    if (
                                        job["get_job_resource_list"]["compute_node"]
                                        != "tbd"
                                    ):
                                        queued_job_with_valid_compute_node += 1
                                    else:
                                        job_count += 1

                            for job_id in set(job_list) - set(
                                job_list[
                                    : job_count + queued_job_with_valid_compute_node
                                ]
                            ):
                                if (
                                    "compute_node"
                                    not in get_jobs[job_id]["get_job_resource_list"][
                                        "select"
                                    ]
                                ):
                                    run_command(
                                        [
                                            system_cmds["qalter"],
                                            "-l",
                                            "error_message=Number_of_concurrent_running_jobs_("
                                            + str(
                                                queue_parameter_values[
                                                    "max_running_jobs"
                                                ]
                                            )
                                            + ")_or_queued_job_being_launched_reached",
                                            str(job_id),
                                        ],
                                        "call",
                                    )

                            job_list = job_list[
                                : job_count + queued_job_with_valid_compute_node
                            ]
                            logpush("New job_list: " + str(job_list))
                        else:
                            pass

                except Exception as err:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    logpush(
                        "max_running_jobs: Error occurred when trying to determine if job can start: {}, {}, {}".format(
                            exc_type, fname, exc_tb.tb_lineno
                        )
                    )
                    sys.exit(1)

                for job_id in job_list:
                    job_parameter_values = {}
                    job = get_jobs[job_id]

                    job_owner = str(job["get_job_owner"])
                    job_id = str(job["get_job_id"])

                    if job["get_job_resource_list"]["compute_node"] != "tbd":
                        skip_job = True
                    else:
                        skip_job = False

                    if skip_job is False and limit_running_jobs is False:
                        job_required_resource = job["get_job_resource_list"]
                        license_requirement = {}
                        logpush(
                            "Checking if we have enough resources available to run job_"
                            + job_id
                        )
                        can_run = True
                        for res in job_required_resource:
                            if res in job_parameter_values.keys():
                                logpush(
                                    "Override default: "
                                    + res
                                    + " value.  Job will use new value: "
                                    + str(job_required_resource[res])
                                )
                                if res == "spot_price":
                                    if (
                                        isinstance(job_required_resource[res], float)
                                        is not True
                                    ):
                                        logpush(
                                            "spot price must be a float. Ignoring "
                                            + str(job_required_resource[res])
                                            + " and capacity will run as OnDemand"
                                        )
                                        job_required_resource[res] = 0

                                if res == "scratch_size":
                                    if (
                                        isinstance(job_required_resource[res], int)
                                        is not True
                                    ):
                                        logpush(
                                            "scratch_size must be an integer. Ignoring "
                                            + str(job_required_resource[res])
                                        )
                                        job_required_resource[res] = 0

                                if res == "scratch_iops":
                                    if (
                                        isinstance(job_required_resource[res], int)
                                        is not True
                                    ):
                                        logpush(
                                            "scratch_iops must be an integer. Ignoring "
                                            + str(job_required_resource[res])
                                        )
                                        job_required_resource[res] = 0

                                job_parameter_values[res] = job_required_resource[res]

                            else:
                                logpush(
                                    "No default value for "
                                    + res
                                    + ". Creating new entry with value: "
                                    + str(job_required_resource[res])
                                )
                                job_parameter_values[res] = job_required_resource[res]

                            try:
                                if fnmatch.filter([res], "*_lic*"):
                                    if (
                                        int(job_required_resource[res])
                                        <= license_available[res]
                                    ):
                                        # job can run
                                        license_requirement[res] = int(
                                            job_required_resource[res]
                                        )
                                    else:
                                        logpush(
                                            "Ignoring job_"
                                            + job_id
                                            + " as we we dont have enough: "
                                            + str(res)
                                        )
                                        license_error_message = (
                                            "Not enough licenses "
                                            + str(res)
                                            + ". You have requested "
                                            + str(job_required_resource[res])
                                            + " but there is only "
                                            + str(license_available[res])
                                            + " licenses available."
                                        )
                                        run_command(
                                            [
                                                system_cmds["qalter"],
                                                "-l",
                                                "error_message='"
                                                + license_error_message.replace(
                                                    " ", "_"
                                                )
                                                + "'",
                                                str(job_id),
                                            ],
                                            "call",
                                        )
                                        can_run = False
                            except:
                                logpush(
                                    "One required PBS resource has not been specified on the JSON input for "
                                    + job_id
                                    + ": "
                                    + str(res)
                                    + " . Please update custom_flexlm_resources on "
                                    + str(arg.config)
                                )
                                can_run = False

                        if can_run is True:
                            for queue_param in queue_parameter_values.keys():
                                if queue_param not in job_parameter_values.keys():
                                    job_parameter_values[
                                        queue_param
                                    ] = queue_parameter_values[queue_param]

                            # Checking for required parameters
                            if "instance_type" not in job_parameter_values.keys():
                                logpush(
                                    "No instance type detected either on the queue_mapping.yml or at job submission. Exiting ..."
                                )
                                exit(1)

                            if "instance_ami" not in job_parameter_values.keys():
                                logpush(
                                    "No instance_ami type detected either on the queue_mapping.yml .. defaulting to base os"
                                )
                                job_parameter_values[
                                    "instance_ami"
                                ] = soca_configuration["CustomAMI"]

                            # Append new resource to job resource for better tracking
                            # Ignore queue resources which are not configurable at job level
                            try:
                                alter_job_res = " ".join(
                                    "-l {}={}".format(key, value)
                                    for key, value in job_parameter_values.items()
                                    if key not in restricted_job_resources
                                )
                            except Exception as err:
                                logpush(
                                    "Unable to edit job with qalter command. Please edit the restricted_job_resources if the parameter is not a valid scheduler resource"
                                )

                            run_command(
                                [system_cmds["qalter"]]
                                + alter_job_res.split()
                                + [str(job_id)],
                                "call",
                            )
                            desired_capacity = int(job_required_resource["nodect"])
                            cpus_count_pattern = re.search(
                                r"[.](\d+)", job_parameter_values["instance_type"]
                            )
                            if cpus_count_pattern:
                                cpu_per_system = int(cpus_count_pattern.group(1)) * 2
                            else:
                                cpu_per_system = "2"

                            # Prevent job to start if PPN requested > CPUs per system
                            if "ppn" in job_required_resource.keys():
                                if job_required_resource["ppn"] > cpu_per_system:
                                    logpush(
                                        "Ignoring Job "
                                        + job_id
                                        + " as the PPN specified ("
                                        + str(job_required_resource["ppn"])
                                        + ") is higher than the number of cpu per system : "
                                        + str(cpu_per_system),
                                        "error",
                                    )
                                    can_run = False

                            logpush(
                                "job_"
                                + job_id
                                + " can run, doing dry run test with following parameters: "
                                + job_parameter_values["instance_type"]
                                + " *  "
                                + str(desired_capacity)
                            )
                            try:
                                # Adding extra parameters to job_parameter_values
                                job_parameter_values[
                                    "desired_capacity"
                                ] = desired_capacity
                                job_parameter_values["queue"] = queue_name
                                job_parameter_values["job_id"] = job_id
                                job_parameter_values["job_name"] = job["get_job_name"]
                                job_parameter_values["job_owner"] = job["get_job_owner"]
                                job_parameter_values["job_project"] = job[
                                    "get_job_project"
                                ]
                                job_parameter_values["keep_forever"] = False

                                # create capacity for the job
                                create_new_asg = add_nodes.main(**job_parameter_values)
                                if create_new_asg["success"] is True:
                                    compute_unit = create_new_asg["compute_node"]
                                    stack_id = create_new_asg["stack_name"]
                                    logpush(
                                        str(job_id)
                                        + " : compute_node="
                                        + str(compute_unit)
                                        + " | stack_id="
                                        + str(stack_id)
                                    )
                                    # Add new PBS resource to the job
                                    # stack_id=xxx -> CloudFormation Stack Name
                                    # compute_node=xxx -> Unique ID that will be assigned to all EC2 hosts for this job

                                    select = (
                                        job_required_resource["select"].split(
                                            ":compute_node"
                                        )[0]
                                        + ":compute_node="
                                        + str(compute_unit)
                                    )
                                    logpush("select variable: " + str(select))

                                    run_command(
                                        [
                                            system_cmds["qalter"],
                                            "-l",
                                            "select=" + select,
                                            str(job_id),
                                        ],
                                        "call",
                                    )
                                    run_command(
                                        [
                                            system_cmds["qalter"],
                                            "-l",
                                            "stack_id=" + stack_id,
                                            str(job_id),
                                        ],
                                        "call",
                                    )

                                    # flush error if any
                                    run_command(
                                        [
                                            system_cmds["qalter"],
                                            "-l",
                                            "error_message=",
                                            str(job_id),
                                        ],
                                        "call",
                                    )

                                    for (
                                        resource,
                                        count_to_substract,
                                    ) in license_requirement.items():
                                        license_available[resource] = (
                                            license_available[resource]
                                            - count_to_substract
                                        )
                                        logpush(
                                            "License available: "
                                            + str(license_available[resource])
                                        )

                                else:
                                    sanitized_error = re.sub(
                                        r"\W+", "_", create_new_asg["message"]
                                    )
                                    sanitized_error = (
                                        create_new_asg["message"]
                                        .replace("'", "_")
                                        .replace("!", "_")
                                        .replace(" ", "_")
                                    )
                                    run_command(
                                        [
                                            system_cmds["qalter"],
                                            "-l",
                                            "error_message='" + sanitized_error + "'",
                                            str(job_id),
                                        ],
                                        "call",
                                    )
                                    logpush(
                                        "Error while trying to create ASG: "
                                        + str(create_new_asg)
                                    )

                            except Exception as e:
                                exc_type, exc_obj, exc_tb = sys.exc_info()
                                fname = os.path.split(
                                    exc_tb.tb_frame.f_code.co_filename
                                )[1]
                                logpush(
                                    "Create ASG (refer to add_nodes.py) failed for job_"
                                    + job_id
                                    + " with error: "
                                    + str(e)
                                    + " "
                                    + str(exc_type)
                                    + " "
                                    + str(fname)
                                    + " "
                                    + str(exc_tb.tb_lineno),
                                    "error",
                                )
                        else:
                            logpush("can_run is False for " + str(job_id))
                    else:
                        logpush("Skip " + str(job_id))
