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

import subprocess
import argparse
import getpass
import json
import subprocess
import sys
import yaml
import os
import hashlib
from ast import literal_eval
from datetime import datetime

from prettytable import PrettyTable


def run_command(cmd):
    try:
        command = subprocess.Popen(
            cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        stdout, stderr = command.communicate()
        return literal_eval(stdout.decode("utf-8"))  # clear possible escape char
    except subprocess.CalledProcessError as e:
        exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-u", "--user", nargs="?", help="Retrieve jobs for a specific user"
    )
    parser.add_argument(
        "-q", "--queue", nargs="?", help="Retrieve all jobs behind a specific queue"
    )
    parser.add_argument("-j", "--job", nargs="?", help="Specific job id")
    parser.add_argument(
        "-s", "--state", nargs="?", help="Retrieve jobs using specific state"
    )
    parser.add_argument(
        "-w", "--wide", action="store_const", const=True, help="Display all exec host"
    )
    parser.add_argument(
        "-d",
        "--desktop",
        action="store_const",
        const=True,
        help="Display Graphical sessions",
    )
    parser.add_argument("-f", "--format", nargs="?", help="json format")
    arg = parser.parse_args()
    qstat_output = run_command("/opt/pbs/bin/qstat -f -F json")
    desktop_queue = ["desktop"]
    job_id_order = []
    output = []
    dict_output = {}
    job_order = 0

    # Retrieve Default Queue parameters
    queue_settings_file = (
        "/apps/soca/"
        + os.environ["SOCA_CONFIGURATION"]
        + "/cluster_manager/settings/queue_mapping.yml"
    )
    queue_parameter_values = {}
    try:
        stream_resource_mapping = open(queue_settings_file, "r")
        docs = yaml.load_all(stream_resource_mapping, Loader=yaml.FullLoader)
        for doc in docs:
            for items in doc.values():
                for type, info in items.items():
                    if arg.queue in info["queues"]:
                        for parameter_key, parameter_value in info.items():
                            queue_parameter_values[parameter_key] = parameter_value
            stream_resource_mapping.close()
    except Exception as err:
        print("Unable to read {} with error: {}".format(queue_settings_file, err))
        sys.exit(1)

    if "scaling_mode" in queue_parameter_values.keys():
        scaling_mode = queue_parameter_values["scaling_mode"]
    else:
        # default to single_job
        scaling_mode = "single_job"

    if scaling_mode == "multiple_jobs":
        table_output = PrettyTable(
            [
                "Job ID",
                "Instance Type",
                "HT Support",
                "spot_price",
                "Queue",
                "Owner",
                "Job State",
                "Exec hosts",
                "Job Name",
                "NDS",
                "TSK",
                "Start Time",
                "Submit Time",
                "Job ID Hash",
                "Terminate When Idle",
            ]
        )
    else:
        table_output = PrettyTable(
            [
                "Job ID",
                "Queue",
                "Owner",
                "Job State",
                "Exec hosts",
                "Job Name",
                "NDS",
                "TSK",
                "Start Time",
                "Submit Time",
            ]
        )

    if "Jobs" not in qstat_output.keys():
        print("INFO: No jobs detected.")
        sys.exit(0)

    for job, job_data in qstat_output["Jobs"].items():
        try:
            # Reset important parameters to queue parameters
            if "instance_type" in queue_parameter_values.keys():
                instance_type = queue_parameter_values["instance_type"]

            if "ht_support" in queue_parameter_values.keys():
                ht_support = queue_parameter_values["ht_support"]

            if "instance_ami" in queue_parameter_values.keys():
                instance_ami = queue_parameter_values["instance_ami"]

            if "spot_price" in queue_parameter_values.keys():
                spot_price = queue_parameter_values["spot_price"]
            else:
                spot_price = False

            if "terminate_when_idle" in queue_parameter_values.keys():
                terminate_when_idle = queue_parameter_values["terminate_when_idle"]

            ignore = False
            job_id = job.split(".")[0]
            job_owner = job_data["Job_Owner"].split("@")[0]
            job_queue = job_data["queue"]
            job_state = job_data["job_state"]
            if "instance_type" in job_data["Resource_List"].keys():
                instance_type = job_data["Resource_List"]["instance_type"]
            if "ht_support" in job_data["Resource_List"].keys():
                ht_support = job_data["Resource_List"]["ht_support"]
            if "spot_price" in job_data["Resource_List"].keys():
                spot_price = job_data["Resource_List"]["spot_price"]
            if "instance_ami" in job_data["Resource_List"].keys():
                instance_ami = job_data["Resource_List"]["instance_ami"]

            if arg.user is None:
                if job_owner != getpass.getuser():
                    # When arg.user is specified, ignore all jobs which don't match the requested user owner
                    ignore = True
                else:
                    # If job belongs to user, ignore only if desktop GUI and --desktop is not set
                    if arg.desktop is None:
                        if job_queue in desktop_queue:
                            ignore = True
            else:
                if arg.user == "all":
                    pass
                else:
                    if job_owner != arg.user:
                        # When arg.user is specified, ignore all jobs which don't match the requested user owner
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

            if "exec_vnode" in job_data.keys():
                if arg.wide is True:
                    exec_vnode = job_data["exec_vnode"]
                else:
                    exec_vnode = job_data["exec_vnode"].split("+")[0]
            else:
                exec_vnode = "-"

            if job_state.lower() != "r":
                stime = "-"
                stime_epoch = "-"
            else:
                stime = job_data["stime"]
                stime_epoch = (
                    datetime.strptime(stime, "%a %b %d %H:%M:%S %Y")
                ).strftime("%s")

            if scaling_mode == "multiple_jobs":
                h = hashlib.sha256()
                if spot_price == False:
                    t = (instance_type, instance_ami, ht_support, job_queue, "false")
                else:
                    t = (instance_type, instance_ami, ht_support, job_queue, spot_price)
                for item in t:
                    h.update(item.encode("utf-8"))
                job_id_hash = h.hexdigest()

            if ignore is False:
                if scaling_mode == "multiple_jobs":
                    job_id_order.append(job_id_hash)
                    job_order += 1
                    job_info = {
                        "get_job_id": job_id,
                        "get_job_instance_type": instance_type,
                        "get_job_ht_support": ht_support,
                        "get_job_spot_price": spot_price,
                        "get_job_id_hash": job_id_hash,
                        "get_job_queue_name": job_queue,
                        "get_job_owner": job_owner,
                        "get_job_state": job_state,
                        "get_execution_hosts": exec_vnode,
                        "get_job_name": job_data["Job_Name"],
                        "get_job_nodect": job_data["Resource_List"]["nodect"],
                        "get_job_ncpus": job_data["Resource_List"]["ncpus"],
                        "get_job_start_time": stime,
                        "get_job_start_time_epoch": stime_epoch,
                        "get_job_queue_time": job_data["qtime"],
                        "get_job_queue_time_epoch": (
                            datetime.strptime(job_data["qtime"], "%a %b %d %H:%M:%S %Y")
                        ).strftime("%s"),
                        "get_job_project": job_data["project"],
                        "get_job_submission_directory": job_data["Variable_List"][
                            "PBS_O_WORKDIR"
                        ],
                        "get_job_resource_list": job_data["Resource_List"],
                        "get_job_order_in_queue": job_order,
                        "get_job_terminate_when_idle": terminate_when_idle,
                    }
                    if job_id_hash in dict_output.keys():
                        dict_output[job_id_hash][job_id] = job_info
                    else:
                        dict_output[job_id_hash] = {job_id: job_info}
                else:
                    job_id_order.append(job_id)
                    job_order += 1
                    dict_output[job_id] = {
                        "get_job_id": job_id,
                        "get_job_queue_name": job_queue,
                        "get_job_owner": job_owner,
                        "get_job_state": job_state,
                        "get_execution_hosts": exec_vnode,
                        "get_job_name": job_data["Job_Name"],
                        "get_job_nodect": job_data["Resource_List"]["nodect"],
                        "get_job_ncpus": job_data["Resource_List"]["ncpus"],
                        "get_job_start_time": stime,
                        "get_job_start_time_epoch": stime_epoch,
                        "get_job_queue_time": job_data["qtime"],
                        "get_job_queue_time_epoch": (
                            datetime.strptime(job_data["qtime"], "%a %b %d %H:%M:%S %Y")
                        ).strftime("%s"),
                        "get_job_project": job_data["project"],
                        "get_job_submission_directory": job_data["Variable_List"][
                            "PBS_O_WORKDIR"
                        ],
                        "get_job_resource_list": job_data["Resource_List"],
                        "get_job_order_in_queue": job_order,
                    }
        except Exception as err:
            print(err)
            pass
    if arg.format == "json":
        table_output = dict_output
        print(json.dumps(table_output))
    else:
        if len(dict_output) == 0:
            print("INFO: No jobs detected.")
        else:
            if scaling_mode == "multiple_jobs":
                for job_hash in dict_output.keys():
                    for id in dict_output[job_hash]:
                        table_output.add_row(
                            [
                                dict_output[job_hash][id]["get_job_id"],
                                dict_output[job_hash][id]["get_job_instance_type"],
                                dict_output[job_hash][id]["get_job_ht_support"],
                                dict_output[job_hash][id]["get_job_spot_price"],
                                dict_output[job_hash][id]["get_job_queue_name"],
                                dict_output[job_hash][id]["get_job_owner"],
                                dict_output[job_hash][id]["get_job_state"],
                                dict_output[job_hash][id]["get_execution_hosts"],
                                dict_output[job_hash][id]["get_job_name"],
                                dict_output[job_hash][id]["get_job_nodect"],
                                dict_output[job_hash][id]["get_job_ncpus"],
                                dict_output[job_hash][id]["get_job_start_time"],
                                dict_output[job_hash][id]["get_job_queue_time"],
                                dict_output[job_hash][id]["get_job_id_hash"],
                                dict_output[job_hash][id][
                                    "get_job_terminate_when_idle"
                                ],
                            ]
                        )
            else:
                for id in job_id_order:
                    table_output.add_row(
                        [
                            dict_output[id]["get_job_id"],
                            dict_output[id]["get_job_queue_name"],
                            dict_output[id]["get_job_owner"],
                            dict_output[id]["get_job_state"],
                            dict_output[id]["get_execution_hosts"],
                            dict_output[id]["get_job_name"],
                            dict_output[id]["get_job_nodect"],
                            dict_output[id]["get_job_ncpus"],
                            dict_output[id]["get_job_start_time"],
                            dict_output[id]["get_job_queue_time"],
                        ]
                    )
            print(table_output)
