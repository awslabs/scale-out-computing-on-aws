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

import os
import subprocess
import sys
import datetime
import boto3
import pytz

sys.path.append(os.path.dirname(__file__))
import configuration
from ast import literal_eval


def run_command(cmd, cmd_type):
    try:
        if cmd_type == "check_output":
            command = subprocess.check_output(cmd)
            return literal_eval(command.decode("utf-8"))
        elif cmd_type == "call":
            command = subprocess.call(cmd)
            return command
        else:
            print("Command not Defined")
            exit(1)

    except subprocess.CalledProcessError as e:
        return ""


def get_all_compute_instances(cluster_id):
    job_stack = {}
    # ATTENTION /!\
    # CHANGING THIS FILTER COULD POSSIBLY BRING DOWN OTHER EC2 INSTANCES IN YOUR AWS ACCOUNT
    ec2_paginator = ec2_client.get_paginator("describe_instances")
    ec2_iterator = ec2_paginator.paginate(
        Filters=[
            {
                "Name": "instance-state-name",
                "Values": [
                    "running",
                ],
            },
            {"Name": "tag:soca:NodeType", "Values": ["soca-compute-node"]},
            {"Name": "tag:soca:KeepForever", "Values": ["true", "false"]},
            {"Name": "tag:soca:ClusterId", "Values": [cluster_id]},
        ],
    )

    for page in ec2_iterator:
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                try:
                    instance_id = instance["InstanceId"]
                    instance_type = instance["InstanceType"]
                    subnet_id = instance["SubnetId"]
                    availability_zone = instance["Placement"]["AvailabilityZone"]
                    job_id = [
                        x["Value"] for x in instance["Tags"] if x["Key"] == "soca:JobId"
                    ]
                    job_queue = [
                        x["Value"]
                        for x in instance["Tags"]
                        if x["Key"] == "soca:JobQueue"
                    ][0]
                    keep_forever = [
                        x["Value"]
                        for x in instance["Tags"]
                        if x["Key"] == "soca:KeepForever"
                    ][0]
                    terminate_when_idle = [
                        x["Value"]
                        for x in instance["Tags"]
                        if x["Key"] == "soca:TerminateWhenIdle"
                    ][0]
                    cloudformation_stack = ""
                    stack_id = ""
                    asg_spotfleet_id = ""
                    for x in instance["Tags"]:
                        if x["Key"] == "aws:cloudformation:stack-name":
                            cloudformation_stack = x["Value"]
                        if x["Key"] == "aws:autoscaling:groupName":
                            asg_spotfleet_id = x["Value"]
                        elif x["Key"] == "aws:ec2spot:fleet-request-id":
                            asg_spotfleet_id = x["Value"]
                        if x["Key"] == "soca:StackId":
                            stack_id = x["Value"]
                    if cloudformation_stack == "":
                        cloudformation_stack = stack_id
                    private_dns = instance["PrivateDnsName"].split(".")[0]

                    if not job_id:
                        job_id = "do_not_delete"
                    else:
                        job_id = job_id[0]

                    if job_id in job_stack.keys():
                        job_stack[job_id]["instances"][private_dns] = {
                            "instance_id": instance_id,
                            "instance_type": instance_type,
                            "subnet_id": subnet_id,
                            "availability_zone": availability_zone,
                        }
                    else:
                        host = {}
                        host[private_dns] = {
                            "instance_id": instance_id,
                            "instance_type": instance_type,
                            "subnet_id": subnet_id,
                            "availability_zone": availability_zone,
                        }

                        job_stack[job_id] = {
                            "stack_name": cloudformation_stack,
                            "terminate_when_idle": terminate_when_idle,
                            "asg_spotfleet_id": asg_spotfleet_id,
                            "keep_forever": keep_forever,
                            "instances": host,
                            "job_queue": job_queue,
                            "job_id": job_id,
                        }
                except Exception as e:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    print(exc_type, fname, exc_tb.tb_lineno)

    return job_stack


def get_scheduler_jobs_in_queue():
    qstat_args = " -f -F json"
    check_current_jobs = run_command(
        (sbins["qstat"] + qstat_args).split(), "check_output"
    )
    if "Jobs" in check_current_jobs.keys():
        job_ids = [job.split(".")[0] for job in check_current_jobs["Jobs"].keys()]
        return job_ids
    else:
        return []


def get_scheduler_all_nodes():
    pbsnodes_args = " -a -F json"
    pbs_hosts = []
    pbs_hosts_down = []
    pbs_hosts_free = {}
    pbs_hosts_offline = []
    try:
        pbsnodes_output = run_command(
            (sbins["pbsnodes"] + pbsnodes_args).split(), "check_output"
        )
        if "nodes" in pbsnodes_output.keys():
            for hostname, data in pbsnodes_output["nodes"].items():
                if "jobs" not in data.keys():
                    if "job-exclusive" not in str(data["state"]):
                        if "down" in str(data["state"]):
                            pbs_hosts_down.append(hostname)
                    if (
                        str(data["state"]) == "free"
                        and data["pcpus"] == data["resources_available"]["ncpus"]
                    ):
                        if "last_used_time" in data.keys():
                            pbs_hosts_free[hostname] = data["last_used_time"]
                        else:
                            # Automatically remove capacity after 15 mins if no job ran on it
                            pbs_hosts_free[hostname] = (
                                data["last_state_change_time"] + 900
                            )

                    if str(data["state"]) == "offline":
                        pbs_hosts_offline.append(hostname)
                pbs_hosts.append(hostname)
    except AttributeError as e:
        # Case when scheduler does not have any valid host
        pass
    except Exception as e:
        print(e)

    return {
        "pbs_hosts": pbs_hosts,
        "pbs_hosts_down": pbs_hosts_down,
        "pbs_hosts_free": pbs_hosts_free,
        "pbs_hosts_offline": pbs_hosts_offline,
    }


def delete_stack(stack_to_delete):
    for stack_name in stack_to_delete:
        print("Deleting " + stack_name)
        cloudformation_client.delete_stack(StackName=stack_name)


def delete_hosts(hosts):
    for host in hosts:
        cmd = [sbins["qmgr"], "-c", "delete node " + host]
        try:
            print("Running " + str(cmd))
            run_command(cmd, "call")
        except Exception as e:
            print("Error trying to run " + str(cmd) + " Error: " + str(e))


def add_hosts(hosts, compute_instances):
    for host in hosts:
        for k, v in compute_instances.items():
            if host in v["instances"].keys():
                host_asg_spotfleet_id = v["asg_spotfleet_id"]
                host_queue = v["job_queue"]
                host_job_id = v["job_id"]
                host_instance_id = v["instances"][host]["instance_id"]
                host_instance_type = v["instances"][host]["instance_type"]
                host_subnet_id = v["instances"][host]["subnet_id"]
                host_az = v["instances"][host]["availability_zone"]
                cmds = [
                    [
                        sbins["qmgr"],
                        "-c",
                        "create node " + host + "  queue=" + host_queue,
                    ],
                    [
                        sbins["qmgr"],
                        "-c",
                        "set node "
                        + host
                        + " resources_available.compute_node=job"
                        + host_job_id
                        + ",resources_available.instance_id="
                        + host_instance_id
                        + ",resources_available.asg_spotfleet_id="
                        + host_asg_spotfleet_id
                        + ",resources_available.instance_type="
                        + host_instance_type
                        + ",resources_available.availability_zone="
                        + host_az
                        + ",resources_available.subnet_id="
                        + host_subnet_id,
                    ],
                ]
                for cmd in cmds:
                    try:
                        print("Running " + str(cmd))
                        run_command(cmd, "call")
                    except Exception as e:
                        print("Error trying to run " + str(cmd) + " Error: " + str(e))


def set_hosts_offline(hosts):
    for host in hosts.keys():
        print(
            "Setting host: "
            + host
            + " offline as it has been idle for more than "
            + str(hosts[host])
            + " mins"
        )
        cmd = [sbins["qmgr"], "-c", "set node " + host + " state=offline"]
        try:
            print("Running " + str(cmd))
            run_command(cmd, "call")
        except Exception as e:
            print("Error trying to run " + str(cmd) + " Error: " + str(e))


def remove_offline_nodes_spotfleet(spotfleets):
    for spotfleet in spotfleets.keys():
        hosts_to_delete = []
        instances_to_delete = []
        instance_weighted_capacity = {}
        instance_weights = 0
        weighted_capacity = False
        new_target_capacity = 0
        response = ec2_client.describe_spot_fleet_requests(
            SpotFleetRequestIds=[spotfleet]
        )
        try:
            if (
                "WeightedCapacity"
                in response["SpotFleetRequestConfigs"][0]["SpotFleetRequestConfig"][
                    "LaunchTemplateConfigs"
                ][0]["Overrides"][0]
            ):
                weighted_capacity = True
                print("Found WeightedCapacity in SpotFleet")
                for item in response["SpotFleetRequestConfigs"][0][
                    "SpotFleetRequestConfig"
                ]["LaunchTemplateConfigs"][0]["Overrides"]:
                    instance_weighted_capacity[item["InstanceType"]] = item[
                        "WeightedCapacity"
                    ]
        except:
            weighted_capacity = False
        for x in spotfleets[spotfleet]:
            hosts_to_delete.append(x["host"])
            instances_to_delete.append(x["instance_id"])
            if weighted_capacity:
                instance_weights += int(instance_weighted_capacity[x["instance_type"]])

        fulfilled_capacity = int(
            response["SpotFleetRequestConfigs"][0]["SpotFleetRequestConfig"][
                "FulfilledCapacity"
            ]
        )
        target_capacity = int(
            response["SpotFleetRequestConfigs"][0]["SpotFleetRequestConfig"][
                "TargetCapacity"
            ]
        )
        now = pytz.utc.localize(datetime.datetime.utcnow())
        now_minus_ten_minutes = (now - datetime.timedelta(minutes=10)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        spot_fleet_history = ec2_client.describe_spot_fleet_request_history(
            SpotFleetRequestId=spotfleet,
            EventType="fleetRequestChange",
            StartTime=now_minus_ten_minutes,
            MaxResults=1,
        )
        try:
            spot_fleet_last_activity = spot_fleet_history["HistoryRecords"][0][
                "Timestamp"
            ]
            if now > (spot_fleet_last_activity + datetime.timedelta(minutes=4)):
                # SpotFleet likely has adjusted fulfilled capacity
                current_capacity = fulfilled_capacity
            else:
                # SpotFleet has not adjusted fulfilled capacity so need to use target_capacity to scale-down
                current_capacity = target_capacity
        except:
            # Couldn't find fleetRequestChange in the past 10 mins so use fulfilled_capacity
            current_capacity = fulfilled_capacity

        if weighted_capacity:
            total_capacity = instance_weights
            new_target_capacity = max(0, current_capacity - instance_weights)
        else:
            total_capacity = len(spotfleets[spotfleet])
            new_target_capacity = max(0, current_capacity - len(hosts_to_delete))

        if (new_target_capacity == 0) or (current_capacity == total_capacity):
            # TargetCapacity == Total capacity for this spotfleet. Delete the cloudformation stack
            resp = ec2_client.describe_spot_fleet_instances(
                SpotFleetRequestId=spotfleet
            )
            resp = ec2_client.describe_instances(
                InstanceIds=[resp["ActiveInstances"][0]["InstanceId"]]
            )
            for x in resp["Reservations"][0]["Instances"][0]["Tags"]:
                if x["Key"] == "soca:StackId":
                    cloudformation_stack = x["Value"]
            print("Terminating SpotFleet: " + spotfleet)
            delete_stack([cloudformation_stack])
            delete_hosts(hosts_to_delete)
        elif (
            response["SpotFleetRequestConfigs"][0]["SpotFleetRequestState"] == "active"
        ):
            delete_hosts(hosts_to_delete)
            print("Terminating instances " + ", ".join(instances_to_delete))
            resp = ec2_client.terminate_instances(InstanceIds=instances_to_delete)
            print(
                "Updating TargetCapacity for SpotFleet: "
                + spotfleet
                + " to: "
                + str(new_target_capacity)
            )
            resp = ec2_client.modify_spot_fleet_request(
                SpotFleetRequestId=spotfleet, TargetCapacity=new_target_capacity
            )


def remove_offline_nodes_asg(asgs):
    for asg in asgs.keys():
        hosts_to_delete = []
        instances_to_delete = []
        instance_weighted_capacity = {}
        instance_weights = 0
        weighted_capacity = False
        new_target_capacity = 0
        response = autoscaling_client.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg], MaxRecords=100
        )
        try:
            if (
                "WeightedCapacity"
                in response["AutoScalingGroups"][0]["MixedInstancesPolicy"][
                    "LaunchTemplate"
                ]["Overrides"][0]
            ):
                weighted_capacity = True
                print("Found WeightedCapacity in ASG")
                for item in response["AutoScalingGroups"][0]["MixedInstancesPolicy"][
                    "LaunchTemplate"
                ]["Overrides"]:
                    instance_weighted_capacity[item["InstanceType"]] = item[
                        "WeightedCapacity"
                    ]
        except:
            weighted_capacity = False
        for x in asgs[asg]:
            hosts_to_delete.append(x["host"])
            instances_to_delete.append(x["instance_id"])
            if weighted_capacity:
                instance_weights += int(instance_weighted_capacity[x["instance_type"]])

        if weighted_capacity:
            total_capacity = instance_weights
            new_target_capacity = max(
                0,
                int(response["AutoScalingGroups"][0]["DesiredCapacity"])
                - instance_weights,
            )
        else:
            total_capacity = len(asgs[asg])
            new_target_capacity = max(
                0,
                int(response["AutoScalingGroups"][0]["DesiredCapacity"])
                - len(hosts_to_delete),
            )

        if (new_target_capacity == 0) or (
            int(response["AutoScalingGroups"][0]["DesiredCapacity"]) == total_capacity
        ):
            # DesiredCapacity == Total capacity for this asg. Delete the cloudformation stack
            resp = ec2_client.describe_instances(
                InstanceIds=[
                    response["AutoScalingGroups"][0]["Instances"][0]["InstanceId"]
                ]
            )
            for x in resp["Reservations"][0]["Instances"][0]["Tags"]:
                if x["Key"] == "aws:cloudformation:stack-name":
                    cloudformation_stack = x["Value"]
            delete_stack([cloudformation_stack])
            delete_hosts(hosts_to_delete)
        else:
            print(
                "Updating DesiredCapacity for ASG: "
                + asg
                + " to: "
                + str(new_target_capacity)
            )
            resp = autoscaling_client.update_auto_scaling_group(
                AutoScalingGroupName=asg,
                MinSize=new_target_capacity,
                MaxSize=new_target_capacity,
                DesiredCapacity=new_target_capacity,
            )
            resp = autoscaling_client.detach_instances(
                AutoScalingGroupName=asg,
                InstanceIds=instances_to_delete,
                ShouldDecrementDesiredCapacity=False,
            )
            delete_hosts(hosts_to_delete)
            print("Terminating instances " + ", ".join(instances_to_delete))
            resp = ec2_client.terminate_instances(InstanceIds=instances_to_delete)


def remove_offline_nodes(hosts):
    asgs = {}
    spotfleets = {}
    for host in hosts:
        asg_spotfleet_id = (
            subprocess.check_output(
                "qmgr -c 'print node "
                + str(host)
                + "' | grep asg_spotfleet_id | awk '{print $NF}'",
                shell=True,
            )
            .decode("utf-8")
            .strip()
        )  # nosec
        instance_id = (
            subprocess.check_output(
                "qmgr -c 'print node "
                + str(host)
                + "' | grep instance_id | awk '{print $NF}'",
                shell=True,
            )
            .decode("utf-8")
            .strip()
        )  # nosec
        instance_type = (
            subprocess.check_output(
                "qmgr -c 'print node "
                + str(host)
                + "' | grep instance_type | awk '{print $NF}'",
                shell=True,
            )
            .decode("utf-8")
            .strip()
        )  # nosec
        if asg_spotfleet_id.startswith("sfr-"):
            if asg_spotfleet_id not in spotfleets:
                spotfleets[asg_spotfleet_id] = []
            spotfleets[asg_spotfleet_id].append(
                {
                    "host": host,
                    "instance_id": instance_id,
                    "instance_type": instance_type,
                }
            )
        elif asg_spotfleet_id.startswith("soca-"):
            if asg_spotfleet_id not in asgs:
                asgs[asg_spotfleet_id] = []
            asgs[asg_spotfleet_id].append(
                {
                    "host": host,
                    "instance_id": instance_id,
                    "instance_type": instance_type,
                }
            )

    remove_offline_nodes_spotfleet(spotfleets)
    remove_offline_nodes_asg(asgs)


if __name__ == "__main__":
    print(
        "\nStarting at: " + str(datetime.datetime.now().strftime("%b-%d-%Y %H:%M:%S"))
    )
    soca_configuration = configuration.get_soca_configuration()
    ec2_client = boto3.client("ec2", config=configuration.boto_extra_config())
    cloudformation_client = boto3.client(
        "cloudformation", config=configuration.boto_extra_config()
    )
    autoscaling_client = boto3.client(
        "autoscaling", config=configuration.boto_extra_config()
    )

    sbins = {
        "qstat": "/opt/pbs/bin/qstat",
        "qmgr": "/opt/pbs/bin/qmgr",
        "pbsnodes": "/opt/pbs/bin/pbsnodes",
    }

    # 1 - get all running EC2 instances
    compute_instances = get_all_compute_instances(soca_configuration["ClusterId"])
    # Get all current instances private DNS
    current_ec2_compute_nodes_dns = [
        item
        for sublist in [v["instances"] for k, v in compute_instances.items()]
        for item in sublist
    ]

    # 2 - get a list of all job ids in the queue
    scheduler_jobs_in_queue = get_scheduler_jobs_in_queue()

    # 3 - Get all pbsnodes

    all_nodes = get_scheduler_all_nodes()
    pbs_nodes = all_nodes["pbs_hosts"]
    pbs_nodes_down = all_nodes["pbs_hosts_down"]
    pbs_nodes_free = all_nodes["pbs_hosts_free"]
    pbs_nodes_offline = all_nodes["pbs_hosts_offline"]
    cloudformation_stack_to_delete = []

    compute_nodes_to_set_offline = {}
    compute_hosts_to_delete = []
    for job_id, stack_data in compute_instances.items():
        if (
            stack_data["keep_forever"] == "false"
            and stack_data["terminate_when_idle"] == "0"
        ):
            if job_id not in scheduler_jobs_in_queue:
                print(job_id + " NOT IN QUEUE. CAN KILL")
                cloudformation_stack_to_delete.append(stack_data["stack_name"])
                for host in stack_data["instances"]:
                    compute_hosts_to_delete.append(host)
        if int(stack_data["terminate_when_idle"]) > 0:
            for host in stack_data["instances"]:
                if host in pbs_nodes_free.keys():
                    print(
                        "Found idle host: "
                        + str(host)
                        + " now: "
                        + str(int(datetime.datetime.now().timestamp()))
                        + " last_used_time: "
                        + str(pbs_nodes_free[host])
                        + " terminate_when_idle: "
                        + str(int(stack_data["terminate_when_idle"]) * 60)
                    )
                    if (
                        datetime.datetime.now().timestamp()
                        > pbs_nodes_free[host]
                        + int(stack_data["terminate_when_idle"]) * 60
                    ):
                        compute_nodes_to_set_offline[host] = stack_data[
                            "terminate_when_idle"
                        ]
                        pbs_nodes_offline.append(host)
                        # If the ASG/SpotFleet has a single host, then delete the cloudformation stack
                        if stack_data["asg_spotfleet_id"].startswith("sfr-"):
                            response = ec2_client.describe_spot_fleet_instances(
                                SpotFleetRequestId=stack_data["asg_spotfleet_id"],
                                MaxResults=1000,
                            )
                            if len(response["ActiveInstances"]) == 1:
                                cloudformation_stack_to_delete.append(
                                    stack_data["stack_name"]
                                )
                                compute_hosts_to_delete.append(host)
                        elif stack_data["asg_spotfleet_id"].startswith("soca-"):
                            response = autoscaling_client.describe_auto_scaling_groups(
                                AutoScalingGroupNames=[stack_data["asg_spotfleet_id"]],
                                MaxRecords=100,
                            )
                            if response["AutoScalingGroups"][0]["DesiredCapacity"] == 1:
                                cloudformation_stack_to_delete.append(
                                    stack_data["stack_name"]
                                )
                                compute_hosts_to_delete.append(host)

    if compute_nodes_to_set_offline.__len__() > 0:
        set_hosts_offline(compute_nodes_to_set_offline)

    if pbs_nodes_offline.__len__() > 0:
        remove_offline_nodes(pbs_nodes_offline)

    if cloudformation_stack_to_delete.__len__() > 0:
        delete_stack(cloudformation_stack_to_delete)
        delete_hosts(compute_hosts_to_delete)

    # Now clean any hosts on pbs_nodes IN DOWN STATE, not serving jobs and not in current_ec2_compute_nodes_dns (mostly KeepForever instance we previously deleted)
    legacy_host_to_delete = list(
        set(pbs_nodes_down) - set(current_ec2_compute_nodes_dns)
    )

    if legacy_host_to_delete.__len__() > 0:
        print("need to qmgr delete legacy")
        print(legacy_host_to_delete)
        delete_hosts(legacy_host_to_delete)

    compute_nodes_to_add = list(
        (set(current_ec2_compute_nodes_dns) - set(pbs_nodes))
        - set(compute_hosts_to_delete)
    )

    if compute_nodes_to_add.__len__() > 0:
        print(f"need to qmgr add {compute_nodes_to_add}")
        add_hosts(compute_nodes_to_add, compute_instances)
