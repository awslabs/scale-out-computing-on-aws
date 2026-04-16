# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import cfnresponse
import boto3
import logging
import time

"""
Custom Resource Lambda to launch EC2 instances with NestedVirtualization enabled.
CloudFormation does not support CpuOptions.NestedVirtualization, so this Lambda
calls RunInstances directly with the full CpuOptions specification.
"""

logging.getLogger().setLevel(logging.INFO)
logging.info(f"boto3 version: {boto3.__version__}")
ec2 = boto3.client("ec2")


def lambda_handler(event, context):
    try:
        logging.info(f"event: {event}")
        request_type = event["RequestType"]
        props = event["ResourceProperties"]

        if request_type == "Delete":
            # Terminate instances tagged by this stack
            instance_ids = _get_stack_instances(props["StackName"])
            if instance_ids:
                logging.info(f"Terminating instances: {instance_ids}")
                ec2.terminate_instances(InstanceIds=instance_ids)
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {})
            return

        if request_type in ("Create", "Update"):
            lt_id = props["LaunchTemplateId"]
            lt_version = props["LaunchTemplateVersion"]
            node_count = int(props["NodeCount"])
            instance_types = props["InstanceTypes"]
            stack_name = props["StackName"]

            # Build CpuOptions with nested virtualization
            cpu_options = {"NestedVirtualization": "enabled"}
            if props.get("CoreCount"):
                cpu_options["CoreCount"] = int(props["CoreCount"])
            if props.get("ThreadsPerCore"):
                cpu_options["ThreadsPerCore"] = int(props["ThreadsPerCore"])

            resp = ec2.run_instances(
                LaunchTemplate={"LaunchTemplateId": lt_id, "Version": lt_version},
                InstanceType=instance_types[0],
                MinCount=node_count,
                MaxCount=node_count,
                CpuOptions=cpu_options,
                TagSpecifications=[
                    {
                        "ResourceType": "instance",
                        "Tags": [{"Key": "soca:NestedVirtStack", "Value": stack_name}],
                    }
                ],
            )
            all_instance_ids = [i["InstanceId"] for i in resp["Instances"]]
            logging.info(f"Launched {len(all_instance_ids)} instances: {all_instance_ids}")

            cfnresponse.send(
                event,
                context,
                cfnresponse.SUCCESS,
                {"InstanceIds": ",".join(all_instance_ids)},
                ",".join(all_instance_ids),
            )
            return

    except Exception as e:
        logging.exception("Unhandled exception")
        cfnresponse.send(event, context, cfnresponse.FAILED, {"error": str(e)}, str(e))


def _get_stack_instances(stack_name):
    """Find instances tagged with this stack name."""
    resp = ec2.describe_instances(
        Filters=[
            {"Name": "tag:soca:NestedVirtStack", "Values": [stack_name]},
            {"Name": "instance-state-name", "Values": ["pending", "running", "stopping", "stopped"]},
        ]
    )
    ids = []
    for r in resp.get("Reservations", []):
        for i in r.get("Instances", []):
            ids.append(i["InstanceId"])
    return ids
