# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import sys
import datetime
from utils.aws.ssm_parameter_store import SocaConfig
from utils.aws.boto3_wrapper import get_boto
from utils.analytics_client import SocaAnalyticsClient
from utils.logger import SocaLogger


def retrieve_desktops(cluster_id: str) -> dict:
    desktop_information = {}

    ec2_paginator = ec2_client.get_paginator("describe_instances")
    ec2_iterator = ec2_paginator.paginate(
        Filters=[
            {
                "Name": "instance-state-name",
                "Values": [
                    "pending",
                    "running",
                    "shutting-down",
                    "stopping",
                    "stopped",
                ],
            },
            {"Name": "tag:soca:NodeType", "Values": ["dcv_node"]},
            {"Name": "tag:soca:ClusterId", "Values": [cluster_id]},
        ],
    )

    for page in ec2_iterator:
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                desktop_information[instance["InstanceId"]] = {}
                desktop_information[instance["InstanceId"]][
                    "soca_cluster_id"
                ] = cluster_id
                desktop_information[instance["InstanceId"]][
                    "desktop_uuid"
                ] = f"{instance['InstanceId']}_{cluster_id}"
                desktop_information[instance["InstanceId"]][
                    "timestamp"
                ] = datetime.datetime.now().isoformat()

                # Add all tags as top level value
                for tag in instance["Tags"]:
                    desktop_information[instance["InstanceId"]][tag["Key"]] = tag[
                        "Value"
                    ]

                # Add all desktop info to Analytics
                # https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/ec2.html#EC2.Client.describe_instances
                for k, v in instance.items():
                    if k != "Tags":
                        desktop_information[instance["InstanceId"]][k] = v

    return desktop_information


if __name__ == "__main__":
    ec2_client = get_boto(service_name="ec2").message
    _index_name = "soca_desktops"
    _cluster_id = SocaConfig(key="/configuration/ClusterId").get_value().message
    _log_file_location = f"/opt/soca/{_cluster_id}/cluster_manager/analytics/logs/desktop_hosts_tracking.log"
    logger = SocaLogger(name="analytics_desktop_hosts_tracking").rotating_file_handler(
        file_path=_log_file_location
    )

    logger.info(f"Tracking active SOCA Virtual Desktops . Log: {_log_file_location}")

    _analytics_client = SocaAnalyticsClient(
        endpoint=SocaConfig(key="/configuration/Analytics/endpoint")
        .get_value()
        .get("message"),
        engine=SocaConfig(key="/configuration/Analytics/engine")
        .get_value()
        .get("message"),
    )

    if _analytics_client.is_enabled().success is False:
        logger.info("Analytics is not enabled, exiting")
        sys.exit(1)
    else:
        _analytics_client.initialize()
        logger.info("Analytics client initialized")

    _current_desktops = retrieve_desktops(cluster_id=_cluster_id)

    if len(_current_desktops) > 0:
        for desktop_data in _current_desktops.values():
            _index_data = _analytics_client.index(index=_index_name, body=desktop_data)
            if _index_data.success:
                logger.info(f"RECORD INDEXED SUCCESSFULLY > {desktop_data}")
            else:
                logger.error(f"Error while indexing {desktop_data}")
    else:
        logger.info("No active SOCA Virtual Desktops found")
