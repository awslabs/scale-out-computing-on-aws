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
import json
import sys
import boto3

sys.path.append(os.path.dirname(__file__))
from botocore import config as botocore_config
from opensearchpy import OpenSearch, RequestsHttpConnection
from opensearchpy.exceptions import NotFoundError as NotFoundError
from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
import datetime


def boto_extra_config():
    aws_solution_user_agent = {"user_agent_extra": "AwsSolution/SO0072/2.7.4"}
    return botocore_config.Config(**aws_solution_user_agent)


def get_soca_configuration():
    secretsmanager_client = boto3.client("secretsmanager", config=boto_extra_config())
    configuration_secret_name = os.environ["SOCA_CONFIGURATION"]
    response = secretsmanager_client.get_secret_value(
        SecretId=configuration_secret_name
    )
    return json.loads(response["SecretString"])


def retrieve_desktops(cluster_id):
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
            {"Name": "tag:soca:NodeType", "Values": ["dcv"]},
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

def build_client(engine):
    try:
        if engine == 'opensearch':
            return OpenSearch(
                [os_endpoint],
                http_auth=awsauth,
                use_ssl=True,
                verify_certs=True,
                ssl_assert_hostname=False,
                ssl_show_warn=False,
                connection_class=RequestsHttpConnection,
            )
        else:
            return Elasticsearch([os_endpoint],
                               port=443,
                               http_auth=awsauth,
                               use_ssl=True,
                               verify_certs=True,
                               connection_class=RequestsHttpConnection)

    except Exception as err:
        print(f"Unable to establish connection to  {os_endpoint} due to {err}")
        sys.exit(1)

if __name__ == "__main__":
    ec2_client = boto3.client("ec2", config=boto_extra_config())
    try:
        soca_configuration = get_soca_configuration()
    except Exception as err:
        print(f"Unable to retrieve SOCA configuration due to {err}")
        sys.exit(1)
    session = boto3.Session()
    credentials = session.get_credentials()
    awsauth = AWS4Auth(
        credentials.access_key,
        credentials.secret_key,
        session.region_name,
        "es",
        session_token=credentials.token,
    )
    os_endpoint = "https://" + soca_configuration["OSDomainEndpoint"]
    os_index_name = "soca_desktops"
    cluster_id = os.environ.get("SOCA_CONFIGURATION", None)
    if cluster_id is None:
        print(
            "SOCA_CONFIGURATION environment variable not found. Make sure to source /etc/environment before executing this script"
        )
        sys.exit(1)

    os_client = build_client(soca_configuration['AnalyticsEngine'])
    current_desktops = retrieve_desktops(cluster_id)

    if len(current_desktops) > 0:
        for desktop_data in current_desktops.values():
            try:
                add = os_client.index(index=os_index_name, body=desktop_data)
                if add["result"] != "created":
                    print(f"Unable to index {desktop_data} due to {add}")

            except Exception as err:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                print(
                    f"Error trying to add a new record to elasticsearch {desktop_data} due to {exc_type}  {exc_tb.tb_lineno} with error {err}"
                )
