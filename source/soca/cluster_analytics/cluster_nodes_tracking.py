#!/usr/bin/python
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

import sys
import subprocess
import json
import boto3
from opensearchpy import OpenSearch, RequestsHttpConnection
from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
import pytz
import datetime
import os
from botocore import config as botocore_config


def boto_extra_config():
    aws_solution_user_agent = {"user_agent_extra": "AwsSolution/SO0072/__VERSION__"}
    return botocore_config.Config(**aws_solution_user_agent)


def get_soca_configuration():
    secretsmanager_client = boto3.client("secretsmanager", config=boto_extra_config())
    configuration_secret_name = os.environ["SOCA_CONFIGURATION"]
    response = secretsmanager_client.get_secret_value(
        SecretId=configuration_secret_name
    )
    return json.loads(response["SecretString"])


def os_index_new_item(body, os_index_name):
    add = os_client.index(index=os_index_name, body=body)
    print(add)
    if add["result"] == "created":
        return True
    else:
        return False


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
    try:
        soca_configuration = get_soca_configuration()
    except Exception as err:
        print(f"Unable to retrieve SOCA configuration due to {err}")
        sys.exit(1)

    commands = {"pbsnodes": "/opt/pbs/bin/pbsnodes", "pbsnodes_args": " -a -F json"}
    tz = pytz.timezone("America/Los_Angeles")
    os_endpoint = "https://" + soca_configuration["OSDomainEndpoint"]
    session = boto3.Session()
    credentials = session.get_credentials()
    awsauth = AWS4Auth(
        credentials.access_key,
        credentials.secret_key,
        session.region_name,
        "es",
        session_token=credentials.token,
    )
    os_index_name = "soca_nodes"
    os_client = build_client(soca_configuration['AnalyticsEngine'])
    try:
        command = subprocess.Popen(
            (commands["pbsnodes"] + commands["pbsnodes_args"]).split(),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        stdout, stderr = command.communicate()
        if "pbsnodes: Server has no node list" in stdout.decode("utf-8"):
            exit(0)
        else:
            pbsnodes_output = json.loads(stdout)
    except subprocess.CalledProcessError as e:
        print(f"CalledProcessError: {e}")
        exit(1)
    except Exception as e:
        print(f"Unknown Error: {e}")
        exit(1)

    timestamp = pbsnodes_output["timestamp"]
    for hostname, data in pbsnodes_output["nodes"].items():
        data["timestamp"] = datetime.datetime.fromtimestamp(timestamp, tz).isoformat()

        if os_index_new_item(json.dumps(data), os_index_name) is False:
            print(f"Error while indexing {data}")
        else:
            print(f"Indexed {data}")
