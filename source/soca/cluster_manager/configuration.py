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

import boto3
import os
import json
from botocore import config as botocore_config


def boto_extra_config():
    aws_solution_user_agent = {"user_agent_extra": "AwsSolution/SO0072/2.7.4"}
    return botocore_config.Config(**aws_solution_user_agent)


def get_soca_configuration():
    """
    Return general configuration parameter
    """
    secretsmanager_client = boto3.client("secretsmanager", config=boto_extra_config())
    configuration_secret_name = os.environ["SOCA_CONFIGURATION"]
    response = secretsmanager_client.get_secret_value(
        SecretId=configuration_secret_name
    )
    return json.loads(response["SecretString"], strict=False)


def return_desktop_queues():
    """
    List of queued dedicated to DCV.
    These queues do not have any compute_node mapping and multiple PBS jobs can land on the same hardware
    """
    return ["desktop"]
