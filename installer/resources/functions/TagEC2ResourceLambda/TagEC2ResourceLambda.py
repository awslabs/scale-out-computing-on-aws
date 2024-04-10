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

import cfnresponse
import boto3
import json
import logging
import os

"""
Tag EC2 Resource
"""
logging.getLogger().setLevel(logging.INFO)


def lambda_handler(event, context):
    try:
        logging.info(f"event: {event}")
        resourceId = event["ResourceProperties"]["ResourceId"]
        logging.info(f"resourceId: {resourceId}")
        tags = event["ResourceProperties"]["Tags"]
        logging.info(f"tags: {tags}")

        ec2_client = boto3.client("ec2")
        ec2_client.create_tags(Resources=[resourceId], Tags=tags)
    except Exception as e:
        logging.exception("Unhandled exception")
        cfnresponse.send(event, context, cfnresponse.FAILED, {"error": str(e)}, str(e))

    cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, "")
