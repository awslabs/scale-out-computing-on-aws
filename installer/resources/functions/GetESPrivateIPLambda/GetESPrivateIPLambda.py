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
import logging

"""
Get prefix list id
"""
logging.getLogger().setLevel(logging.INFO)


def lambda_handler(event, context):
    try:
        logging.info(f"event: {event}")
        requestType = event["RequestType"]
        if requestType == "Delete":
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, "")
            return
        ClusterId = event["ResourceProperties"]["ClusterId"]
        logging.info("ClusterId: " + ClusterId)
        ec2_client = boto3.client("ec2")
        response = ec2_client.describe_network_interfaces(
            Filters=[
                {"Name": "description", "Values": ["ES " + ClusterId]},
                {"Name": "requester-id", "Values": ["amazon-elasticsearch"]},
            ]
        )
        ipAddresses = []
        for networkInterface in response["NetworkInterfaces"]:
            logging.debug(networkInterface)
            az = networkInterface["AvailabilityZone"]
            logging.info("AZ: " + az)
            for privateIpAddress in networkInterface["PrivateIpAddresses"]:
                logging.debug(privateIpAddress)
                ipAddress = privateIpAddress["PrivateIpAddress"]
                logging.info("ipAddress:" + ipAddress)
                ipAddresses.append(ipAddress)
        if len(ipAddresses) == 0:
            msg = "No IP addresses found"
            logging.error(msg)
            cfnresponse.send(event, context, cfnresponse.FAILED, {"error": msg}, msg)
        else:
            ipAddressesStr = ",".join(ipAddresses)
            cfnresponse.send(
                event,
                context,
                cfnresponse.SUCCESS,
                {"IpAddresses": ipAddressesStr},
                str(ipAddresses),
            )
    except:
        logging.exception("Caught exception")
        error_message = (
            f"Exception getting private IP addresses for ES soca-{ClusterId}"
        )
        cfnresponse.send(
            event, context, cfnresponse.FAILED, {"error": error_message}, error_message
        )
