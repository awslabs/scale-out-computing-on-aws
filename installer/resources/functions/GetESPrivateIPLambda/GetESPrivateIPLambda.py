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


ec2_client = boto3.client("ec2")


def lambda_handler(event, context):
    try:
        logging.info(f"event: {event}")
        request_type: str = event.get("RequestType", "")
        logging.info(f"Request Type: {request_type}")

        if request_type == "Delete":
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, "")
            return

        cluster_id: str = event.get("ResourceProperties", []).get("ClusterId", "")
        logging.info(f"ClusterId: {cluster_id}")

        if not cluster_id:
            msg = "ClusterId not provided"
            logging.error(msg)
            cfnresponse.send(event, context, cfnresponse.FAILED, {"error": msg}, msg)


        _ec2_paginator = ec2_client.get_paginator("describe_network_interfaces")
        _ec2_page_iterator = _ec2_paginator.paginate(
            Filters=[
                {"Name": "description", "Values": ["ES " + cluster_id]},
                {"Name": "requester-id", "Values": ["amazon-elasticsearch"]},
            ]
        )

        ip_addresses: list = []
        logging.info("Getting IP addresses")
        for response in _ec2_page_iterator:
            for networkInterface in response.get("NetworkInterfaces", []):
                logging.debug(networkInterface)

                az = networkInterface.get("AvailabilityZone", "")
                logging.info(f"AZ: {az}")
                if not az:
                    continue

                for private_ip_address in networkInterface.get("PrivateIpAddresses", []):
                    logging.debug(private_ip_address)
                    ip_address = private_ip_address.get("PrivateIpAddress", "")
                    logging.info(f"ipAddress: {ip_address}")
                    if ip_address not in ip_addresses:
                        ip_addresses.append(ip_address)


        if not ip_addresses:
            msg = "No IP addresses found"
            logging.error(msg)
            cfnresponse.send(event, context, cfnresponse.FAILED, {"error": msg}, msg)
        else:
            ip_addresses_str = ",".join(ip_addresses)
            cfnresponse.send(
                event,
                context,
                cfnresponse.SUCCESS,
                {"IpAddresses": ip_addresses_str},
                str(ip_addresses),
            )
    except:
        logging.exception("Caught exception")
        error_message = "Exception getting private IP addresses for ES"
        cfnresponse.send(
            event, context, cfnresponse.FAILED, {"error": error_message}, error_message
        )
