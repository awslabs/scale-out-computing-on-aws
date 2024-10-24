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


from flask_restful import Resource, reqparse
from flask import request
import logging
from decorators import private_api
import errors
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.ssm_parameter_store import SocaConfig
from utils.error import SocaError

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class ListLoginNodes(Resource):
    @private_api
    def get(self):
        """
        List all Login Nodes IP
        ---
        tags:
          - LoginNodes

        responses:
          200:
            description: Pair of user/token is valid
          401:
            description: Invalid user/token pair
        """
        logger.debug("Fetching all Login Nodes IPs for your SOCA environment")
        user = request.headers.get("X-SOCA-USER")
        if user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        login_nodes = []

        ec2_paginator = client_ec2.get_paginator("describe_instances")
        ec2_iterator = ec2_paginator.paginate(
            Filters=[
                {"Name": "tag:soca:NodeType", "Values": ["LoginNode"]},
                {"Name": "instance-state-name", "Values": ["running"]},
                {
                    "Name": "tag:soca:ClusterId",
                    "Values": [
                        SocaConfig(key="/configuration/ClusterId")
                        .get_value()
                        .get("message")
                    ],
                },
            ],
        )

        for page in ec2_iterator:
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    logger.debug(f"Found Login Node instance {instance}")
                    _public_ip = instance.get("PublicIpAddress", None)
                    _private_ip = instance.get("PrivateIpAddress")
                    login_nodes.append(_public_ip if _public_ip else _private_ip)
        logger.debug(f"Login nodes list: {login_nodes}")
        return {"success": True, "message": login_nodes}, 200
