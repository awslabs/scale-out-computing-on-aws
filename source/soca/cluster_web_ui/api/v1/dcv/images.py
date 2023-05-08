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

import config
from flask_restful import Resource
import logging
from decorators import admin_api, restricted_api, private_api
from models import db, AmiList
import boto3

logger = logging.getLogger("api")
session = boto3.session.Session()
aws_region = session.region_name
ec2_client = boto3.client("ec2", aws_region, config=config.boto_extra_config())


class ListImages(Resource):
    @admin_api
    def get(self):
        """
        List all EC2 AMI registered as DCV images on SOCA
        ---
        tags:
          - DCV
        responses:
          200:
            description: Pair of user/token is valid
          203:
            description: Invalid user/token pair
          400:
            description: Malformed client input
        """

        ami_info = {}
        for session_info in AmiList.query.filter_by(is_active=True).all():
            ami_info[session_info.ami_label] = session_info.ami_id
        return {"success": True, "message": ami_info}, 200
