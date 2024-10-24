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

from flask_restful import Resource
import logging
from decorators import admin_api, restricted_api, private_api
from models import db, AmiList
from utils.response import SocaResponse
logger = logging.getLogger("soca_logger")


class ListImages(Resource):
    @admin_api
    def get(self):
        """
        List all EC2 AMI (Windows or Linux) registered as DCV images on SOCA
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
        logger.debug("List all DCV Images available")
        for session_info in AmiList.query.filter_by(is_active=True).all():
            ami_info[session_info.ami_label] = {
                "ami_id": session_info.ami_id,
                "ami_type": session_info.ami_type,
                "ami_arch": session_info.ami_arch,
                "ami_root_disk_size": session_info.ami_root_disk_size,
                "created_on": str(session_info.created_on)
            }
        if not ami_info:
            logger.warning("No AMI found")
        logger.debug(f"All AMIs: {ami_info}")
        return SocaResponse(success=True, message=ami_info).as_flask()
