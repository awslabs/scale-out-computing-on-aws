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
import logging
from decorators import admin_api, restricted_api, private_api
from models import db, VirtualDesktopProfiles, SoftwareStacks, Projects
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class ProjectsByUser(Resource):

    @private_api
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="args")
        args = parser.parse_args()

        _projects_for_user = {}
        _user = args["user"]
        if _user is None:
            SocaError.CLIENT_MISSING_PARAMETER(parameter=_user).as_flask()

        for _project in Projects.query.filter_by(is_active=True).all():
            _allowed_users = [
                item.strip() for item in _project.allowed_users.split(",")
            ]

            project_data = _project.as_dict()

            if "*" in _allowed_users or _user in _allowed_users:
                project_data["software_stack_ids"] = [
                    stack.id for stack in _project.software_stacks
                ]
                _projects_for_user[_project.id] = project_data

        return SocaResponse(success=True, message=_projects_for_user).as_flask()
