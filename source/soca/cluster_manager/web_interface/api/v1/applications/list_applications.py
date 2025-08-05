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
import utils.aws.boto3_wrapper as utils_boto3
from utils.response import SocaResponse
from utils.error import SocaError
from decorators import admin_api
from models import ApplicationProfiles

logger = logging.getLogger("soca_logger")


budgets_client = utils_boto3.get_boto(service_name="budgets").message
sts_client = utils_boto3.get_boto(service_name="sts").message


class Applications(Resource):
    @staticmethod
    @admin_api
    def get():
        """
        Get application profiles
        ---
        openapi: 3.1.0
        operationId: listApplications
        tags:
          - Applications
        summary: Get application profiles
        description: Retrieves all application profiles (admin access required)
        parameters:
          - in: header
            name: X-SOCA-USER
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 100
              pattern: '^[a-zA-Z0-9._-]+$'
            description: SOCA username for authentication (must be admin)
            example: "admin.user"
          - in: header
            name: X-SOCA-TOKEN
            required: true
            schema:
              type: string
              minLength: 10
              maxLength: 1000
            description: SOCA authentication token
            example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        responses:
          '200':
            description: Application profiles retrieved successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: object
                      additionalProperties:
                        type: object
                        properties:
                          id:
                            type: integer
                            example: 1
                          profile_name:
                            type: string
                            example: "ANSYS Fluent"
                          created_by:
                            type: string
                            example: "admin"
                          profile_form:
                            type: string
                            example: "<form>...</form>"
                          profile_job:
                            type: string
                            example: "#!/bin/bash\n..."
                          profile_interpreter:
                            type: string
                            example: "bash"
                          profile_thumbnail:
                            type: string
                            example: "data:image/png;base64,..."
                          acl_allowed_users:
                            type: string
                            example: "user1,user2"
                          acl_restricted_users:
                            type: string
                            example: "restricted_user"
                          created_on:
                            type: string
                            format: date-time
                            example: "2024-01-15T10:30:00Z"
                          deactivated_on:
                            type: string
                            format: date-time
                            nullable: true
                            example: null
          '403':
            description: Insufficient permissions
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 403
                    message:
                      type: string
                      example: "Admin access required"
          '500':
            description: Server error
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Error retrieving applications profile list, check logs for more details."
        """
        try:
            _application_profiles = {}
            get_all_application_profiles = ApplicationProfiles.query.all()
            for profile in get_all_application_profiles:
                _application_profiles[profile.id] = profile.as_dict()

            return SocaResponse(success=True, message=_application_profiles).as_flask()

        except Exception as e:
            logger.error(f"Error retrieving application profile list: {str(e)}")
            return SocaError.GENERIC_ERROR(
                helper=f"Error retrieving applications profile list, check logs for more details."
            ).as_flask()