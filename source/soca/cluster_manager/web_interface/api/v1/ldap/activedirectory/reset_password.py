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

import re
import config
from flask_restful import Resource, reqparse
import logging
from decorators import private_api, admin_api
import json
import utils.aws.boto3_wrapper as utils_boto3
import os
import sys
from utils.response import SocaResponse
from utils.error import SocaError
import json

logger = logging.getLogger("soca_logger")


class Reset(Resource):
    @admin_api
    def post(self):
        """
        Change password for a given user
        ---
        tags:
          - User Management

        parameters:
          - in: body
            name: body
            schema:
              required:
                - user
                - password
              properties:
                user:
                  type: string
                  description: SOCA user
                password:
                  type: string
                  description: New password to configure

        responses:
          200:
            description: Pair of username/token is valid
          203:
            description: Invalid username/token pair
          400:
            description: Malformed client input
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="form")
        parser.add_argument("password", type=str, location="form")
        args = parser.parse_args()
        user = args["user"]
        password = args["password"]
        logger.info(f"Received AWS DS password reset request for {user} for directory service: {config.Config.DIRECTORY_SERVICE_ID}")
        if user.lower() in password.lower():
            return SocaError.IDENTITY_PROVIDER_ERROR(helper="Password cannot contain username").as_flask()
        ds_password_complexity = r"(?=^.{8,64}$)((?=.*\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[^A-Za-z0-9\s])(?=.*[a-z])|(?=.*[^A-Za-z0-9\s])(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[A-Z])(?=.*[^A-Za-z0-9\s]))^.*"
        if not re.search(ds_password_complexity, password):
            return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"Password does not meet the required complexity. Regex is {ds_password_complexity}").as_flask()

        lambda_client = utils_boto3.get_boto(service_name="lambda").message
        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        if password is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="password").as_flask()

        ds_password_reset_lambda_arn = config.Config.DIRECTORY_SERVICE_RESET_LAMBDA_ARN
        if not ds_password_reset_lambda_arn:
            return SocaError.IDENTITY_PROVIDER_ERROR(helper="Missing DIRECTORY_SERVICE_RESET_LAMBDA_ARN in config").as_flask()

        try:
            req = lambda_client.invoke(
                FunctionName=ds_password_reset_lambda_arn,
                Payload=json.dumps(
                    {
                        "Username": user,
                        "Password": password,
                        "DirectoryServiceId": config.Config.DIRECTORY_SERVICE_ID,
                    },
                    indent=2,
                ).encode("utf-8"),
            )

            _response = json.load(req['Payload'].decode("utf-8") if isinstance(req['Payload'], bytes) else req['Payload'])
            logger.info(f"Result Lambda Reset password: {_response}")
            if _response["success"] is True:
                return SocaResponse(success=True, message="Password updated correctly").as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"Unable to reset password due to {_response['message']}").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()
