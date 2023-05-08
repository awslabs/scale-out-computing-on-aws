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

import hashlib
import os
import re
import config
from flask_restful import Resource, reqparse
import logging
from decorators import private_api, admin_api
import errors
import boto3
import json

logger = logging.getLogger("api")


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
        logger.info(f"Received password reset request for {user}")
        if user.lower() in password.lower():
            return errors.all_errors("DS_PASSWORD_USERNAME_IN_PW")
        ds_password_complexity = r"(?=^.{8,64}$)((?=.*\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[^A-Za-z0-9\s])(?=.*[a-z])|(?=.*[^A-Za-z0-9\s])(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[A-Z])(?=.*[^A-Za-z0-9\s]))^.*"
        if not re.search(ds_password_complexity, password):
            return errors.all_errors("DS_PASSWORD_COMPLEXITY_ERROR")
        lambda_client = boto3.client("lambda", config=config.boto_extra_config())
        if user is None or password is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER",
                "user (str) and password (str) parameters are required",
            )

        ds_password_reset_lambda_arn = config.Config.DIRECTORY_SERVICE_RESET_LAMBDA_ARN
        if not ds_password_reset_lambda_arn:
            return errors.all_errors("MISSING_DS_RESET_LAMBDA")

        try:
            response = lambda_client.invoke(
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
            logger.info(str(response["Payload"].read()))
            return {"success": True, "message": "Password updated correctly."}, 200

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)
