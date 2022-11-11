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

import logging

import config
import errors
import ldap
from decorators import private_api
from flask_restful import Resource, reqparse

logger = logging.getLogger("api")


class Authenticate(Resource):
    @private_api
    def post(self):
        """
        Validate a LDAP user/password
        ---
        tags:
          - LDAP management

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
                token:
                  type: string
                  description: Token associated to the user

        responses:
          200:
            description: Pair of user/token is valid
          210:
            description: Invalid user/token pair
          400:
            description: Client error
          401:
            description: Un-authorized
          500:
            description: Backend error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="form")
        parser.add_argument("password", type=str, location="form")
        args = parser.parse_args()
        user = args["user"]
        password = args["password"]
        if user is None or password is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "user (str) and password (str) are required.")

        try:
            logger.info(f"Received authentication request for {user}")
            conn = ldap.initialize(f"ldap://{config.Config.DOMAIN_NAME}")
            conn.simple_bind_s(f"{user}@{config.Config.DOMAIN_NAME}", password)
            logger.info(f"Auth success")
            return {"success": True, "message": "User is valid"}, 200
        except Exception as err:
            logger.info(f"Auth failed")
            return errors.all_errors(type(err).__name__, err)
