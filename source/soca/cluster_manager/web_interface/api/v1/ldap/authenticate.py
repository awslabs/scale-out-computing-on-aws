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
import sys
import os
from decorators import private_api
import logging
from utils.error import SocaError
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.response import SocaResponse
import pathlib
import config
from api.v1.ldap.user import create_home

logger = logging.getLogger("soca_logger")


class Authenticate(Resource):
    @private_api
    def post(self):
        """
        Validate an LDAP user/password
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
            description: The Pair of user/token is valid
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

        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        if password is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="password").as_flask()

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            # note: we can pass user as just username or entire base_dn. SocaIdentityProvider will automatically update it
            _user_bind = _soca_identity_client.bind_as_user(dn=user, password=password)
            if _user_bind.success:
                logger.info(f"Successful Login for {user}, checking if user has a valid SOCA home ...")
                _home_dir = pathlib.Path(f"{config.Config.USER_HOME}/{user}")
                if _home_dir.exists():
                    logger.info(f"{_home_dir} already exist.")
                else:
                    # Handle case where user login from external AD/LDAP and user was not specifically created by SOCA
                    logger.info(f"{_home_dir} does not already exist, creating it ...")
                    # Search for the pattern in the provided DN
                    create_home(username=user.split(",")[0].split("=")[-1], group=f"{user}{config.Config.DIRECTORY_GROUP_NAME_SUFFIX}")

            return SocaResponse(
                success=_user_bind.success, message=_user_bind.message
            ).as_flask()


        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()
