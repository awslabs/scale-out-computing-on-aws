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
from base64 import b64encode as encode
from email.utils import parseaddr
import config
import ldap
from flask_restful import Resource, reqparse
from requests import get
import json
import logging
from decorators import private_api, admin_api
from flask import session
import ldap.modlist as modlist
from datetime import datetime
import errors
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.response import SocaResponse
from utils.error import SocaError
import os
import sys
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

        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()
        if password is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="password").as_flask()

        dn_user = f"uid={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}"
        enc_passwd = bytes(password, "utf-8")
        salt = os.urandom(16)
        sha = hashlib.sha1(enc_passwd)  # nosec
        sha.update(salt)
        digest = sha.digest()
        b64_envelop = encode(digest + salt)
        passwd = "{{SSHA}}{}".format(b64_envelop.decode("utf-8"))
        new_value = passwd
        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            mod_attrs = [(ldap.MOD_REPLACE, "userPassword", new_value.encode("utf-8"))]
            _update = _soca_identity_client.modify(dn=dn_user, mod_list=mod_attrs)
            if _update.success:
                return SocaResponse(success=True, message="Password updated correctly").as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"Unable to reset password for {user} because {_update.message}").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()
