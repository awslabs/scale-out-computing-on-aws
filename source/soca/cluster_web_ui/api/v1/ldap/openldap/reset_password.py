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
import json
import logging
import os
from base64 import b64encode as encode
from datetime import datetime
from email.utils import parseaddr

import config
import errors
import ldap
import ldap.modlist as modlist
from decorators import admin_api, private_api
from flask import session
from flask_restful import Resource, reqparse
from requests import get

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
        if user is None or password is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER", "user (str) and password (str) parameters are required"
            )

        dn_user = "uid=" + user + ",ou=people," + config.Config.LDAP_BASE_DN
        enc_passwd = bytes(password, "utf-8")
        salt = os.urandom(16)
        sha = hashlib.sha1(enc_passwd)  # nosec
        sha.update(salt)
        digest = sha.digest()
        b64_envelop = encode(digest + salt)
        passwd = "{{SSHA}}{}".format(b64_envelop.decode("utf-8"))
        new_value = passwd
        try:
            conn = ldap.initialize("ldap://" + config.Config.LDAP_HOST)
            conn.simple_bind_s(config.Config.ROOT_DN, config.Config.ROOT_PW)
            mod_attrs = [(ldap.MOD_REPLACE, "userPassword", new_value.encode("utf-8"))]
            conn.modify_s(dn_user, mod_attrs)
            return {"success": True, "message": "Password updated correctly."}, 200

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)
