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
import ldap
from flask_restful import Resource
import logging
from decorators import admin_api, private_api
from errors import all_errors

logger = logging.getLogger("api")


class Users(Resource):
    @private_api
    def get(self):
        """
        List all LDAP users
        ---
        tags:
          - User Management
        responses:
          200:
            description: Pair of username/token is valid
          203:
            description: Invalid username/token pair
          400:
            description: Malformed client input
        """
        ldap_host = config.Config.LDAP_HOST
        base_dn = config.Config.LDAP_BASE_DN
        all_ldap_users = {}
        user_search_base = "ou=People," + base_dn
        user_search_scope = ldap.SCOPE_SUBTREE
        user_filter = "uid=*"
        try:
            con = ldap.initialize(f"ldap://{ldap_host}")
            users = con.search_s(user_search_base, user_search_scope, user_filter)
            for user in users:
                user_base = user[0]
                username = user[1]["uid"][0].decode("utf-8")
                all_ldap_users[username] = user_base

            return {"success": True, "message": all_ldap_users}, 200

        except Exception as err:
            return all_errors(type(err).__name__, err)
