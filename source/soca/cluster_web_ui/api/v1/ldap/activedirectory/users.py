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
        all_ldap_users = {}
        try:
            conn = ldap.initialize(f"ldap://{config.Config.DOMAIN_NAME}")
            conn.protocol_version = 3
            conn.set_option(ldap.OPT_REFERRALS, 0)
            conn.simple_bind_s(
                f"{config.Config.ROOT_USER}@{config.Config.DOMAIN_NAME}",
                config.Config.ROOT_PW,
            )
            user_search_base = (
                f"OU=Users,OU={config.Config.NETBIOS},{config.Config.LDAP_BASE}"
            )
            filter_criteria = f"(objectClass=person)"
            logger.info(
                f"Checking all AD users with search filter {filter_criteria} and base {user_search_base}"
            )
            for dn, entry in conn.search_s(
                user_search_base, ldap.SCOPE_SUBTREE, filter_criteria, ["cn"]
            ):
                all_ldap_users[entry["cn"][0].decode("utf-8")] = str(dn)
            logger.info(f"all ldap users {all_ldap_users}")
            return {"success": True, "message": all_ldap_users}, 200

        except Exception as err:
            return all_errors(type(err).__name__, err)
