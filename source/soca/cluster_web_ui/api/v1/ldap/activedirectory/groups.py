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
from decorators import private_api
import errors
import re

logger = logging.getLogger("api")


class Groups(Resource):
    @private_api
    def get(self):
        """
        List all LDAP groups
        ---
        tags:
          - Group Management
        responses:
          200:
            description: Group info
          400:
            description: Malformed client input
          500:
            description: Backend issue
        """
        try:
            all_ldap_groups = {}
            conn = ldap.initialize(f"ldap://{config.Config.DOMAIN_NAME}")
            conn.protocol_version = 3
            conn.set_option(ldap.OPT_REFERRALS, 0)
            conn.simple_bind_s(
                f"{config.Config.ROOT_USER}@{config.Config.DOMAIN_NAME}",
                config.Config.ROOT_PW,
            )
            group_search_base = (
                f"OU=Users,OU={config.Config.NETBIOS},{config.Config.LDAP_BASE}"
            )
            filter_criteria = f"(objectClass=group)"
            groups = conn.search_s(
                group_search_base, ldap.SCOPE_SUBTREE, filter_criteria, ["cn", "member"]
            )
            logger.info(
                f"Checking all AD groups with search filter {filter_criteria} and base {group_search_base}"
            )
            for group in groups:
                logger.info(f"Detected {group}")
                group_base = group[0]
                group_name = group[1]["cn"][0].decode("utf-8")
                members = []
                if "member" in group[1].keys():
                    for member in group[1]["member"]:
                        user = re.match("cn=(\w+),", member.decode("utf-8"))
                        if user:
                            members.append(user.group(1))
                        else:
                            # handle case where lDAP ownership was done outside of SOCA
                            members.append(member.decode("utf-8"))
                            # return {"success": False, "message": "Unable to retrieve memberUid for this group: " + str(group_base) + "members: "+str(group[1]["memberUid"])}, 500

                all_ldap_groups[group_name] = {
                    "group_dn": group_base,
                    "members": members,
                }
            logger.info(f"Groups detected {all_ldap_groups}")
            return {"success": True, "message": all_ldap_groups}, 200

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)
