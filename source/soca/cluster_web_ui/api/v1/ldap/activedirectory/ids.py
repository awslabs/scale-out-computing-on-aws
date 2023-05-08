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

import ldap
import errors
from flask_restful import Resource
import config
import logging
from decorators import admin_api
from random import choice

logger = logging.getLogger("api")


class Ids(Resource):
    @admin_api
    def get(self):
        """
        Return available Linux UID/GID numbers
        ---
        tags:
          - LDAP management
        responses:
          200:
            description: Return list of UID/GID
          500:
            description: Unable to contact LDAP server
          501:
           description: Unknown error (followed by trace)
        """
        uid_in_use = []
        gid_in_use = []
        UID = 5000
        GID = 5000
        MAX_IDS = 65533  # 65534 is for "nobody" and 65535 is reserved
        try:
            conn = ldap.initialize(f"ldap://{config.Config.DOMAIN_NAME}")
            conn.simple_bind_s(
                f"{config.Config.ROOT_USER}@{config.Config.DOMAIN_NAME}",
                config.Config.ROOT_PW,
            )
            user_res = conn.search_s(
                f"ou=Users,ou={config.Config.NETBIOS},{config.Config.LDAP_BASE}",
                ldap.SCOPE_SUBTREE,
                "objectClass=person",
                ["uidNumber"],
            )
            group_res = conn.search_s(
                f"ou=Users,ou={config.Config.NETBIOS},{config.Config.LDAP_BASE}",
                ldap.SCOPE_SUBTREE,
                "objectClass=group",
                ["gidNumber"],
            )
            for a in user_res:
                if a[1]:
                    uid_temp = int(a[1].get("uidNumber")[0])
                    uid_in_use.append(uid_temp)

            for a in group_res:
                if a[1]:
                    gid_temp = int(a[1].get("gidNumber")[0])
                    gid_in_use.append(gid_temp)

            return {
                "success": True,
                "message": {
                    "proposed_uid": choice(
                        [i for i in range(UID, MAX_IDS) if i not in uid_in_use]
                    ),
                    "proposed_gid": choice(
                        [i for i in range(GID, MAX_IDS) if i not in gid_in_use]
                    ),
                    "uid_in_use": uid_in_use,
                    "gid_in_use": gid_in_use,
                },
            }, 200

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)
