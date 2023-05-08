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
        try:
            conn = ldap.initialize("ldap://" + config.Config.LDAP_HOST)
            user_res = conn.search_s(
                config.Config.LDAP_BASE_DN,
                ldap.SCOPE_SUBTREE,
                "objectClass=Group",
                ["uidNumber"],
            )
            group_res = conn.search_s(
                config.Config.LDAP_BASE_DN,
                ldap.SCOPE_SUBTREE,
                "objectClass=posixGroup",
                ["gidNumber"],
            )

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)

        UID = 5000
        GID = 5000
        MAX_IDS = 65533  # 65534 is for "nobody" and 65535 is reserved

        for uid in user_res:
            uid_temp = int(uid[1].get("uidNumber")[0])
            uid_in_use.append(uid_temp)

        for gid in group_res:
            gid_temp = int(gid[1].get("gidNumber")[0])
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
