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
from flask_restful import Resource
import config
import logging
from decorators import admin_api
from random import choice
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.response import SocaResponse
from utils.error import SocaError
import os
import sys

logger = logging.getLogger("soca_logger")


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
        if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
            _user_filter = "objectClass=person"
            _user_attr_list = ["uidNumber"]
            _group_filter = "objectClass=posixGroup"
            _group_attr_list = ["gidNumber"]
        else:
            # Todo: review AD with SID
            _user_filter = "(&(objectClass=person)(uidNumber=*))"
            _user_attr_list = ["uidNumber"]
            _group_filter = "(&(objectClass=group)(gidNumber=*))"
            _group_attr_list = ["gidNumber"]

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            user_res = _soca_identity_client.search(base=config.Config.DIRECTORY_PEOPLE_SEARCH_BASE,
                                                    scope=ldap.SCOPE_SUBTREE,
                                                    filter=_user_filter,
                                                    attr_list=_user_attr_list)

            group_res = _soca_identity_client.search(
                base=config.Config.DIRECTORY_GROUP_SEARCH_BASE,
                scope=ldap.SCOPE_SUBTREE,
                filter=_group_filter,
                attr_list=_group_attr_list)

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

        uid_in_use = []
        gid_in_use = []

        UID = 5001
        GID = 5001 # 5000 is for admin in SUDOERS OU
        MAX_IDS = 65533  # 65534 is for "nobody" and 65535 is reserved

        if user_res.success:
            for uid in user_res.message:
                uid_in_use.append(int(uid[1].get("uidNumber")[0]))
        else:
            return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"Unable to lookup uidNumber because of {user_res.message}").as_flask()

        if group_res.success:
            for gid in group_res.message:
                gid_in_use.append(int(gid[1].get("gidNumber")[0]))
        else:
            if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to lookup gidNumber because of {group_res.message}").as_flask()
            else:
                logger.warning(f"Unable to lookup gidNumber because of {group_res.message}. gidNumber is optional on Active Directory, so just triggering warning")

        return SocaResponse(
            success=True,
            message={
                "proposed_uid": choice(
                    [i for i in range(UID, MAX_IDS) if i not in uid_in_use]
                ),
                "proposed_gid": choice(
                    [i for i in range(GID, MAX_IDS) if i not in gid_in_use]
                ),
                "uid_in_use": uid_in_use,
                "gid_in_use": gid_in_use,
        }).as_flask()
