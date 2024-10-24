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
import os
import sys
from utils.error import SocaError
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.response import SocaResponse
from utils.aws.ssm_parameter_store import SocaConfig

logger = logging.getLogger("soca_logger")


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
        # List all LDAP users
        if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
            _filter = "objectClass=posixGroup"
            _attr_list = ["cn", "memberUid"]
        else:
            _filter = "objectClass=group"
            _attr_list = ["cn", "member"]

        all_ldap_groups = {}
        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            _groups = _soca_identity_client.search(base=config.Config.DIRECTORY_GROUP_SEARCH_BASE,
                                                   scope=ldap.SCOPE_SUBTREE,
                                                   filter=_filter,
                                                   attr_list=_attr_list)
            if _groups.success:
                # ex: ('cn=socaadminsocagroup,ou=group,dc=soca-dev200,dc=local', {'cn': [b'socaadminsocagroup'], 'memberUid': [b'socaadmin']})
                for group in _groups.message:
                    group_base = group[0]
                    group_name = group[1]["cn"][0].decode("utf-8") if isinstance(group[1]["cn"][0], bytes) else group[1]["cn"][0]
                    members = []
                    if _attr_list[1] in group[1].keys():
                        for member in group[1][_attr_list[1]]:
                            members.append(member.decode("utf-8") if isinstance(member, bytes) else member)

                    all_ldap_groups[group_name] = {
                        "group_dn": group_base,
                        "members": members,
                    }
                return SocaResponse(success=True, message=all_ldap_groups).as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"Unable to list all groups because of {_groups.message}").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()
