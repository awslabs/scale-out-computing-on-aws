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
import config
import ldap
from models import db, ApiKeys
from decorators import restricted_api, admin_api
import errors
import logging
import os
import sys
from utils.aws.ssm_parameter_store import SocaConfig
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.response import SocaResponse
from utils.error import SocaError
logger = logging.getLogger("soca_logger")


class Sudo(Resource):
    @admin_api
    def get(self):
        """
        Check SUDO permissions for a user
        ---
        tags:
          - User Management
        parameters:
          - in: body
            name: body
            schema:
              required:
                - user
              properties:
                user:
                   type: string
                   description: user of the SOCA user

        responses:
          200:
            description: Pair of user/token is valid
          203:
            description: Invalid user/token pair
          400:
            description: Malformed client input
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="args")
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
            _user_filter = f"(&(objectClass=sudoRole)(sudoUser={user}))"
            _attr_list = ["cn"]
        else:
            # member on AD expects the DN of the user
            _user_filter = f"(&(objectClass=group)(member=cn={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}))"
            _attr_list = ["cn"]

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            _is_sudo = _soca_identity_client.search(
                base=config.Config.DIRECTORY_ADMIN_SEARCH_BASE,
                scope=ldap.SCOPE_SUBTREE,
                filter=_user_filter,
                attr_list = _attr_list
            )
            if _is_sudo.success:
                if len(_is_sudo.message) == 1:
                    return SocaResponse(success=True, message=f"{user} has SUDO permissions").as_flask()
                else:
                    return SocaResponse(success=False, message=f"{user} does not have SUDO permissions").as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"Unable to check SUDO permissions because of {_is_sudo.message}").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

    @admin_api
    def post(self):
        """
        Add SUDO permission for a user
        ---
        tags:
          - User Management
        parameters:
          - in: body
            name: body
            schema:
              required:
                - user
              properties:
                user:
                  type: string
                  description: user of the SOCA user
                token:
                  type: string
                  description: token associated to the user

        responses:
          200:
            description: Pair of user/token is valid
          203:
            description: Invalid user/token pair
          400:
            description: Malformed client input
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="form")
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
                _dn_user = f"cn={user},{config.Config.DIRECTORY_ADMIN_SEARCH_BASE}"
                _attrs = [
                    ("objectClass", [
                        "top".encode("utf-8"),
                        "sudoRole".encode("utf-8")
                    ]),
                    ("sudoHost", ["ALL".encode("utf-8")]),
                    ("sudoUser", [str(user).encode("utf-8")]),
                    ("sudoCommand", ["ALL".encode("utf-8")]),
                ]
                _add_sudo = _soca_identity_client.add(dn=_dn_user, mod_list=_attrs)
            else:
                # with AD, there is no concept of Sudoers OU, instead we rely on group membership
                _dn_sudoers_group = config.Config.DIRECTORY_ADMIN_SEARCH_BASE
                _dn_user = f"cn={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}"
                _add_sudo = _soca_identity_client.modify(dn=_dn_sudoers_group,
                                                         mod_list=[(ldap.MOD_ADD, "member", [_dn_user.encode("utf-8")])])

            if _add_sudo.success:
                change_user_key_scope = ApiKeys.query.filter_by(
                    user=user, is_active=True
                ).all()
                if change_user_key_scope:
                    for key in change_user_key_scope:
                        key.scope = "sudo"
                        db.session.commit()
                return SocaResponse(success=True, message=f"{user} has now SUDO permissions").as_flask()
            else:
                return SocaResponse(success=False, message=f"Unable to grant SUDO permission to {user} because of {_add_sudo.get('message')}").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}").as_flask()

    @admin_api
    def delete(self):
        """
        Remove SUDO permission for a user
        ---
        tags:
          - User Management
        parameters:
          - in: body
            name: body
            schema:
              required:
                - user
              properties:
                user:
                  type: string
                  description: user of the SOCA user

        responses:
          200:
            description: Pair of user/token is valid
          203:
            description: Invalid user/token pair
          400:
            description: Malformed client input
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="form")
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user")

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
                dn_user = f"cn={user},{config.Config.DIRECTORY_ADMIN_SEARCH_BASE}"
                _delete_sudo = _soca_identity_client.delete(dn=dn_user)
            else:
                _dn_sudoers_group = config.Config.DIRECTORY_ADMIN_SEARCH_BASE
                _dn_user = f"cn={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}"
                _delete_sudo = _soca_identity_client.modify(dn=_dn_sudoers_group,
                                                            mod_list=[(ldap.MOD_DELETE, "member", [_dn_user.encode("utf-8")])])

            if _delete_sudo.get("success"):
                change_user_key_scope = ApiKeys.query.filter_by(
                    user=user, is_active=True
                ).all()
                if change_user_key_scope:
                    for key in change_user_key_scope:
                        key.scope = "user"
                        db.session.commit()
                return SocaResponse(success=True, message=f"{user} does not have admin permission anymore").as_flask()
            else:
                return SocaResponse(success=False, message=f"Unable to remove admin permission for {user} because of {_delete_sudo.get('message')}").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}").as_flask()
