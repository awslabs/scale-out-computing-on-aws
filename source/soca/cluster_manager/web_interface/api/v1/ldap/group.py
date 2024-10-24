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
from flask_restful import Resource, reqparse
from requests import get, put
import logging
from flask import request
from decorators import private_api, admin_api
import re
import errors
import os
import sys
from utils.error import SocaError
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.response import SocaResponse
from utils.aws.ssm_parameter_store import SocaConfig
from utils.http_client import SocaHttpClient
logger = logging.getLogger("soca_logger")


class Group(Resource):
    @admin_api
    def get(self):
        """
        Retrieve information for a specific group
        ---
        tags:
          - Group Management
        parameters:
          - in: body
            name: body
            schema:
            required:
              - group
            properties:
              group:
                type: string
                description: user of the SOCA user

        responses:
          200:
            description: Return user information
          203:
            description: Unknown user
          400:
            description: Malformed client input
        """
        parser = reqparse.RequestParser()
        parser.add_argument("group", type=str, location="args")
        args = parser.parse_args()
        group = args["group"]
        if group is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="group",
            ).as_flask()


        _group_search_base = config.Config.DIRECTORY_GROUP_SEARCH_BASE
        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
                _filter = f"(&(objectClass=posixGroup)(cn={group}))"
                _attr_list = ["cn", "memberUid"]
            else:
                _filter = f"(&(objectClass=group)(cn={group}))"
                _attr_list = ["cn", "member"]

            _group = _soca_identity_client.search(
                base=_group_search_base,
                scope=ldap.SCOPE_SUBTREE,
                filter=_filter,
                attr_list=_attr_list,
            )
            if _group.success is False:
                logger.debug(f"{group} is not a valid LDAP group")
                return SocaResponse(success=False, message=f"LDAP group {group} does not exist").as_flask()
            else:
                group_base = ""
                members = []
                for group in _group.message:
                    group_base = group[0]
                    if _attr_list[1] in group[1].keys():
                        for member in group[1][_attr_list[1]]:
                            members.append(member.decode("utf-8") if isinstance(member, bytes) else member)

                return SocaResponse(success=True, message={"group_dn": group_base, "members": members}).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}").as_flask()

    @admin_api
    def post(self):
        """
        Create a new LDAP group
        ---
        tags:
          - Group Management
        parameters:
          - in: body
            name: body
            schema:
              required:
                - group
              optional:
                - gid
                - users
              properties:
                group:
                  type: string
                  description: Name of the group
                gid:
                  type: integer
                  description: Linux GID to be associated to the group
                users:
                  type: list
                  description: List of user(s) to add to the group


        responses:
          200:
            description: Group created
          203:
            description: Group already exist
          204:
            description: User does not exist and can't be added to the group
          400:
            description: Malformed client input
          500:
            description: Backend issue
        """
        parser = reqparse.RequestParser()
        parser.add_argument("group", type=str, location="form")
        parser.add_argument("gid", type=int, location="form")
        parser.add_argument(
            "members", type=str, location="form"
        )  # comma separated list of users

        args = parser.parse_args()
        _group_regex_pattern = r'^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}$'
        if re.match(_group_regex_pattern, args["group"]):
            group = args["group"].lower()
        else:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"group {args['group']} is not valid, must match {_group_regex_pattern} (contains -and start with- only alpha-numerical characters plus _ . - and must be 31 chars max").as_flask()

        gid = args["gid"]

        _group_search_base = config.Config.DIRECTORY_GROUP_SEARCH_BASE
        _people_search_base = config.Config.DIRECTORY_PEOPLE_SEARCH_BASE

        if args["members"] is None:
            members = []
        else:
            members = args["members"].split(",")

        _get_gid = SocaHttpClient(endpoint="/api/ldap/ids", headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY}).get()
        if _get_gid.success:
            current_ldap_gids = _get_gid.message
        else:
            return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"Unable to retrieve IDS due to {_get_gid.message}").as_flask()

        if gid is None:
            group_id = current_ldap_gids["proposed_gid"]
        else:
            if gid in current_ldap_gids["gid_in_use"]:
                return errors.all_errors("GID_ALREADY_IN_USE")
            group_id = gid

        if group is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="group").as_flask()

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            group_members = []
            if members is not None:
                if not isinstance(members, list):
                    return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"members must be a valid list").as_flask()

                _get_all_users = SocaHttpClient(endpoint="/api/ldap/users", headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY}).get()
                if _get_all_users.success:
                    all_users = _get_all_users.message
                else:
                    return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"Unable to retrieve the list of all SOCA users because of {_get_all_users.message}").as_flask()

                for member in members:
                    if member not in all_users.keys():
                        return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"Unable to create group because supplied user {member} does not exist").as_flask()
                    else:
                        group_members.append(member)

            if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
                group_dn = f"cn={group},{_group_search_base}"
                attrs = [
                    ("objectClass", ["top".encode("utf-8"), "posixGroup".encode("utf-8")]),
                    ("gidNumber", [str(group_id).encode("utf-8")]),
                    (
                        "cn",
                        [str(group).encode("utf-8")],
                    ),
                ]
            else:
                group_dn = f"cn={group},{_group_search_base}"
                attrs = [
                    ("objectClass", ["top".encode("utf-8"), "group".encode("utf-8")]),
                    ("gidNumber", [str(group_id).encode("utf-8")]),
                    ("sAMAccountName", [f"{group}".encode("utf-8")]),
                ]

            _soca_identity_client.add(dn=group_dn, mod_list=attrs)

            users_not_added = []
            for member in group_members:
                _add_member_to_group = SocaHttpClient(endpoint="/api/ldap/group", headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY}).put(data={"group": group, "user": member, "action": "add"})
                if not _add_member_to_group.success:
                    users_not_added.append(member)

            if users_not_added.__len__() == 0:
                return SocaResponse(success=True, message="Group created successfully").as_flask()
            else:
                return SocaResponse(success=True, message=f"Group created successfully but unable to add some users: {users_not_added}").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}").as_flask()

    @admin_api
    def delete(self):
        """
        Delete a LDAP group
        ---
        tags:
          - Group Management
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
            description: Deleted group
          203:
            description: Unknown user
          400:
            description: Malformed client input
        """
        parser = reqparse.RequestParser()
        parser.add_argument("group", type=str, location="form")
        args = parser.parse_args()
        group = args["group"]

        request_user = request.headers.get("X-SOCA-USER")
        if request_user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        if request_user == group:
            return SocaError.IDENTITY_PROVIDER_ERROR(helper="You cannot delete your own group").as_flask()

        if group is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="group").as_flask()

        _group_search_base = config.Config.DIRECTORY_GROUP_SEARCH_BASE

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
                _dn = f"cn={group},{_group_search_base}"
            else:
                _dn = f"cn={group},{_group_search_base}"

            _delete_req = _soca_identity_client.delete(dn=_dn)
            if _delete_req.success:
                return SocaResponse(success=True, message="Group deleted successfully").as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"Unable to delete group because of {_delete_req.message}").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}").as_flask()

    @admin_api
    def put(self):
        """
        Add/Remove user to/from a LDAP group
        ---
        tags:
          - Group Management

        parameters:
          - in: body
            name: body
            schema:
              required:
                - user
                - attribute
                - value
              properties:
                group:
                  type: string
                  description: user of the SOCA user
                user:
                  type: string
                  description: Attribute to change
                action:
                  type: string
                  description: New attribute value

        responses:
          200:
            description: LDAP attribute modified successfully
          203:
            description: User already belongs to the group
          204:
            description: User does not belong to the group
          400:
            description: Malformed client input
          401:
            description: Unable to bind LDAP (invalid credentials)
          500:
            description: Backend issue (see trace)
        """
        parser = reqparse.RequestParser()
        parser.add_argument("group", type=str, location="form")
        parser.add_argument("user", type=str, location="form")
        parser.add_argument("action", type=str, location="form")
        args = parser.parse_args()
        group = args["group"]
        user = args["user"]
        action = args["action"]
        ALLOWED_ACTIONS = ["add", "remove"]

        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        if group is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="group").as_flask()

        if action is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="action").as_flask()

        if action not in ALLOWED_ACTIONS:
            return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"Action {action} is not supported").as_flask()

        # Modifying resources on ActiveDirectory require to supply the full DN for the user
        if config.Config.DIRECTORY_AUTH_PROVIDER in ["aws_ds_managed_activedirectory", "aws_ds_simple_activedirectory"]:
            if not config.Config.DIRECTORY_PEOPLE_SEARCH_BASE.lower() in user.lower():
                user_dn = f"cn={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}"
            else:
                user_dn = user
        else:
            user_dn = user

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            _group_search_base = config.Config.DIRECTORY_GROUP_SEARCH_BASE
            _people_search_base = config.Config.DIRECTORY_PEOPLE_SEARCH_BASE

            if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
                _group_dn = f"cn={group},{_group_search_base}"
                _attr_name = "memberUid"
            else:
                _group_dn = f"cn={group},{_group_search_base}"
                _attr_name = "member"

            _is_user_exist = SocaHttpClient(endpoint="/api/ldap/user", headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY}).get(params={"user": user})

            if _is_user_exist.success:
                if len(_is_user_exist.message) == 0:
                    return SocaError.IDENTITY_PROVIDER_ERROR( helper=f"User {user} does not exist").as_flask()
                else:
                    if action == "add":
                        mod_attrs = [(ldap.MOD_ADD, _attr_name, [user_dn.encode("utf-8")])]
                    else:
                        mod_attrs = [(ldap.MOD_DELETE, _attr_name, [user_dn.encode("utf-8")])]

                    _modify = _soca_identity_client.modify(dn=_group_dn, mod_list=mod_attrs)
                    if _modify.success:
                        return SocaResponse(success=True, message="Group updated successfully").as_flask()
                    else:
                        return SocaResponse(success=False, message=f"Unable to modify group because of {_modify.message}").as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"Unable to determine if {user} exist because of {_is_user_exist.message}").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}").as_flask()
