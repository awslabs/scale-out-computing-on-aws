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

logger = logging.getLogger("api")


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
            return {"success": False, "message": "user can not be empty"}, 400

        try:
            logger.info(f"Checking SUDO permission for {user}")
            conn = ldap.initialize(f"ldap://{config.Config.DOMAIN_NAME}")
            conn.protocol_version = 3
            conn.set_option(ldap.OPT_REFERRALS, 0)
            conn.simple_bind_s(
                f"{config.Config.ROOT_USER}@{config.Config.DOMAIN_NAME}",
                config.Config.ROOT_PW,
            )
            user_search_base = f"CN={user},OU=Users,OU={config.Config.NETBIOS},{config.Config.LDAP_BASE}"
            sudoers_group = config.Config.SUDOERS_GROUP
            filter_criteria = f"(&(objectClass=group)(member={user_search_base}))"
            for dn, entry in conn.search_s(
                config.Config.LDAP_BASE,
                ldap.SCOPE_SUBTREE,
                filter_criteria,
                ["cn", "member"],
            ):
                if isinstance(entry, dict):
                    logger.info(f"Checking {sudoers_group}: {dn}, {entry}")
                    if "cn" in entry.keys():
                        if entry["cn"][0].decode("utf-8") == sudoers_group:
                            logger.info(
                                "Logger SUDOERS group detected, checking members"
                            )
                            if "member" in entry.keys():
                                for users in entry["member"]:
                                    logger.info(f"Detected sudo permission for {users}")
                                    if user_search_base.lower() == users.lower().decode(
                                        "utf-8"
                                    ):
                                        return {
                                            "success": True,
                                            "message": "User has SUDO permissions.",
                                        }, 200
            return {
                "success": False,
                "message": "User does not have SUDO permissions.",
            }, 222

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)

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
            return {"success": False, "message": "user can not be empty"}, 400

        conn = ldap.initialize(f"ldap://{config.Config.DOMAIN_NAME}")
        conn.simple_bind_s(
            f"{config.Config.ROOT_USER}@{config.Config.DOMAIN_NAME}",
            config.Config.ROOT_PW,
        )
        sudoers_group = config.Config.SUDOERS_GROUP_DN
        dn_user = (
            f"cn={user},ou=Users,OU={config.Config.NETBIOS},{config.Config.LDAP_BASE}"
        )
        logger.info(f"Adding SUDO permission for {dn_user}")
        mod_attrs = [(ldap.MOD_ADD, "member", [dn_user.encode("utf-8")])]
        try:
            conn.modify_s(sudoers_group, mod_attrs)
            change_user_key_scope = ApiKeys.query.filter_by(
                user=user, is_active=True
            ).all()
            if change_user_key_scope:
                for key in change_user_key_scope:
                    key.scope = "sudo"
                    db.session.commit()
            logger.info(f"Permission granted for {user}")
            return {"success": True, "message": f"{user} now has admin permission"}, 200
        except Exception as e:
            return errors.all_errors(type(e).__name__, e)

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
            return {"success": False, "message": "user can not be empty"}, 400

        conn = ldap.initialize(f"ldap://{config.Config.DOMAIN_NAME}")
        conn.simple_bind_s(
            f"{config.Config.ROOT_USER}@{config.Config.DOMAIN_NAME}",
            config.Config.ROOT_PW,
        )
        sudoers_group = config.Config.SUDOERS_GROUP_DN
        dn_user = (
            f"cn={user},ou=Users,OU={config.Config.NETBIOS},{config.Config.LDAP_BASE}"
        )
        logger.info(f"Revoking sudo permission for {dn_user}")
        mod_attrs = [(ldap.MOD_DELETE, "member", [dn_user.encode("utf-8")])]
        try:
            conn.modify_s(sudoers_group, mod_attrs)
            change_user_key_scope = ApiKeys.query.filter_by(
                user=user, is_active=True
            ).all()
            if change_user_key_scope:
                for key in change_user_key_scope:
                    key.scope = "user"
                    db.session.commit()
            logger.info(f"Permission revoked for {user}")
            return {
                "success": True,
                "message": f"Revoked SUDO permission for {user}",
            }, 200
        except Exception as e:
            return errors.all_errors(type(e).__name__, e)
