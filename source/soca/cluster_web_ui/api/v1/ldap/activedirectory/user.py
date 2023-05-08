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

import hashlib
import os
from base64 import b64encode as encode
import time
from email.utils import parseaddr
import config
import ldap
import errors
from flask_restful import Resource, reqparse
from requests import get, post, put, delete
import json
import logging
from flask import request
from decorators import private_api, admin_api
import sys
import shutil
import datetime
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend

logger = logging.getLogger("api")


def create_home(username, usergroup):
    try:
        user_home = config.Config.USER_HOME
        key = rsa.generate_private_key(
            backend=crypto_default_backend(), public_exponent=65537, key_size=2048
        )
        private_key = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            crypto_serialization.NoEncryption(),
        )
        public_key = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH,
        )
        private_key_str = private_key.decode("utf-8")
        public_key_str = public_key.decode("utf-8")
        # Create user directory structure
        user_path = f"{user_home}/{username}/.ssh"
        os.makedirs(user_path)

        # Copy default .bash profile
        shutil.copy("/etc/skel/.bashrc", f'{"/".join(user_path.split("/")[:-1])}/')
        shutil.copy(
            "/etc/skel/.bash_profile", f'{"/".join(user_path.split("/")[:-1])}/'
        )
        shutil.copy("/etc/skel/.bash_logout", f'{"/".join(user_path.split("/")[:-1])}/')

        # Create SSH keypair
        print(private_key_str, file=open(user_path + "/id_rsa", "w"))
        print(public_key_str, file=open(user_path + "/id_rsa.pub", "w"))
        print(public_key_str, file=open(user_path + "/authorized_keys", "w"))

        # Adjust file/folder ownership
        for path in [
            f"{user_home}/{username}",
            f"{user_home}/{username}/.ssh",
            f"{user_home}/{username}/.ssh/authorized_keys",
            f"{user_home}/{username}/.ssh/id_rsa",
            f"{user_home}/{username}/.ssh/id_rsa.pub",
            f"{user_home}/{username}/.bashrc",
            f"{user_home}/{username}/.bash_profile",
            f"{user_home}/{username}/.bash_logout",
        ]:
            shutil.chown(path, user=username, group=usergroup)

        # Adjust file/folder permissions
        os.chmod(f"{user_home}/{username}", 0o700)
        os.chmod(f"{user_home}/{username}/.ssh", 0o700)
        os.chmod(f"{user_home}/{username}/.ssh/id_rsa", 0o600)
        os.chmod(f"{user_home}/{username}/.ssh/authorized_keys", 0o600)
        return True

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
        return e


class User(Resource):
    @admin_api
    def get(self):
        """
        Retrieve information for a specific user
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
            description: Return user information
          203:
            description: Unknown user
          400:
            description: Malformed client input
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="args")
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER", "user (str) parameter is required"
            )

        try:
            conn = ldap.initialize(f"ldap://{config.Config.DOMAIN_NAME}")
            conn.simple_bind_s(
                f"{config.Config.ROOT_USER}@{config.Config.DOMAIN_NAME}",
                config.Config.ROOT_PW,
            )
            conn.protocol_version = 3
            conn.set_option(ldap.OPT_REFERRALS, 0)
            user_search_base = (
                f"OU=Users,OU={config.Config.NETBIOS},{config.Config.LDAP_BASE}"
            )
            user_search_scope = ldap.SCOPE_SUBTREE
            user_filter = f"(&(objectClass=user)(sAMAccountName={user}))"
            check_user = conn.search_s(user_search_base, user_search_scope, user_filter)
            if check_user.__len__() == 0:
                return {"success": False, "message": "Unknown user"}, 203
            else:
                return {"success": True, "message": str(check_user)}, 200

        except Exception as err:
            return {"success": False, "message": "Unknown error: " + str(err)}, 500

    @admin_api
    def post(self):
        """
        Create a new LDAP user
        ---
        tags:
          - User Management
        parameters:
          - in: body
            name: body
            schema:
              required:
                - user
                - password
                - sudoers
                - email
              optional:
                - uid
                - gid
              properties:
                user:
                  type: string
                  description: user you want to create
                password:
                  type: string
                  description: Password for the new user
                sudoers:
                  type: boolean
                  description: True (give user SUDO permissions) or False
                email:
                  type: string
                  description: Email address associated to the user
                uid:
                  type: integer
                  description: Linux UID to be associated to the user
                gid:
                  type: integer
                  description: Linux GID to be associated to user's group
        responses:
          200:
            description: User created
          203:
            description: User already exist
          400:
            description: Malformed client input
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="form")
        parser.add_argument("password", type=str, location="form")
        parser.add_argument("sudoers", type=int, location="form")
        parser.add_argument("email", type=str, location="form")
        parser.add_argument("shell", type=str, location="form")
        parser.add_argument(
            "uid", type=int, location="form"
        )  # 0 = no value specified, use default one
        parser.add_argument(
            "gid", type=int, location="form"
        )  # 0 = no value specified, use default one
        args = parser.parse_args()
        user = "".join(
            x for x in args["user"] if x.isalpha() or x.isdigit()
        ).lower()  # Sanitize input
        password = args["password"]
        sudoers = args["sudoers"]
        email = args["email"]
        uid = args["uid"]
        gid = args["gid"]
        shell = args["shell"]
        group = f"{args['user']}{config.Config.GROUP_NAME_SUFFIX}"

        logger.info(
            f"Received New User creation: user: {user}, sudoers {sudoers}, email {email}, uid {uid}, gid {gid}, shell {shell}"
        )
        if user is None or password is None or sudoers is None or email is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER",
                "user (str), password (str), sudoers (bool) and email (str) parameters are required",
            )

        if shell is None:
            shell = "/bin/bash"

        if user.lower() in password.lower():
            return errors.all_errors("DS_PASSWORD_USERNAME_IN_PW")

        if user.lower() == "admin":
            return errors.all_errors("DS_PASSWORD_USERNAME_IS_ADMIN")

        get_id = get(
            config.Config.FLASK_ENDPOINT + "/api/ldap/ids",
            headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
            verify=False,
        )  # nosec
        if get_id.status_code == 200:
            current_ldap_ids = json.loads(get_id.text)
        else:
            logger.error("/api/ldap/ids returned error : " + str(get_id.__dict__))
            return {
                "success": False,
                "message": "/api/ldap/ids returned error: " + str(get_id.__dict__),
            }, 500

        # Note: parseaddr adheres to rfc5322 , which means user@domain is a correct address.
        # You do not necessarily need to add a tld at the end
        if "@" not in parseaddr(email)[1]:
            return errors.all_errors("INVALID_EMAIL_ADDRESS")

        if uid == 0:
            uid = current_ldap_ids["message"]["proposed_uid"]
        else:
            if uid in current_ldap_ids["message"]["uid_in_use"]:
                return errors.all_errors("UID_ALREADY_IN_USE")

        if gid == 0:
            gid = current_ldap_ids["message"]["proposed_gid"]
        else:
            if gid in current_ldap_ids["message"]["gid_in_use"]:
                return errors.all_errors("GID_ALREADY_IN_USE")

        try:
            conn = ldap.initialize(f"ldap://{config.Config.DOMAIN_NAME}")
            conn.simple_bind_s(
                f"{config.Config.ROOT_USER}@{config.Config.DOMAIN_NAME}",
                config.Config.ROOT_PW,
            )
            conn.protocol_version = 3
            conn.set_option(ldap.OPT_REFERRALS, 0)
            dn_user = f"cn={user},ou=Users,ou={config.Config.NETBIOS},{config.Config.LDAP_BASE}"
            attrs = [
                (
                    "objectClass",
                    [
                        "top".encode("utf-8"),
                        "person".encode("utf-8"),
                        "user".encode("utf-8"),
                        "organizationalPerson".encode("utf-8"),
                    ],
                ),
                ("displayName", [str(user).encode("utf-8")]),
                ("mail", [email.encode("utf-8")]),
                ("sAMAccountName", [str(user).encode("utf-8")]),
                (
                    "userPrincipalName",
                    [str(user + "@" + config.Config.DOMAIN_NAME).encode("utf-8")],
                ),
                ("cn", [str(user).encode("utf-8")]),
                ("uidNumber", [str(uid).encode("utf-8")]),
                ("loginShell", [shell.encode("utf-8")]),
                ("homeDirectory", (str(user) + "/" + str(user)).encode("utf-8")),
            ]

            # Create group first to prevent GID issue
            create_user_group = post(
                config.Config.FLASK_ENDPOINT + "/api/ldap/group",
                headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                data={"group": f"{group}", "gid": gid},
                verify=False,
            )  # nosec
            if create_user_group.status_code != 200:
                return errors.all_errors(
                    "COULD_NOT_CREATE_GROUP", str(create_user_group.text)
                )

            # Create user
            conn.add_s(dn_user, attrs)

            # Wait for the account to be sync
            time.sleep(30)
            # Reset password via Lambda
            change_password = post(
                config.Config.FLASK_ENDPOINT + "/api/user/reset_password",
                headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                data={"user": user, "password": password},
                verify=False,
            )  # nosec
            logger.info(f"Checking password reset request: {change_password.text}")
            if change_password.status_code != 200:
                return errors.all_errors(
                    "DS_CREATED_USER_NO_PW", str(change_password.text)
                )

            logger.info(
                "Sleeping 10 seconds to make sure domain controllers are in sync"
            )
            time.sleep(10)

            # Add user to group, need to wait 30 for account sync on AD
            """
            update_group = put(config.Config.FLASK_ENDPOINT + "/api/ldap/group",
                               headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                               data={"group": f"{user}group",
                                     "user": user,
                                     "action": "add"},
                               verify=False) # nosec

            if update_group.status_code != 200:
                return errors.all_errors("UNABLE_TO_ADD_USER_TO_GROUP", f"User/Group created but could not add user to his group due to {update_group.json()}")
            """
            # Create home directory
            logger.info("About to create home directory for user")
            if create_home(user, group) is False:
                return errors.all_errors(
                    "UNABLE_CREATE_HOME",
                    "User added but unable to create home director",
                )

            logger.info(f"About to generate API KEY for {user}")
            # Create API Key
            try:
                get(
                    config.Config.FLASK_ENDPOINT + "/api/user/api_key",
                    headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                    params={"user": user},
                    verify=False,
                ).json()  # nosec
            except Exception as err:
                logger.error(
                    "User created but unable to create API key. SOCA will try to generate it when user log in for the first time "
                    + str(err)
                )

            # Add Sudo permission
            if sudoers == 1:
                logger.info(f"Adding SUDO permissions to user {user}")
                grant_sudo = post(
                    config.Config.FLASK_ENDPOINT + "/api/ldap/sudo",
                    headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                    data={"user": user},
                    verify=False,  # nosec
                )
                if grant_sudo.status_code != 200:
                    return errors.all_errors(
                        "UNABLE_TO_GRANT_SUDO",
                        "User added but unable to give admin permissions",
                    )
            logger.info("User added successfully")
            return {"success": True, "message": "Added user"}, 200

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)

    @admin_api
    def delete(self):
        """
        Delete a LDAP user ($HOME is preserved on EFS)
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
            description: Deleted user
          203:
            description: Unknown user
          204:
            description: User deleted but API still active
          400:
            description: Malformed client input
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="form")
        args = parser.parse_args()
        user = args["user"]
        group = f"{args['user']}{config.Config.GROUP_NAME_SUFFIX}"
        if user is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER", "user (str) parameter is required"
            )

        request_user = request.headers.get("X-SOCA-USER")
        if request_user is None:
            return errors.all_errors("X-SOCA-USER_MISSING")

        if request_user == user:
            return errors.all_errors("CLIENT_OWN_RESOURCE")

        try:
            logger.info(f"Received user delete request for {user}")
            domain_name = config.Config.DOMAIN_NAME
            root_user = config.Config.ROOT_USER
            root_pw = config.Config.ROOT_PW
            ldap_base = config.Config.LDAP_BASE
            netbios = config.Config.NETBIOS
            conn = ldap.initialize(f"ldap://{domain_name}")
            conn.simple_bind_s(f"{root_user}@{domain_name}", root_pw)
            today = datetime.datetime.utcnow().strftime("%s")
            user_home = config.Config.USER_HOME + "/" + user
            backup_folder = config.Config.USER_HOME + "/" + user + "_" + today
            logger.info(f"Creating backup folder {backup_folder}")
            shutil.move(user_home, backup_folder)
            entries_to_delete = [
                f"cn={user},ou=Users,ou={netbios},{ldap_base}",
                f"cn={group},ou=Users,ou={netbios},{ldap_base}",
            ]

            for entry in entries_to_delete:
                try:
                    logger.info(f"About to delete {entry}")
                    conn.delete_s(entry)
                except ldap.NO_SUCH_OBJECT:
                    if entry == f"cn={user},ou=Users,ou={netbios},{ldap_base}":
                        return {"success": False, "message": "Unknown user"}, 203
                except Exception as err:
                    return {
                        "success": False,
                        "message": "Unknown error: " + str(err),
                    }, 500
            logger.info(f"About to invalidate API key for {user}")
            invalidate_api_key = delete(
                config.Config.FLASK_ENDPOINT + "/api/user/api_key",
                headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                data={"user": user},
                verify=False,
            )  # nosec
            logger.info(invalidate_api_key.json())
            if invalidate_api_key.status_code != 200:
                return errors.all_errors(
                    "API_KEY_NOT_DELETED",
                    "User deleted but unable to deactivate API key. "
                    + str(invalidate_api_key),
                )

            return {"success": True, "message": "Deleted user."}, 200

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)
