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

import datetime
import hashlib
import json
import logging
import os
import shutil
import sys
from base64 import b64encode as encode
from email.utils import parseaddr

import config
import errors
import ldap
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from decorators import admin_api, private_api
from flask import request
from flask_restful import Resource, reqparse
from requests import delete, get, post, put

logger = logging.getLogger("api")


def create_home(username, group):
    try:
        user_home = config.Config.USER_HOME
        key = rsa.generate_private_key(backend=crypto_default_backend(), public_exponent=65537, key_size=2048)
        private_key = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            crypto_serialization.NoEncryption(),
        )
        public_key = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH, crypto_serialization.PublicFormat.OpenSSH
        )
        private_key_str = private_key.decode("utf-8")
        public_key_str = public_key.decode("utf-8")

        # Create user directory structure
        user_path = f"{user_home}/{username}/.ssh"
        os.makedirs(user_path)

        # Copy default .bash profile
        shutil.copy("/etc/skel/.bashrc", f'{"/".join(user_path.split("/")[:-1])}/')
        shutil.copy("/etc/skel/.bash_profile", f'{"/".join(user_path.split("/")[:-1])}/')
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
            shutil.chown(path, user=username, group=group)

        # Adjust file/folder permissions
        os.chmod(f"{user_home}/{username}/", 0o700)
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
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "user (str) parameter is required")

        user_filter = "cn=" + user
        user_search_base = "ou=People," + config.Config.LDAP_BASE_DN
        user_search_scope = ldap.SCOPE_SUBTREE
        try:
            conn = ldap.initialize("ldap://" + config.Config.LDAP_HOST)
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
        parser.add_argument("uid", type=int, location="form")  # 0 = no value specified, use default one
        parser.add_argument("gid", type=int, location="form")  # 0 = no value specified, use default one
        args = parser.parse_args()
        user = "".join(x for x in args["user"] if x.isalpha() or x.isdigit()).lower()  # Sanitize input
        password = args["password"]
        sudoers = args["sudoers"]
        email = args["email"]
        uid = args["uid"]
        gid = args["gid"]
        shell = args["shell"]
        group = f"{args['user']}{config.Config.GROUP_NAME_SUFFIX}"
        if shell is None:
            shell = "/bin/bash"

        get_id = get(
            config.Config.FLASK_ENDPOINT + "/api/ldap/ids",
            headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
            verify=False,
        )  # nosec
        if get_id.status_code == 200:
            current_ldap_ids = json.loads(get_id.text)
        else:
            logger.error("/api/ldap/ids returned error : " + str(get_id.__dict__))
            return {"success": False, "message": "/api/ldap/ids returned error: " + str(get_id.__dict__)}, 500

        if user is None or password is None or sudoers is None or email is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER",
                "user (str), password (str), sudoers (bool) and email (str) parameters are required",
            )

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
            conn = ldap.initialize("ldap://" + config.Config.LDAP_HOST)
            dn_user = "uid=" + user + ",ou=people," + config.Config.LDAP_BASE_DN
            enc_passwd = bytes(password, "utf-8")
            salt = os.urandom(16)
            sha = hashlib.sha1(enc_passwd)  # nosec
            sha.update(salt)
            digest = sha.digest()
            b64_envelop = encode(digest + salt)
            passwd = "{{SSHA}}{}".format(b64_envelop.decode("utf-8"))
            attrs = [
                (
                    "objectClass",
                    [
                        "top".encode("utf-8"),
                        "person".encode("utf-8"),
                        "posixAccount".encode("utf-8"),
                        "shadowAccount".encode("utf-8"),
                        "inetOrgPerson".encode("utf-8"),
                        "organizationalPerson".encode("utf-8"),
                    ],
                ),
                ("uid", [str(user).encode("utf-8")]),
                ("uidNumber", [str(uid).encode("utf-8")]),
                ("gidNumber", [str(gid).encode("utf-8")]),
                ("mail", [email.encode("utf-8")]),
                ("cn", [str(user).encode("utf-8")]),
                ("sn", [str(user).encode("utf-8")]),
                ("loginShell", [str(shell).encode("utf-8")]),
                ("homeDirectory", (config.Config.USER_HOME + "/" + str(user)).encode("utf-8")),
                ("userPassword", [passwd.encode("utf-8")]),
            ]

            conn.simple_bind_s(config.Config.ROOT_DN, config.Config.ROOT_PW)

            # Create group first to prevent GID issue
            create_user_group = post(
                config.Config.FLASK_ENDPOINT + "/api/ldap/group",
                headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                data={"group": f"{group}", "gid": gid},
                verify=False,
            )  # nosec
            if create_user_group.status_code != 200:
                return errors.all_errors("COULD_NOT_CREATE_GROUP", str(create_user_group.text))

            # Assign user
            conn.add_s(dn_user, attrs)

            # Add user to group
            update_group = put(
                config.Config.FLASK_ENDPOINT + "/api/ldap/group",
                headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                data={"group": f"{group}", "user": user, "action": "add"},
                verify=False,
            )  # nosec
            if update_group.status_code != 200:
                return errors.all_errors(
                    "UNABLE_TO_ADD_USER_TO_GROUP", "User/Group created but could not add user to his group"
                )

            # Create home directory
            if create_home(user, group) is False:
                return errors.all_errors("UNABLE_CREATE_HOME", "User added but unable to create home director")

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
                grant_sudo = post(
                    config.Config.FLASK_ENDPOINT + "/api/ldap/sudo",
                    headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                    data={"user": user},
                    verify=False,  # nosec
                )
                if grant_sudo.status_code != 200:
                    return errors.all_errors("UNABLE_TO_GRANT_SUDO", "User added but unable to give admin permissions")

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
        if user is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "user (str) parameter is required")

        request_user = request.headers.get("X-SOCA-USER")
        if request_user is None:
            return errors.all_errors("X-SOCA-USER_MISSING")

        if request_user == user:
            return errors.all_errors("CLIENT_OWN_RESOURCE")

        ldap_base = config.Config.LDAP_BASE_DN
        try:
            conn = ldap.initialize("ldap://" + config.Config.LDAP_HOST)
            conn.simple_bind_s(config.Config.ROOT_DN, config.Config.ROOT_PW)
            group = f"{args['user']}{config.Config.GROUP_NAME_SUFFIX}"
            entries_to_delete = [
                "uid=" + user + ",ou=People," + ldap_base,
                "cn=" + group + ",ou=Group," + ldap_base,
                "cn=" + user + ",ou=Sudoers," + ldap_base,
            ]

            today = datetime.datetime.utcnow().strftime("%s")
            user_home = config.Config.USER_HOME + "/" + user
            backup_folder = config.Config.USER_HOME + "/" + user + "_" + today
            shutil.move(user_home, backup_folder)
            os.chmod(backup_folder, 0o700)
            for entry in entries_to_delete:
                try:
                    conn.delete_s(entry)
                except ldap.NO_SUCH_OBJECT:
                    if entry == "uid=" + user + ",ou=People," + ldap_base:
                        return {"success": False, "message": "Unknown user"}, 203
                    else:
                        pass
                except Exception as err:
                    return {"success": False, "message": "Unknown error: " + str(err)}, 500

            invalidate_api_key = delete(
                config.Config.FLASK_ENDPOINT + "/api/user/api_key",
                headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                data={"user": user},
                verify=False,
            )  # nosec

            if invalidate_api_key.status_code != 200:
                return errors.all_errors(
                    "API_KEY_NOT_DELETED", "User deleted but unable to deactivate API key. " + str(invalidate_api_key)
                )

            return {"success": True, "message": "Deleted user."}, 200

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)
