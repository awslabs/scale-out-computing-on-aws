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
import re
import stat
from base64 import b64encode as encode
from email.utils import parseaddr
import config
from flask_restful import Resource, reqparse
import logging
from flask import request
from decorators import private_api, admin_api, feature_flag
import sys
import shutil
from datetime import datetime, timezone
from utils.identity_provider_client import SocaIdentityProviderClient
import struct
from utils.subprocess_client import SocaSubprocessClient
from utils.http_client import SocaHttpClient
from utils.error import SocaError
from utils.response import SocaResponse
import grp
import ldap

logger = logging.getLogger("soca_logger")
import time


def populate_ssh_keys(username: str, user_path: str) -> bool:
    """
    Generate SSH keypairs and store them in the user's home directory
    """
    logger.info(f"Generating SSH keypairs for {username=} / {user_path=}")

    if not username:
        logger.error("populate_ssh_keys Missing username")
        return False

    if not user_path:
        logger.error("populate_ssh_keys Missing user_path")
        return False

    # Create the .ssh directory for the user
    _ssh_path_str: str = f"{user_path}/.ssh"

    # The SSH keys to generate from ssh-keygen
    # This is done as a dict so you can modify the per-key args if desired
    _ssh_key_dict: dict = {
        # Adjust the generated key types for your specific environment based on the security threats and policy
        "rsa": {
            "command": f"su {username} -c 'ssh-keygen -t rsa -b 4096 -f {_ssh_path_str}/id_rsa -N \""
            "\" '",
        },
        "ed25519": {
            "command": f"su {username} -c 'ssh-keygen -t ed25519 -f {_ssh_path_str}/id_ed25519 -N \""
            "\" '",
        },
        # "dsa":  {
        #     "command": f"su {username} -c 'ssh-keygen -t dsa -f {_ssh_path_str}/id_dsa -N \"""\" '",
        # },
        # "ecdsa": {
        #     "command": f"su {username} -c 'ssh-keygen -t ecdsa -f {_ssh_path_str}/id_ecdsa -N \"""\" '",
        # },
    }

    logger.debug(f"{_ssh_key_dict}")

    _ssh_keys_generated: int = 0
    for _ssh_key_type, _ssh_keygen_data in _ssh_key_dict.items():
        logger.info(f"Trying to create SSH key of type {_ssh_key_type}")
        _cmd = _ssh_keygen_data.get("command", "")

        if not _cmd:
            logger.error(f"Missing command for SSH keytype - {_ssh_key_type}")
            continue

        logger.info(f"Generating ssh_key {_ssh_key_type=} via {_cmd=}")
        try:
            _ssh_key_result = SocaSubprocessClient(run_command=_cmd).run()
            if _ssh_key_result.get("message") is False:
                logger.error(
                    f"Unable to generate {_ssh_key_type} - {_ssh_key_result=} because of  {_ssh_key_result.get('message')}"
                )
                continue
            else:
                logger.debug(
                    f"ssh_key_result for type {_ssh_key_type} - {_ssh_key_result=}"
                )
                _ssh_keys_generated += 1

        except Exception as e:
            logger.error(
                f"Unable to generate SSH keypair for keytype {_ssh_key_type} - {e}"
            )
            continue
        finally:
            logger.debug(f"ssh_key_result for type {_ssh_key_type}")

    # Did we generate all the desired keypair types?
    if _ssh_keys_generated == len(_ssh_key_dict):
        logger.info(f"Done generating all ({_ssh_keys_generated}) keypairs for user")
    else:
        logger.warning(
            f"Unable to generate all SSH keypairs - Generated {_ssh_keys_generated} of {len(_ssh_key_dict)} keypairs. Check log for errors"
        )

    return True


def create_home(username: str, group: str):
    try:
        user_home = config.Config.USER_HOME
        logger.info(f"Creating new HOME for {username=}/{group=}/{user_home=}")

        # Create user directory structure

        user_path = f"{user_home}/{username}"

        for _create_dir in [user_path, f"{user_path}/.ssh"]:
            logger.info(f"Creating {_create_dir}")

            if ".ssh" in _create_dir:
                # Keep the SSH directory protected - only accessible by the user
                _permissions = stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR
            else:
                # Home dir by default allows the user group to have access
                _permissions = (
                    stat.S_IRUSR
                    | stat.S_IWUSR
                    | stat.S_IXUSR
                    | stat.S_IRGRP
                    | stat.S_IXGRP
                )

            os.makedirs(
                name=_create_dir,
                mode=_permissions,
                exist_ok=True,
            )
            # Just to make sure
            os.chmod(path=_create_dir, mode=_permissions)

        # Copy default .bash profile
        _default_skel = [
            "/etc/skel/.bashrc",
            "/etc/skel/.bash_profile",
            "/etc/skel/.bash_logout",
        ]
        for _skel in _default_skel:
            if os.path.exists(_skel):
                shutil.copy(src=_skel, dst=user_path)
            else:
                logger.warning(
                    f"Unable to copy {_skel}, file does not exist, ignoring ... "
                )

        # Adjust file/folder ownership
        try:
            group = grp.getgrnam(group).gr_name
        except KeyError:
            # Handle case where group does not exist, e.g when using an external directory
            logger.warning(f"Unable to determine gr_name for {group}")
            group = None

        for _path in [
            f"{user_path}",
            f"{user_path}/.ssh",
            f"{user_path}/.bashrc",
            f"{user_path}/.bash_profile",
            f"{user_path}/.bash_logout",
        ]:
            logger.info(
                f"About to chown {_path=} hierarchy with {username=} and {group=}"
            )
            if os.path.exists(_path):
                shutil.chown(path=_path, user=username, group=group)
            else:
                logger.warning(f"Unable to chown {_path}, path does not exist")

        logger.info(f"Create SSH keypairs for {username}")
        if populate_ssh_keys(username=username, user_path=user_path) is False:
            logger.error(f"Unable to generate SSH keypairs for user {username}")
            return False

        logger.info("Configuring authorized_keys based on ssh keypairs created")
        _authorized_keys_file = f"{user_path}/.ssh/authorized_keys"
        os.makedirs(os.path.dirname(_authorized_keys_file), exist_ok=True)
        with open(_authorized_keys_file, "a") as authorized_keys_file:
            for filename in os.listdir(f"{user_path}/.ssh"):
                if filename.endswith(".pub"):
                    pub_key_path = os.path.join(f"{user_path}/.ssh", filename)
                    with open(pub_key_path, "r") as pub_key_file:
                        pub_key_content = pub_key_file.read()
                        authorized_keys_file.write(pub_key_content + "\n")

        logger.info(
            "Enforcing right permissions for all files within .ssh folder post keypair creation"
        )
        for root, dirs, files in os.walk(f"{user_path}/.ssh"):
            for _file in files:
                _file_path = os.path.join(root, _file)
                logger.info(f"Changing permissions for {_file_path}")
                os.chmod(_file_path, stat.S_IRUSR | stat.S_IWUSR)
                shutil.chown(path=_file_path, user=username, group=group)

        return True

    except Exception as _e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        logger.error(exc_type, fname, exc_tb.tb_lineno)
        return False


class User(Resource):
    @private_api
    def get(self):
        """
        Get user information
        ---
        openapi: 3.1.0
        operationId: getLdapUser
        tags:
          - User Management
        summary: Get user information
        description: Retrieve detailed information for a specific LDAP user by username or DN
        security:
          - socaAuth: []
        parameters:
          - name: user
            in: query
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 256
              example: "john.doe"
            description: Username or DN of the user to retrieve
        responses:
          '200':
            description: Successfully retrieved user information
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: array
                      items:
                        type: array
                        description: LDAP entry data
                      example: [["cn=john.doe,ou=people,dc=soca,dc=local", {"uid": ["john.doe"]}]]
          '203':
            description: User not found
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "User not found"
          '400':
            description: Missing required parameter
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Missing required parameter: user"
          '500':
            description: Internal server error
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to connect to LDAP server"
        components:
          securitySchemes:
            socaAuth:
              type: apiKey
              in: header
              name: X-SOCA-USER
              description: SOCA username for authentication
            socaToken:
              type: apiKey
              in: header
              name: X-SOCA-TOKEN
              description: SOCA authentication token
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="args")
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        try:

            if config.Config.DIRECTORY_AUTH_PROVIDER in [
                "openldap",
                "existing_openldap",
            ]:
                _filter = f"(&(objectClass=person)(uid={user}))"
                _attrs = ["uid"]
            else:
                if config.Config.DIRECTORY_PEOPLE_SEARCH_BASE.lower() in user.lower():
                    _filter = f"(&(objectClass=user)(distinguishedName={user}))"
                else:
                    _filter = f"(&(objectClass=user)(sAMAccountName={user}))"
                # Attrs is important otherwise response will contains non-utf8 char (sID etc)
                _attrs = ["sAMAccountName"]

            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            _search_user = _soca_identity_client.search(
                base=config.Config.DIRECTORY_PEOPLE_SEARCH_BASE,
                filter=_filter,
                attr_list=_attrs,
            )

            if _search_user.success:
                return SocaResponse(
                    success=True, message=_search_user.message
                ).as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to find user because of {_search_user.message}"
                ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

    @admin_api
    @feature_flag(flag_name="USERS_GROUPS_MANAGEMENT", mode="api")
    def post(self):
        """
        Create new user
        ---
        openapi: 3.1.0
        operationId: createLdapUser
        tags:
          - User Management
        summary: Create new user
        description: Create a new LDAP user with home directory, SSH keys, and group membership
        security:
          - socaAuth: []
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - user
                  - password
                  - sudoers
                  - email
                properties:
                  user:
                    type: string
                    description: Username for the new user (alphanumeric, _, -, . allowed, max 31 chars)
                    minLength: 1
                    maxLength: 31
                    pattern: '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'
                    example: "john.doe"
                  password:
                    type: string
                    description: Password for the new user
                    minLength: 1
                    format: password
                    example: "SecurePass123!"
                  sudoers:
                    type: integer
                    description: Grant sudo permissions (1 = yes, 0 = no)
                    enum: [0, 1]
                    example: 0
                  email:
                    type: string
                    description: Email address for the user
                    format: email
                    example: "john.doe@company.com"
                  shell:
                    type: string
                    description: Login shell for the user
                    default: "/bin/bash"
                    example: "/bin/bash"
                  uid:
                    type: integer
                    description: Linux UID (0 = auto-assign)
                    minimum: 0
                    maximum: 65535
                    default: 0
                    example: 1001
                  gid:
                    type: integer
                    description: Linux GID (0 = auto-assign)
                    minimum: 0
                    maximum: 65535
                    default: 0
                    example: 1001
        responses:
          '200':
            description: User created successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: string
                      example: "User created"
          '203':
            description: User already exists
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to create user, john.doe already exist"
          '400':
            description: Invalid input parameters
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Missing required parameter: user"
          '500':
            description: Internal server error
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to create user due to LDAP error"
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
        
        if args.get("user", None) is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        if re.match(config.Config.USER_REGEX_PATTERN, args["user"]):
            user = args["user"].lower()
        else:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"User {args['user']} is not valid, must match {config.Config.USER_REGEX_PATTERN} (contains -and start with- only alpha-numerical characters plus _ . - and must be 31 chars max"
            ).as_flask()

        password = args["password"]
        sudoers = args["sudoers"]
        email = args["email"]
        uid = args["uid"]
        gid = args["gid"]
        shell = args["shell"]
        group = f"{args['user']}{config.Config.DIRECTORY_GROUP_NAME_SUFFIX}"

        people_search_base = config.Config.DIRECTORY_PEOPLE_SEARCH_BASE

        if shell is None:
            logger.warning(
                "shell not specified for new user creation, default to /bin/bash"
            )
            shell = "/bin/bash"

        if password is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="password").as_flask()

        if sudoers is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="sudoers").as_flask()

        if email is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="email").as_flask()

        _get_id = SocaHttpClient(
            endpoint="/api/ldap/ids",
            headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
        ).get()
        if _get_id.success:
            current_ldap_ids = _get_id.message
        else:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"/api/ldap/ids returned error: {_get_id.message}"
            ).as_flask()

        if uid == 0:
            uid = current_ldap_ids["proposed_uid"]
        else:
            if uid in current_ldap_ids["uid_in_use"]:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to create user {user}, UID {uid} already in use"
                ).as_flask()

        if gid == 0:
            gid = current_ldap_ids["proposed_gid"]
        else:
            if gid in current_ldap_ids["gid_in_use"]:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to create user {user}, GID {gid} already in use"
                ).as_flask()

        # Note: parseaddr adheres to rfc5322 , which means user@domain is a correct address.
        # You do not necessarily need to add a tld at the end
        if "@" not in parseaddr(email)[1]:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Unable to create user {user}, Invalid email address"
            ).as_flask()

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()

            _is_user_exist = SocaHttpClient(
                endpoint="/api/ldap/user",
                headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
            ).get(params={"user": user})
            if _is_user_exist.success:
                if len(_is_user_exist.message) == 0:
                    pass
                else:
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper=f"Unable to create user, {user} already exist"
                    ).as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to check if user {user} already exist, {_is_user_exist.message}"
                ).as_flask()

            if config.Config.DIRECTORY_AUTH_PROVIDER in [
                "openldap",
                "existing_openldap",
            ]:
                _dn_user = f"uid={user},{people_search_base}"
                enc_passwd = bytes(password, "utf-8")
                salt = os.urandom(16)
                sha = hashlib.sha1(enc_passwd)  # nosec
                sha.update(salt)
                digest = sha.digest()
                b64_envelop = encode(digest + salt)
                passwd = "{{SSHA}}{}".format(b64_envelop.decode("utf-8"))
                _attrs = [
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
                    ("mail", [str(email).encode("utf-8")]),
                    ("cn", [str(user).encode("utf-8")]),
                    ("sn", [str(user).encode("utf-8")]),
                    ("loginShell", [str(shell).encode("utf-8")]),
                    (
                        "homeDirectory",
                        (config.Config.USER_HOME + "/" + str(user)).encode("utf-8"),
                    ),
                    ("userPassword", [passwd.encode("utf-8")]),
                ]

            else:
                # note: for MAD/SAD, password management is done via LambDa
                _dn_user = f"cn={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}"
                _attrs = [
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
                    ("mail", [str(email).encode("utf-8")]),
                    ("sAMAccountName", [str(user).encode("utf-8")]),
                    (
                        "userPrincipalName",
                        [
                            str(
                                user + "@" + config.Config.DIRECTORY_DOMAIN_NAME
                            ).encode("utf-8")
                        ],
                    ),
                    ("cn", [str(user).encode("utf-8")]),
                    ("uidNumber", [str(uid).encode("utf-8")]),
                    ("uid", [str(uid).encode("utf-8")]),
                    ("gidNumber", [str(gid).encode("utf-8")]),
                    ("loginShell", [shell.encode("utf-8")]),
                    (
                        "homeDirectory",
                        (str(config.Config.USER_HOME) + "/" + str(user)).encode(
                            "utf-8"
                        ),
                    ),
                ]

            logger.info(f"About to create new account {user}")
            logger.info("Create group first to prevent GID issue")
            _create_user_group = SocaHttpClient(
                endpoint="/api/ldap/group",
                headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
            ).post(data={"group": f"{group}", "gid": gid})
            if not _create_user_group.success:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to create user {user}, unable to create group {group} because of {_create_user_group.message}"
                ).as_flask()
            logger.info(f"Group {group} created successfully")

            logger.info(f"About to create actual user")
            _user_create = _soca_identity_client.add(dn=_dn_user, mod_list=_attrs)
            if not _user_create.success:
                logger.info(
                    f"Unable to create user {_dn_user}, deleting associated group {group}"
                )
                SocaHttpClient(
                    endpoint="/api/ldap/group",
                    headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                ).delete(data={"group": f"{group}"})
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to create user {user}, Unable to create {_dn_user} because of {_user_create.message}"
                ).as_flask()

            _password_reset_request = 0
            if config.Config.DIRECTORY_AUTH_PROVIDER in [
                "aws_ds_managed_activedirectory",
            ]:
                logger.info(
                    "Set up Password reset for AWS Directory Service AD provider"
                )
                _pw_reset_request = SocaHttpClient(
                    endpoint="/api/user/reset_password",
                    headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                ).post(
                    data={
                        "user": user,
                        "password": password,
                        "directory_id": config.Config.DIRECTORY_SERVICE_ID,
                    }
                )
                while not _pw_reset_request.success:
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper=f"{_pw_reset_request.message}"
                    ).as_flask()

            logger.info("Creating Home Directory for user")
            if create_home(user, group) is False:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"User created but could not create {user} home directory."
                ).as_flask()
            logger.info("Home Directory created successfully")

            logger.info("Creating API key for user")
            try:
                SocaHttpClient(
                    endpoint="/api/user/api_key",
                    headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                ).get(params={"user": user})
            except Exception as err:
                logger.error(
                    f"User created but unable to create API key. SOCA will try to generate it when user log in for the first time {err}"
                )

            if sudoers == 1:
                logger.info(f"Granting Sudo permission to {user}")
                _grant_sudo = SocaHttpClient(
                    endpoint="/api/ldap/sudo",
                    headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                ).post(data={"user": user})

                if not _grant_sudo.success:
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper=f"User created but unable to give admin permissions."
                    ).as_flask()
                else:
                    logger.info("SUDO Permission granted successfully")
            else:
                logger.info("No SUDO permissions requested for this user")

            logger.info(f"Adding user {user} to group {group}")
            _update_group = SocaHttpClient(
                endpoint="/api/ldap/group",
                headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
            ).put(data={"group": f"{group}", "user": user, "action": "add"})

            if not _update_group.success:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"{user} & group {group} created but could not add user to his group."
                ).as_flask()
            else:
                if config.Config.DIRECTORY_AUTH_PROVIDER in [
                    "aws_ds_managed_activedirectory",
                ]:
                    # Default GroupID point to "Domain Users". We update this to match the group we just have created for the user
                    # Any file created by the user will be owned by <user> : <user_group>
                    _find_group_sid = _soca_identity_client.search(
                        base=config.Config.DIRECTORY_GROUP_SEARCH_BASE,
                        filter=f"(&(objectClass=group)(cn={group}))",
                        attr_list=["objectSid"],
                    )
                    if _find_group_sid.get("success"):
                        _group_sid = _find_group_sid.get("message")[0][1].get(
                            "objectSid"
                        )[0]
                        # Extract the RID from the group SID
                        # The RID is stored in the last 4 bytes of the SID
                        _group_rid = struct.unpack("I", _group_sid[-4:])[0]

                        # Add new primaryGroupID attr for user creation
                        # _attrs.append(("primaryGroupID", [str(_group_rid).encode("utf-8")]))
                        _replace_primary_group_id = _soca_identity_client.modify(
                            _dn_user,
                            [
                                (
                                    ldap.MOD_REPLACE,
                                    "primaryGroupID",
                                    [str(_group_rid).encode("utf-8")],
                                )
                            ],
                        )
                        if _replace_primary_group_id.get("success") is False:
                            return SocaError.IDENTITY_PROVIDER_ERROR(
                                helper=f"Unable to set primaryGroupID for user {_dn_user} because of {_replace_primary_group_id.get('message')}"
                            ).as_flask()
                    else:
                        return SocaError.IDENTITY_PROVIDER_ERROR(
                            helper=f"Unable to find objectSid for {group} because of {_find_group_sid}"
                        ).as_flask()

            logger.info(f"{user} has been added to {group} successfully")

            return SocaResponse(success=True, message="User created").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

    @admin_api
    @feature_flag(flag_name="USERS_GROUPS_MANAGEMENT", mode="api")
    def delete(self):
        """
        Delete user
        ---
        openapi: 3.1.0
        operationId: deleteLdapUser
        tags:
          - User Management
        summary: Delete user
        description: Delete a LDAP user and associated group. Home directory is backed up with timestamp suffix.
        security:
          - socaAuth: []
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - user
                properties:
                  user:
                    type: string
                    description: Username of the user to delete
                    minLength: 1
                    maxLength: 31
                    pattern: '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'
                    example: "john.doe"
        responses:
          '200':
            description: User deleted successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: string
                      example: "Deleted user"
          '203':
            description: User not found
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to delete user, john.doe does not seem to exist"
          '400':
            description: Invalid request or self-deletion attempt
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "You cannot request to delete your own account"
          '500':
            description: Internal server error
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to delete user due to LDAP error"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="form")
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        request_user = request.headers.get("X-SOCA-USER")
        if request_user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        if request_user == user:
            return SocaError.GENERIC_ERROR(
                helper="You cannot request to delete your own account"
            ).as_flask()

        _is_user_exist = SocaHttpClient(
            endpoint="/api/ldap/user",
            headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
        ).get(params={"user": user})

        if _is_user_exist.success:
            if len(_is_user_exist.message) != 1:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to delete user, {user} does not seems to exist"
                ).as_flask()
        else:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Unable to check if user {user} already exist, {_is_user_exist.message}"
            ).as_flask()

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()

            if config.Config.DIRECTORY_AUTH_PROVIDER in [
                "openldap",
                "existing_openldap",
            ]:
                group = f"{args['user']}{config.Config.DIRECTORY_GROUP_NAME_SUFFIX}"
                entries_to_delete = [
                    f"uid={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}",
                    f"cn={group},{config.Config.DIRECTORY_GROUP_SEARCH_BASE}",
                    f"cn={user},{config.Config.DIRECTORY_ADMIN_SEARCH_BASE}",
                ]
            else:
                group = f"{args['user']}{config.Config.DIRECTORY_GROUP_NAME_SUFFIX}"
                entries_to_delete = [
                    f"cn={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}",
                    f"cn={group},{config.Config.DIRECTORY_GROUP_SEARCH_BASE}",
                ]

            today = datetime.now(timezone.utc).strftime("%s")
            user_home = config.Config.USER_HOME + "/" + user
            backup_folder = config.Config.USER_HOME + "/" + user + "_" + today
            logger.info(f"Creating backup home folder for {user} -> {backup_folder}")
            try:
                shutil.move(user_home, backup_folder)
                os.chmod(backup_folder, 0o700)
            except Exception as err:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to create backup home folder for {user} due to {err}. Verify if {user_home} exists. Backup folrder to be created: {backup_folder}"
                ).as_flask()

            for entry in entries_to_delete:
                _delete_attempt = _soca_identity_client.delete(dn=entry)
                # note: ldap.NO_SUCH_OBJECT will always return success=True.
                # success=False only if the DELETE command was not able to delete an existing object for whatever reasons
                if not _delete_attempt.success:
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper=f"Unable to delete {entry} because of {_delete_attempt.message}"
                    ).as_flask()

            _invalidate_api_key = SocaHttpClient(
                endpoint="/api/user/api_key",
                headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
            ).delete(data={"user": user})
            if not _invalidate_api_key.success:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"{user} deleted but unable to invalidate API key because of {_invalidate_api_key.message}."
                ).as_flask()

            return SocaResponse(success=True, message="Deleted user").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()
