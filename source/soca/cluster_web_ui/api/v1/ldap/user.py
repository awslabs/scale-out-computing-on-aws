import hashlib
import os
from base64 import b64encode as encode
from email.utils import parseaddr
import config
import ldap
import errors
from flask_restful import Resource, reqparse
from requests import get, post, put
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

def create_home(username):
    try:
        user_home = config.Config.USER_HOME
        key = rsa.generate_private_key(backend=crypto_default_backend(), public_exponent=65537, key_size=2048)
        private_key = key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.TraditionalOpenSSL,
            crypto_serialization.NoEncryption())
        public_key = key.public_key().public_bytes(
            crypto_serialization.Encoding.OpenSSH,
            crypto_serialization.PublicFormat.OpenSSH
        )
        private_key_str = private_key.decode('utf-8')
        public_key_str = public_key.decode('utf-8')
        # Create user directory structure and permissions
        user_path = user_home + '/' + username + '/.ssh'
        os.makedirs(user_path)
        shutil.copy('/etc/skel/.bashrc', user_path[:-4])
        shutil.copy('/etc/skel/.bash_profile', user_path[:-4])
        shutil.copy('/etc/skel/.bash_logout', user_path[:-4])
        print(private_key_str, file=open(user_path + '/id_rsa', 'w'))
        print(public_key_str, file=open(user_path + '/id_rsa.pub', 'w'))
        print(public_key_str, file=open(user_path + '/authorized_keys', 'w'))
        shutil.chown(user_home + '/' + username, user=username, group=username)
        shutil.chown(user_home + '/' + username + '/.ssh', user=username, group=username)
        shutil.chown(user_home + '/' + username + '/.ssh/authorized_keys', user=username, group=username)
        shutil.chown(user_home + '/' + username + '/.ssh/id_rsa', user=username, group=username)
        shutil.chown(user_home + '/' + username + '/.ssh/id_rsa.pub', user=username, group=username)
        os.chmod(user_home + '/' + username, 0o700)
        os.chmod(user_home + '/' + username + '/.ssh', 0o700)
        os.chmod(user_home + '/' + username + '/.ssh/id_rsa', 0o600)
        os.chmod(user_home + '/' + username + '/.ssh/authorized_keys', 0o600)
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
        parser.add_argument('user', type=str, location='args')
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "user (str) parameter is required")

        user_filter = 'cn='+user
        user_search_base = "ou=People," + config.Config.LDAP_BASE_DN
        user_search_scope = ldap.SCOPE_SUBTREE
        try:
            conn = ldap.initialize('ldap://' + config.Config.LDAP_HOST)
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
        parser.add_argument('user', type=str, location='form')
        parser.add_argument('password', type=str, location='form')
        parser.add_argument('sudoers', type=int, location='form')
        parser.add_argument('email', type=str, location='form')
        parser.add_argument('shell', type=str, location='form')
        parser.add_argument('uid', type=int, location='form')  # 0 = no value specified, use default one
        parser.add_argument('gid', type=int, location='form')  # 0 = no value specified, use default one
        args = parser.parse_args()
        user = ''.join(x for x in args["user"] if x.isalpha() or x.isdigit()).lower()  # Sanitize input
        password = args["password"]
        sudoers = args["sudoers"]
        email = args["email"]
        uid = args["uid"]
        gid = args["gid"]
        shell = args["shell"]
        if shell is None:
            shell = "/bin/bash"

        get_id = get(config.Config.FLASK_ENDPOINT + '/api/ldap/ids',
                     headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                     verify=False)
        if get_id.status_code == 200:
            current_ldap_ids = (json.loads(get_id.text))
        else:
            logger.error("/api/ldap/ids returned error : " + str(get_id.__dict__))
            return {"success": False, "message": "/api/ldap/ids returned error: " +str(get_id.__dict__)}, 500

        if user is None or password is None or sudoers is None or email is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "user (str), password (str), sudoers (bool) and email (str) parameters are required")

        # Note: parseaddr adheres to rfc5322 , which means user@domain is a correct address.
        # You do not necessarily need to add a tld at the end
        if "@" not in parseaddr(email)[1]:
            return errors.all_errors("INVALID_EMAIL_ADDRESS")

        if uid == 0:
            uid = current_ldap_ids["message"]['proposed_uid']
        else:
            if uid in current_ldap_ids["message"]['uid_in_use']:
                return errors.all_errors("UID_ALREADY_IN_USE")

        if gid == 0:
            gid = current_ldap_ids["message"]['proposed_gid']
        else:
            if gid in current_ldap_ids["message"]['gid_in_use']:
                return errors.all_errors("GID_ALREADY_IN_USE")
        try:
            conn = ldap.initialize('ldap://' + config.Config.LDAP_HOST)
            dn_user = "uid=" + user + ",ou=people," + config.Config.LDAP_BASE_DN
            enc_passwd = bytes(password, 'utf-8')
            salt = os.urandom(16)
            sha = hashlib.sha1(enc_passwd)
            sha.update(salt)
            digest = sha.digest()
            b64_envelop = encode(digest + salt)
            passwd = '{{SSHA}}{}'.format(b64_envelop.decode('utf-8'))
            attrs = [
                    ('objectClass', ['top'.encode('utf-8'),
                                     'person'.encode('utf-8'),
                                     'posixAccount'.encode('utf-8'),
                                     'shadowAccount'.encode('utf-8'),
                                     'inetOrgPerson'.encode('utf-8'),
                                     'organizationalPerson'.encode('utf-8')]),
                    ('uid', [str(user).encode('utf-8')]),
                    ('uidNumber', [str(uid).encode('utf-8')]),
                    ('gidNumber', [str(gid).encode('utf-8')]),
                    ('mail', [email.encode('utf-8')]),
                    ('cn', [str(user).encode('utf-8')]),
                    ('sn', [str(user).encode('utf-8')]),
                    ('loginShell', [str(shell).encode('utf-8')]),
                    ('homeDirectory', (config.Config.USER_HOME + '/' + str(user)).encode('utf-8')),
                    ('userPassword', [passwd.encode('utf-8')])
                ]

            conn.simple_bind_s(config.Config.ROOT_DN, config.Config.ROOT_PW)

            # Create group first to prevent GID issue
            create_user_group = post(config.Config.FLASK_ENDPOINT + "/api/ldap/group",
                                     headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                                     data={"group": user, "gid": gid},
                                     verify=False)
            if create_user_group.status_code != 200:
                return errors.all_errors("COULD_NOT_CREATE_GROUP", str(create_user_group.text))

            # Assign user
            conn.add_s(dn_user, attrs)

            # Add user to group
            update_group = put(config.Config.FLASK_ENDPOINT + "/api/ldap/group",
                               headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                               data={"group": user,
                                     "user": user,
                                     "action": "add"},
                               verify=False)
            if update_group.status_code != 200:
                return {"success": True, "message": "User/Group created but could not add user to his group"}, 203

            # Create home directory
            if create_home(user) is False:
                return {"success": False, "message": "User added but unable to create home directory"}, 500

            # Add Sudo permission
            if sudoers == 1:
                grant_sudo = post(config.Config.FLASK_ENDPOINT + "/api/ldap/sudo",
                                 headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                                 data={"user": user},
                                 verify=False
                                 )
                if grant_sudo.status_code != 200:
                    return {"success": False, "message": "User added but unable to give admin permissions"}, 500

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
          400:
            description: Malformed client input
                """
        parser = reqparse.RequestParser()
        parser.add_argument('user', type=str, location='form')
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
            conn = ldap.initialize('ldap://' + config.Config.LDAP_HOST)
            conn.simple_bind_s(config.Config.ROOT_DN, config.Config.ROOT_PW)

            entries_to_delete = ["uid=" + user + ",ou=People," + ldap_base,
                                 "cn=" + user + ",ou=Group," + ldap_base,
                                 "cn=" + user + ",ou=Sudoers," + ldap_base]

            today = datetime.datetime.utcnow().strftime("%s")
            user_home = config.Config.USER_HOME + "/" + user
            backup_folder = config.Config.USER_HOME + "/" + user + "_" + today
            shutil.move(user_home, backup_folder)
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
            return {"success": True, "message": "Deleted user."}, 200

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)
