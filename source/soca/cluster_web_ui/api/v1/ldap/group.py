import config
import ldap
from flask_restful import Resource, reqparse
from requests import get, put
import logging
from flask import request
from decorators import private_api, admin_api
import re
import errors
logger = logging.getLogger("api")


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
        parser.add_argument('group', type=str, location='args')
        args = parser.parse_args()
        group = args["group"]
        if group is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "group (str) parameter is required")

        group_search_base = "ou=Group," + config.Config.LDAP_BASE_DN
        group_search_scope = ldap.SCOPE_SUBTREE
        group_filter = 'cn=' + group
        try:
            conn = ldap.initialize('ldap://' + config.Config.LDAP_HOST)
            groups = conn.search_s(group_search_base, group_search_scope, group_filter, ["cn", "memberUid"])
            if groups.__len__() == 0:
                return errors.all_errors("GROUP_DO_NOT_EXIST")

            for group in groups:
                group_base = group[0]
                members = []
                if "memberUid" in group[1].keys():
                    for member in group[1]["memberUid"]:
                        user = re.match("uid=(\w+),", member.decode("utf-8"))
                        if user:
                            members.append(user.group(1))
                        else:
                            members.append(member.decode("utf-8"))
                            # return {"success": False, "message": "Unable to retrieve memberUid for this group: " + str(group_base) + "members: "+str(group[1]["memberUid"])}, 500

            return {"success": True, "message": {"group_dn": group_base, "members": members}}

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)

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
        parser.add_argument('group', type=str, location='form')
        parser.add_argument('gid', type=int, location='form')
        parser.add_argument('members', type=str, location='form')  # comma separated list of users

        args = parser.parse_args()
        group = ''.join(x for x in args["group"] if x.isalpha() or x.isdigit())  # Sanitize Input
        gid = args["gid"]

        if args["members"] is None:
            members = []
        else:
            members = args["members"].split(",")

        get_gid = get(config.Config.FLASK_ENDPOINT + '/api/ldap/ids',
                      headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                      verify=False)

        if get_gid.status_code == 200:
            current_ldap_gids = get_gid.json()
        else:
            return errors.all_errors("UNABLE_RETRIEVE_IDS", str(get_gid.text))

        if gid is None:
            group_id = current_ldap_gids["message"]["proposed_gid"]
        else:
            if gid in current_ldap_gids["message"]["gid_in_use"]:
                return errors.all_errors("GID_ALREADY_IN_USE")
            group_id = gid

        if group is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "group (str) parameter is required")

        try:
            conn = ldap.initialize('ldap://' + config.Config.LDAP_HOST)
            group_members = []
            if members is not None:
                if not isinstance(members, list):
                    return {"success": False,
                            "message": "users must be a valid list"}, 400

                get_all_users = get(config.Config.FLASK_ENDPOINT + "/api/ldap/users",
                                    headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                                    verify=False)

                if get_all_users.status_code == 200:
                    all_users = get_all_users.json()["message"]
                else:
                    return {"success": False, "message": "Unable to retrieve the list of SOCA users " + str(get_all_users.json())}, 212

                for member in members:
                    if member not in all_users.keys():
                        return {"success": False,
                                "message": "Unable to create group because user (" + member +") does not exist."}, 211
                    else:
                        group_members.append(member)

            group_dn = "cn=" + group + ",ou=Group," + config.Config.LDAP_BASE_DN
            attrs = [
                ('objectClass', ['top'.encode('utf-8'),
                                 'posixGroup'.encode('utf-8')]),
                ('gidNumber', [str(group_id).encode('utf-8')]),
                ('cn', [str(group).encode('utf-8')],)
            ]

            conn.simple_bind_s(config.Config.ROOT_DN, config.Config.ROOT_PW)
            conn.add_s(group_dn, attrs)
            users_not_added = []
            for member in group_members:
                add_member_to_group = put(config.Config.FLASK_ENDPOINT + "/api/ldap/group",
                                          headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                                          data={"group": group,
                                                "user": member,
                                                "action": "add"},
                                          verify=False)
                if add_member_to_group.status_code != 200:
                    users_not_added.append(member)

            if users_not_added.__len__() == 0:
                return {"success": True, "message": "Group created successfully"}, 200
            else:
                return {"success": True, "message": "Group created successfully but unable to add some users: " + str(users_not_added)}, 214

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)


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
            description: Deleted user
          203:
            description: Unknown user
          400:
            description: Malformed client input
                """
        parser = reqparse.RequestParser()
        parser.add_argument('group', type=str, location='form')
        args = parser.parse_args()
        group = args["group"]

        request_user = request.headers.get("X-SOCA-USER")
        if request_user is None:
            return errors.all_errors("X-SOCA-USER_MISSING")

        if request_user == group:
            return errors.all_errors("CLIENT_OWN_RESOURCE")

        if group is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "group (str) parameter is required")

        ldap_base = config.Config.LDAP_BASE_DN
        try:
            conn = ldap.initialize('ldap://' + config.Config.LDAP_HOST)
            conn.simple_bind_s(config.Config.ROOT_DN, config.Config.ROOT_PW)
            conn.delete_s("cn=" + group + ",ou=Group," + ldap_base)
            return {"success": True, "message": "Deleted user."}, 200
        except Exception as err:
            return errors.all_errors(type(err).__name__, err)

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
        parser.add_argument('group', type=str, location='form')
        parser.add_argument('user', type=str, location='form')
        parser.add_argument('action', type=str, location='form')
        args = parser.parse_args()
        group = args["group"]
        user = args["user"]
        action = args["action"]
        ALLOWED_ACTIONS = ["add", "remove"]
        if user is None or group is None or action is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "user (str), group (str) and action (str) parameters are required")

        if action not in ALLOWED_ACTIONS:
            return {"success": False,
                    "message": "This action is not supported"}, 400

        try:
            conn = ldap.initialize('ldap://' + config.Config.LDAP_HOST)
            user_dn = "uid=" + user + ",ou=People," + config.Config.LDAP_BASE_DN
            group_dn = "cn=" + group + ",ou=Group," + config.Config.LDAP_BASE_DN

            get_all_users = get(config.Config.FLASK_ENDPOINT + "/api/ldap/users",
                                headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                                verify=False)

            if get_all_users.status_code == 200:
                all_users = get_all_users.json()["message"]
                if user_dn not in all_users.values():
                    return {"success": False,
                            "message": "User do not exist."}, 212
            else:
                return {"success": False,
                        "message": "Unable to retrieve list of LDAP users. " + str(get_all_users._content)}, 500

            if action == "add":
                mod_attrs = [(ldap.MOD_ADD, 'memberUid', [user.encode("utf-8")])]
            else:
                mod_attrs = [(ldap.MOD_DELETE, 'memberUid', [user.encode("utf-8")])]

            conn.simple_bind_s(config.Config.ROOT_DN, config.Config.ROOT_PW)
            conn.modify_s(group_dn, mod_attrs)
            return {"success": True, "message": "LDAP attribute has been modified correctly"}, 200

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)
