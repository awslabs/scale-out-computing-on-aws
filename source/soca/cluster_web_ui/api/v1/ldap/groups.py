import config
import ldap
from flask_restful import Resource
import logging
from decorators import private_api
import errors
import re

logger = logging.getLogger("api")


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
        ldap_host = config.Config.LDAP_HOST
        base_dn = config.Config.LDAP_BASE_DN
        all_ldap_groups = {}
        group_search_base = "ou=Group," + base_dn
        group_search_scope = ldap.SCOPE_SUBTREE
        group_filter = 'cn=*'
        try:
            con = ldap.initialize('ldap://{}'.format(ldap_host))
            groups = con.search_s(group_search_base, group_search_scope, group_filter, ["cn", "memberUid"])
            for group in groups:
                group_base = group[0]
                group_name = group[1]['cn'][0].decode('utf-8')
                members = []
                if "memberUid" in group[1].keys():
                    for member in group[1]["memberUid"]:
                        user = re.match("uid=(\w+),", member.decode("utf-8"))
                        if user:
                            members.append(user.group(1))
                        else:
                            # handle case where lDAP ownership was done outside of SOCA
                            members.append(member.decode("utf-8"))
                            # return {"success": False, "message": "Unable to retrieve memberUid for this group: " + str(group_base) + "members: "+str(group[1]["memberUid"])}, 500

                all_ldap_groups[group_name] = {"group_dn": group_base, "members": members}

            return {"success": True, "message": all_ldap_groups}, 200

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)
