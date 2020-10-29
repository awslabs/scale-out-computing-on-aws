from flask_restful import Resource, reqparse
import config
import ldap
from models import db,ApiKeys
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
        parser.add_argument('user', type=str, location='args')
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return {"success": False, "message": "user can not be empty"}, 400

        ldap_host = config.Config.LDAP_HOST
        base_dn = config.Config.LDAP_BASE_DN

        try:
            con = ldap.initialize('ldap://{}'.format(ldap_host))
            sudoers_search_base = "ou=Sudoers," + base_dn
            sudoers_search_scope = ldap.SCOPE_SUBTREE
            sudoers_filter = 'cn=' + user
            is_sudo = con.search_s(sudoers_search_base, sudoers_search_scope, sudoers_filter)
            if is_sudo.__len__() > 0:
                return {'success': True, 'message': "User has SUDO permissions."}, 200
            else:
                return {'success': False, 'message': "User does not have SUDO permissions."}, 222

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
        parser.add_argument('user', type=str, location='form')
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return {"success": False, "message": "user can not be empty"}, 400

        # check if user exist
        ldap_host = config.Config.LDAP_HOST
        base_dn = config.Config.LDAP_BASE_DN
        try:
            conn = ldap.initialize('ldap://{}'.format(ldap_host))
            conn.simple_bind_s(config.Config.ROOT_DN, config.Config.ROOT_PW)
            dn_user = "cn=" + user + ",ou=Sudoers," + base_dn
            attrs = [
                    ('objectClass', ['top'.encode('utf-8'),
                                     'sudoRole'.encode('utf-8')]),
                    ('sudoHost', ['ALL'.encode('utf-8')]),
                    ('sudoUser', [str(user).encode('utf-8')]),
                    ('sudoCommand', ['ALL'.encode('utf-8')])
                ]

            conn.add_s(dn_user, attrs)
            change_user_key_scope = ApiKeys.query.filter_by(user=user, is_active=True).all()
            if change_user_key_scope:
                for key in change_user_key_scope:
                    key.scope = "sudo"
                    db.session.commit()
            return {"success": True, "message": user + " now has admin permission"}, 200

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)

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
        parser.add_argument('user', type=str, location='form')
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return {"success": False, "message": "user can not be empty"}, 400

        ldap_host = config.Config.LDAP_HOST
        base_dn = config.Config.LDAP_BASE_DN

        try:
            conn = ldap.initialize('ldap://{}'.format(ldap_host))
            conn.simple_bind_s(config.Config.ROOT_DN, config.Config.ROOT_PW)
            dn_user = "cn=" + user + ",ou=Sudoers," + base_dn
            conn.delete_s(dn_user)
            change_user_key_scope = ApiKeys.query.filter_by(user=user, is_active=True).all()
            if change_user_key_scope:
                for key in change_user_key_scope:
                    key.scope = "user"
                    db.session.commit()
            return {"success": True, "message": user + " does not have admin permission anymore"}, 200

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)
