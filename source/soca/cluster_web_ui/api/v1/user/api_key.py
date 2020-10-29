from flask_restful import Resource, reqparse
from models import db, ApiKeys
from requests import get
import datetime
import secrets
import config
from decorators import restricted_api, admin_api
import errors
import logging
logger = logging.getLogger("api")
class ApiKey(Resource):
    @restricted_api
    def get(self):
        """
        Retrieve API key of the user
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
            description: Return the token associated to the user
          203:
            description: No token detected
          400:
            description: Malformed client input
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location='args')
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "user (str) parameter is required")

        try:
            check_existing_key = ApiKeys.query.filter_by(user=user,
                                                         is_active=True).first()
            if check_existing_key:
                return {"success": True, "message": check_existing_key.token}, 200
            else:
                try:
                    permissions = get(config.Config.FLASK_ENDPOINT + "/api/ldap/sudo",
                                      headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                                      params={"user": user},
                                      verify=False)

                    if permissions.status_code == 200:
                        scope = "sudo"
                    else:
                        scope = "user"
                    api_token = secrets.token_hex(16)
                    new_key = ApiKeys(user=user,
                                      token=api_token,
                                      is_active=True,
                                      scope=scope,
                                      created_on=datetime.datetime.utcnow())
                    db.session.add(new_key)
                    db.session.commit()
                    return {"success": True,
                            "message": api_token}, 200

                except Exception as err:
                    return errors.all_errors(type(err).__name__, err)
        except Exception as err:
            return errors.all_errors(type(err).__name__, err)

    @restricted_api
    def delete(self):
        """
        Delete API key(s) associated to a user
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
                description: Key(s) has been deleted successfully.
            203:
                description: Unable to find a token.
            400:
               description: Client error.
        """
        parser = reqparse.RequestParser()
        parser.add_argument('user', type=str, location='form')
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "user (str) parameter is required")
        try:
            check_existing_keys = ApiKeys.query.filter_by(user=user, is_active=True).all()
            if check_existing_keys:
                for key in check_existing_keys:
                    key.is_active = False
                    key.deactivated_on = datetime.datetime.utcnow()
                    db.session.commit()
                return {"success": True, "message": "Successfully deactivated"}, 200
            else:
                return errors.all_errors("NO_ACTIVE_TOKEN")

        except Exception as err:
            return errors.all_errors(type(err).__name__, err)

