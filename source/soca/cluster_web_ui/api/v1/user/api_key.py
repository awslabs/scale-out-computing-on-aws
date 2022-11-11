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
import logging
import secrets

import config
import errors
from decorators import admin_api, restricted_api, retrieve_api_key
from flask_restful import Resource, reqparse
from models import ApiKeys, db
from requests import get

logger = logging.getLogger("api")


class ApiKey(Resource):
    @retrieve_api_key
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
        parser.add_argument("user", type=str, location="args")
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "user (str) parameter is required")

        try:
            check_existing_key = ApiKeys.query.filter_by(user=user, is_active=True).first()
            if check_existing_key:
                return {"success": True, "message": check_existing_key.token}, 200
            else:
                try:
                    # Create an API key for the user if needed
                    user_exist = get(
                        config.Config.FLASK_ENDPOINT + "/api/ldap/user",
                        headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                        params={"user": user},
                        verify=False,
                    )  # nosec
                    if user_exist.status_code == 200:
                        permissions = get(
                            config.Config.FLASK_ENDPOINT + "/api/ldap/sudo",
                            headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                            params={"user": user},
                            verify=False,
                        )  # nosec

                        if permissions.status_code == 200:
                            scope = "sudo"
                        else:
                            scope = "user"
                        api_token = secrets.token_hex(16)
                        new_key = ApiKeys(
                            user=user,
                            token=api_token,
                            is_active=True,
                            scope=scope,
                            created_on=datetime.datetime.utcnow(),
                        )
                        db.session.add(new_key)
                        db.session.commit()
                        return {"success": True, "message": api_token}, 200
                    else:
                        return {"success": False, "message": "Not authorized"}, 401

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
        parser.add_argument("user", type=str, location="form")
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
