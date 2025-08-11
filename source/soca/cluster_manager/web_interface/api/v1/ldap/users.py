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

import config
import ldap
from flask_restful import Resource
import logging
from decorators import admin_api, private_api
from utils.aws.ssm_parameter_store import SocaConfig
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.response import SocaResponse
from utils.error import SocaError
import os
import sys
logger = logging.getLogger("soca_logger")


class Users(Resource):
    @private_api
    def get(self):
        """
        Retrieve all LDAP users
        ---
        openapi: 3.1.0
        operationId: getAllLdapUsers
        tags:
          - User Management
        summary: Retrieve all LDAP users
        description: Returns a list of all users from the configured LDAP directory (OpenLDAP or Active Directory)
        security:
          - socaAuth: []
        responses:
          '200':
            description: Successfully retrieved all LDAP users
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: object
                      description: Dictionary of username to LDAP DN mappings
                      additionalProperties:
                        type: string
                        description: LDAP Distinguished Name
                      example:
                        "john.doe": "cn=john.doe,ou=people,dc=soca,dc=local"
                        "jane.smith": "cn=jane.smith,ou=people,dc=soca,dc=local"
          '203':
            description: Invalid username/token pair
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
                      example: "Invalid authentication credentials"
          '400':
            description: Malformed client input
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
                      example: "Bad request parameters"
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
        all_ldap_users = {}
        if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
            _filter = "(objectClass=person)"
            _attr_name = "uid"
        else:
            # (!(userAccountControl:1.2.840.113556.1.4.803:=2))) -> catch disabled users
            if config.Config.DIRECTORY_AUTH_PROVIDER == "aws_ds_managed_activedirectory":
                _filter = "(&(objectClass=user)(!(sAMAccountName=Admin))(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=AWS_*)))"
            else:
                _filter = "(&(objectClass=user)(!(sAMAccountName=Administrator))(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2))(!(sAMAccountName=AWS_*)))"
            _attr_name = "sAMAccountName"

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            _users = _soca_identity_client.search(base=config.Config.DIRECTORY_PEOPLE_SEARCH_BASE,
                                                  scope=ldap.SCOPE_SUBTREE,
                                                  filter=_filter,
                                                  attr_list=[_attr_name])
            if _users.success:
                for user in _users.message:
                    user_base = user[0]
                    username = user[1][_attr_name][0]
                    all_ldap_users[username.decode("utf-8") if isinstance(username, bytes) else username] = user_base

                return SocaResponse(success=True, message=all_ldap_users).as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"Unable to list all users because of {_users.message}").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}").as_flask()
