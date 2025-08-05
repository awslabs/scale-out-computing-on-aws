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
from cryptography.fernet import Fernet
from flask_restful import Resource, reqparse
from flask import request
import logging
from flask import Response
from utils.aws.ssm_parameter_store import SocaConfig
from utils.error import SocaError
import base64
import ast
from models import db, VirtualDesktopSessions

logger = logging.getLogger("soca_logger")


def decrypt(encrypted_text):
    try:
        key = config.Config.DCV_TOKEN_SYMMETRIC_KEY
        cipher_suite = Fernet(key)
        decrypted_text = cipher_suite.decrypt(encrypted_text)
        return {"success": True, "message": decrypted_text.decode()}
    except Exception as err:
        return SocaError.VIRTUAL_DESKTOP_AUTHENTICATION_ERROR(
            helper=f"Unable to decrypt {encrypted_text} due to {err}"
        )


class DcvAuthenticator(Resource):
    @staticmethod
    def post():
        """
        Authenticate a DCV desktop session
        ---
        openapi: 3.1.0
        operationId: authenticateDcvSession
        tags:
          - Virtual Desktops
        summary: Authenticate DCV desktop session
        description: Validates DCV session authentication token and returns XML response for session access
        parameters:
          - name: X-SOCA-USER
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
            description: SOCA username for authentication
            example: "john.doe"
          - name: X-SOCA-TOKEN
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 256
            description: SOCA authentication token
            example: "abc123token456"
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - sessionId
                  - authenticationToken
                  - clientAddress
                properties:
                  sessionId:
                    type: string
                    minLength: 1
                    maxLength: 100
                    pattern: '^[a-zA-Z0-9._-]+$'
                    description: DCV session identifier
                    example: "dcv-session-123"
                  authenticationToken:
                    type: string
                    minLength: 1
                    maxLength: 10000
                    format: base64
                    description: Base64 encoded encrypted authentication token containing session details
                    example: "Z0FBQUFBQmhkX1pHVGtOcVRHVnNkR1Z5"
                  clientAddress:
                    type: string
                    format: ipv4
                    description: Client IP address requesting authentication
                    example: "192.168.1.100"
        responses:
          '200':
            description: Authentication successful
            content:
              text/xml:
                schema:
                  type: string
                  pattern: '^<auth result="yes"><username>[^<]+</username></auth>$'
                example: '<auth result="yes"><username>john.doe</username></auth>'
          '400':
            description: Missing required parameters
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 400
                    message:
                      type: string
                      example: "Missing required parameter: sessionId"
          '401':
            description: Authentication failed - invalid credentials or session
            content:
              text/xml:
                schema:
                  type: string
                  pattern: '^<auth result="no"/>$'
                example: '<auth result="no"/>'
        """
        parser = reqparse.RequestParser()
        parser.add_argument("sessionId", type=str, location="form")
        parser.add_argument("authenticationToken", type=str, location="form")
        parser.add_argument("clientAddress", type=str, location="form")
        args = parser.parse_args()
        remote_addr = request.remote_addr  # EC2 machine where the call is coming from
        logger.debug(f"Proceeding to DCV Authentication with {args}")
        if not args.get("sessionId", None):
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="sessionId").as_flask()

        if not args.get("authenticationToken", None):
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="authenticationToken"
            ).as_flask()
        else:
            authentication_token = args.get("authenticationToken")

        if not args.get("clientAddress", None):
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="clientAddress"
            ).as_flask()

        required_params = [
            "system",
            "session_user",
            "session_token",
            "instance_id",
        ]
        session_info = {}

        try:
            decoded_token = decrypt(base64.b64decode(authentication_token))
            logger.debug(f"Decoded Token Result {decoded_token}")
            if decoded_token.get("success"):
                decoded_token = ast.literal_eval(decoded_token.get("message"))
            else:
                logger.error(
                    "DCV Authentication: Unable to decrypt the authentication token. It was probably generated by a different Fernet key"
                )
                return Response(
                    f'<auth result="no"/>',
                    status=401,
                    mimetype="text/xml",
                )
        except Exception as err:
            logger.error(
                f"DCV Authentication: Unable to base64 decode the authentication token due to {err}"
            )
            return Response(
                f'<auth result="no"/>',
                status=401,
                mimetype="text/xml",
            )

        for param in required_params:
            if param not in decoded_token.keys():
                return SocaError.VIRTUAL_DESKTOP_AUTHENTICATION_ERROR(
                    helper=f"Unable to find required {param} in {decoded_token}"
                ).as_flask()
            else:
                session_info[param] = decoded_token[param]

        logger.debug(
            f"Detected session info to auth {session_info}, remote_addr is {remote_addr}, session_id is {args.get('sessionId')}"
        )
        validate_session = VirtualDesktopSessions.query.filter_by(
            session_owner=session_info["session_user"],
            instance_private_ip=remote_addr,
            session_token=session_info["session_token"],
            instance_id=session_info["instance_id"],
            session_id=args.get("sessionId"),
            is_active=True,
        ).first()

        logger.debug(f"Validate session: {validate_session}")
        if validate_session:
            user = session_info["session_user"]
        else:
            return SocaError.VIRTUAL_DESKTOP_AUTHENTICATION_ERROR(
                helper="Unable to authenticate this DCV session, combination of session token, instance id, private ip, user is invalid or session is not active"
            ).as_flask()

        if "windows" in session_info["system"].lower():
            _ds_domain_netbios = (
                SocaConfig(key="/configuration/UserDirectory/short_name")
                .get_value()
                .get("message")
            )
            _ds_auth_provider = (
                SocaConfig(key="/configuration/UserDirectory/provider")
                .get_value()
                .get("message")
            )

            if _ds_auth_provider in [
                "aws_ds_managed_activedirectory",
                "aws_ds_simple_activedirectory",
                "existing_active_directory",
            ]:
                xml_response = f'<auth result="yes"><username>{_ds_domain_netbios}\\{user}</username></auth>'
            else:
                xml_response = f'<auth result="yes"><username>{user}</username></auth>'
        else:
            xml_response = f'<auth result="yes"><username>{user}</username></auth>'

        status = 200
        logger.debug(f"DCV Session for {user} Successfully Authenticated")

        return Response(xml_response, status=status, mimetype="text/xml")
