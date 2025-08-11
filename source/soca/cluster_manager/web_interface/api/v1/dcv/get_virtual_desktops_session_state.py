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


from flask_restful import Resource, reqparse
import logging
from models import db, VirtualDesktopSessions
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


class GetVirtualDesktopsSessionState(Resource):
    def get(self):
        """
        Get virtual desktop session states
        ---
        openapi: 3.1.0
        operationId: getVirtualDesktopSessionStates
        tags:
          - Virtual Desktops
        summary: Get session states for virtual desktops
        description: Retrieves the current state of one or more DCV virtual desktop sessions
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
          - name: session_uuid
            in: query
            required: true
            schema:
              type: string
              pattern: '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(,[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})*$'
            description: Comma-separated list of session UUIDs to check
            example: "12345678-1234-1234-1234-123456789abc,87654321-4321-4321-4321-cba987654321"
        responses:
          '200':
            description: Session states retrieved successfully
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: object
                      additionalProperties:
                        type: string
                        enum: ["pending", "running", "stopped", "stopping", "terminated"]
                      description: Dictionary mapping session UUIDs to their states
                      example:
                        "12345678-1234-1234-1234-123456789abc": "running"
                        "87654321-4321-4321-4321-cba987654321": "stopped"
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
                      example: "Missing required parameter: session_uuid"
          '401':
            description: Authentication failed
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
                      example: 401
                    message:
                      type: string
                      example: "Invalid authentication credentials"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("session_uuid", type=str, location="args")
        args = parser.parse_args()
        logger.debug(
            f"Received parameter for listing DCV desktop session state: {args}"
        )

        _sessions_uuid = args["session_uuid"].split(",")
        _session_results = {}
        for _session in _sessions_uuid:
            _check_session = VirtualDesktopSessions.query.filter(
                VirtualDesktopSessions.session_uuid == _session,
                VirtualDesktopSessions.is_active == True,
            ).first()
            if _check_session:
                _session_results[_check_session.session_uuid] = (
                    _check_session.session_state
                )

        logger.debug(
            f"Complete User Sessions Check Session State details to return: {_session_results}"
        )
        return SocaResponse(success=True, message=_session_results).as_flask()
