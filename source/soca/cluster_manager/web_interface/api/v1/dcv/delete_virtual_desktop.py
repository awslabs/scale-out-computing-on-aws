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
from flask import request
import logging
from datetime import datetime, timezone
from utils.response import SocaResponse
from decorators import private_api, feature_flag
from utils.error import SocaError
from models import db, VirtualDesktopSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.cloudformation_helper import SocaCfnClient


logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class DeleteVirtualDesktop(Resource):
    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def delete(self):
        """
        Delete a DCV virtual desktop session
        ---
        openapi: 3.1.0
        operationId: deleteVirtualDesktop
        tags:
          - Virtual Desktops
        summary: Delete virtual desktop session
        description: Terminates an active DCV virtual desktop session and cleans up associated resources
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
                  - session_uuid
                properties:
                  session_uuid:
                    type: string
                    format: uuid
                    description: UUID of the DCV session to delete
                    example: "12345678-1234-1234-1234-123456789abc"
        responses:
          '200':
            description: Virtual desktop session deletion initiated successfully
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
                      type: string
                      example: "Your Virtual Desktop is about to be terminated"
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
                      example: "Missing required header: X-SOCA-USER"
          '403':
            description: Feature not enabled or insufficient permissions
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
                      example: 403
                    message:
                      type: string
                      example: "Virtual desktops feature is not enabled"
          '404':
            description: Session not found or not active
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
                      example: 404
                    message:
                      type: string
                      example: "This session does not exist or is not active"
          '500':
            description: Internal server error during deletion
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
                      example: 500
                    message:
                      type: string
                      example: "Unable to delete cloudformation stack"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("session_uuid", type=str, location="form")

        args = parser.parse_args()
        user = request.headers.get("X-SOCA-USER")
        session_uuid = args["session_uuid"]
        logger.info(f"Receive Delete Desktop for {args} session number {session_uuid}")

        if session_uuid is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="session_uuid"
            ).as_flask()

        if user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        _check_session = VirtualDesktopSessions.query.filter_by(
            session_owner=user, session_uuid=session_uuid, is_active=True
        ).first()
        if _check_session:
            _stack_name = _check_session.stack_name
            # Terminate instance
            logger.debug(
                f"Found session {_check_session} about to delete {_check_session.session_name} and associated CloudFormation {_check_session.stack_name}"
            )

            logger.info(f"Deleting DCV CloudFormation Stack {_stack_name}")
            _delete_stack = SocaCfnClient(stack_name=_stack_name).delete_stack()
            if _delete_stack.get("success") is False:
                return SocaError.AWS_API_ERROR(
                    service_name="cloudformation",
                    helper=f"Unable to delete cloudformation stack ({_stack_name}) due to {_delete_stack.get('message')}",
                ).as_flask()

            logger.debug("Stack deleted successfully, updating database")
            try:
                _check_session.is_active = False
                _check_session.deactivated_on = datetime.now(timezone.utc)
                _check_session.deactivated_by = user
                _check_session.session_state_latest_change_time = datetime.now(
                    timezone.utc
                )
                db.session.commit()

            except Exception as e:
                db.session.rollback()
                return SocaError.DB_ERROR(
                    helper=f"Unable to deactivate DCV desktop session due to {e}",
                    query=_check_session,
                ).as_flask()

            return SocaResponse(
                success=True,
                message=f"Your Virtual Desktop is about to be terminated",
            ).as_flask()

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"This session does not exist or is not active"
            ).as_flask()
