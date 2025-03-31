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
from decorators import private_api
from botocore.exceptions import ClientError
from utils.error import SocaError
from models import db, VirtualDesktopSessions
import utils.aws.boto3_wrapper as utils_boto3

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_cfn = utils_boto3.get_boto(service_name="cloudformation").message


class DeleteVirtualDesktop(Resource):
    @private_api
    def delete(self):
        """
        Terminate a DCV desktop session
        ---
        tags:
          - DCV

        parameters:
          - in: body
            name: body
            schema:
              required:
                - os
              properties:
                session_uuid:
                  type: string
                  description: ID of the DCV session

        responses:
          200:
            description: Pair of user/token is valid
          401:
            description: Invalid user/token pair
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
            try:
                logger.info(f"Deleting DCV CloudFormation Stack {_stack_name}")
                client_cfn.delete_stack(StackName=_stack_name)
            except ClientError as e:
                return SocaError.AWS_API_ERROR(
                    service_name="cloudformation",
                    helper=f"Unable to delete cloudformation stack ({_stack_name}) due to {e}",
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
