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
from utils.cast import SocaCastEngine
from utils.aws.ssm_parameter_store import SocaConfig
from utils.response import SocaResponse
from decorators import private_api
from botocore.exceptions import ClientError
from utils.error import SocaError
from models import db, LinuxDCVSessions, WindowsDCVSessions
import utils.aws.boto3_wrapper as utils_boto3

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_cfn = utils_boto3.get_boto(service_name="cloudformation").message


class DeleteDesktop(Resource):
    @private_api
    def delete(self, session_number):
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
                session_number:
                  type: string
                  description: Session Number
                os:
                  type: string
                  description: DCV session type (Windows or Linux)

        responses:
          200:
            description: Pair of user/token is valid
          401:
            description: Invalid user/token pair
        """
        parser = reqparse.RequestParser()
        parser.add_argument("os", type=str, location="form")

        args = parser.parse_args()
        user = request.headers.get("X-SOCA-USER")
        logger.debug(
            f"Receive Delete Desktop for {args} session number {session_number}"
        )

        if session_number is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="session_number").as_flask()
        else:
            _validate_session_number = SocaCastEngine(session_number).cast_as(int)
            if not _validate_session_number.success:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="session_number",
                    helper="session number must be a valid int",
                ).as_flask()
            else:
                _session_number = _validate_session_number.message

        if user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        if args["os"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="os").as_flask()

        if args["os"].lower() not in ["linux", "windows"]:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="os", helper="os must be either linux or windows"
            ).as_flask()

        if args["os"].lower() == "linux":
            check_session = LinuxDCVSessions.query.filter_by(
                user=user, session_number=_session_number, is_active=True
            ).first()
        else:
            check_session = WindowsDCVSessions.query.filter_by(
                user=user, session_number=_session_number, is_active=True
            ).first()

        if check_session:
            session_name = check_session.session_name
            # Terminate instance
            stack_name = f"{SocaConfig(key='/configuration/ClusterId').get_value().get('message')}-{session_name}-{user}"
            logger.debug(
                f"Found session {check_session} about to delete {session_name} and associated CloudFormation {stack_name}"
            )
            try:
                logger.info(f"Deleting DCV CloudFormation Stack {stack_name}")
                client_cfn.delete_stack(StackName=stack_name)
            except ClientError as e:
                return SocaError.AWS_API_ERROR(
                    service_name="cloudformation",
                    helper=f"Unable to delete cloudformation stack ({stack_name}) due to {e}",
                ).as_flask()
            logger.debug("Stack deleted successfully, updating database")
            try:
                check_session.is_active = False
                check_session.deactivated_on = datetime.now(timezone.utc)
                db.session.commit()
            except Exception as e:
                return SocaError.DB_ERROR(
                    helper=f"Unable to deactivate DCV desktop session due to {e}",
                    query=check_session,
                ).as_flask()

            return SocaResponse(success=True, message=f"Your graphical session {session_name} is about to be terminated as requested").as_flask()

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"This session does not exist or is not active"
            ).as_flask()
