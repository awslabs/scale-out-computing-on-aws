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
from decorators import private_api
from botocore.exceptions import ClientError
from models import db, LinuxDCVSessions, WindowsDCVSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class RestartDesktop(Resource):
    @private_api
    def put(self, session_number):
        """
        Restart a DCV desktop session
        ---
        tags:
          - DCV

        parameters:
          - in: body
            name: body
            schema:
              required:
                - os
                - action
              properties:
                os:
                  type: string
                  description: DCV session type (Windows or Linux)
                action:
                  type: string
                  description: stop, hibernate or terminate
        responses:
          200:
            description: Pair of user/token is valid
          401:
            description: Invalid user/token pair
        """
        parser = reqparse.RequestParser()
        parser.add_argument("os", type=str, location="form")

        args = parser.parse_args()
        logger.info(f"Received parameter for restarting DCV desktop: {args}")
        if session_number is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="session_number").as_flask()
        else:
            _check_session_number = SocaCastEngine(session_number).cast_as(int)
            if not _check_session_number.success:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="session_number",
                    helper="session number must be a valid int",
                ).as_flask()
            else:
                _session_number = _check_session_number.message

        user = request.headers.get("X-SOCA-USER")
        if user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        if args["os"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="os").as_flask()

        if args["os"].lower() not in ["linux", "windows"]:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="os", helper="os must be linux or windows"
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
            instance_id = check_session.session_instance_id
            session_name = check_session.session_name
            if check_session.session_state != "stopped":
                return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                    session_number=_session_number,
                    session_owner=user,
                    helper="This DCV desktop is not stopped. You can only restart a stopped desktop.",
                ).as_flask()
            try:
                client_ec2.start_instances(InstanceIds=[instance_id], DryRun=True)
            except ClientError as e:
                if e.response["Error"].get("Code") == "DryRunOperation":
                    try:
                        client_ec2.start_instances(InstanceIds=[instance_id])
                        try:
                            check_session.session_state = "pending"
                            db.session.commit()
                        except Exception as err:
                            return SocaError.DB_ERROR(
                                query=check_session,
                                helper=f"Unable to update session state to 'pending' due to {err}",
                            ).as_flask()

                        return SocaResponse(success=True, message=f"Your graphical session {session_name} is being restarted").as_flask()


                    except Exception as err:
                        return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                            session_number=_session_number,
                            session_owner=user,
                            helper=f"Please wait a little bit before restarting this session as the underlying resource is still being stopped. Trace: {err}",
                        ).as_flask()

                else:
                    return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                        session_number=_session_number,
                        session_owner=user,
                        helper=f"Unable to restart instance {instance_id} due to {e}",
                    ).as_flask()
        else:
            return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                session_number=_session_number,
                session_owner=user,
                helper="This session does not exist or is not active",
            ).as_flask()
