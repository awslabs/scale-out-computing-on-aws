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
from decorators import private_api
from botocore.exceptions import ClientError
from models import db, LinuxDCVSessions, WindowsDCVSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.ssm_parameter_store import SocaConfig
from utils.response import SocaResponse
from utils.error import SocaError
from utils.cast import SocaCastEngine
import re

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_cfn = utils_boto3.get_boto(service_name="cloudformation").message

class StopDesktop(Resource):
    @private_api
    def put(self, session_number, action):
        """
        Stop/Hibernate a DCV desktop session
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
                action:
                  type: string
                  description: Stop/Hibernate or Terminate
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
        if user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        logger.debug(
            f"Received stop_desktop request for {session_number}, {action} , args {args} user {user}"
        )

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

        if action is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="action").as_flask()
        else:
            args["action"] = action
            if args["action"] not in ["terminate", "stop", "hibernate"]:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="action",
                    helper="action must be terminate, stop or hibernate",
                ).as_flask()

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

            if args["action"] == "hibernate":
                logger.debug("Trying to hibernate the desktop")
                if check_session.session_state == "stopped":
                    return SocaError.VIRTUAL_DESKTOP_STOP_ERROR(
                        session_number=_session_number,
                        session_owner=user,
                        helper="Your desktop is already stopped.",
                    ).as_flask()
                else:
                    # Hibernate instance
                    try:
                        client_ec2.stop_instances(
                            InstanceIds=[instance_id], Hibernate=True, DryRun=True
                        )
                    except ClientError as e:
                        if e.response["Error"].get("Code") == "DryRunOperation":
                            client_ec2.stop_instances(
                                InstanceIds=[instance_id], Hibernate=True
                            )
                            try:
                                check_session.session_state = "stopped"
                                db.session.commit()
                            except Exception as err:
                                return SocaError.DB_ERROR(
                                    query=check_session,
                                    helper=f"Unable to set session_state to stopped due to {err}",
                                ).as_flask()

                            return SocaResponse(success=True, message=f"Session {_session_number} hibernated successfully.").as_flask()
                        else:
                            return SocaError.VIRTUAL_DESKTOP_STOP_ERROR(
                                session_number=_session_number,
                                session_owner=user,
                                helper=f"Unable to hibernate instance due to {e}",
                            ).as_flask()

            elif args["action"] == "stop":
                logger.debug("Trying to stop the desktop")
                if check_session.session_state in "stopped":
                    return SocaError.VIRTUAL_DESKTOP_STOP_ERROR(
                        session_number=_session_number,
                        session_owner=user,
                        helper="Your desktop is already stopped.",
                    ).as_flask()
                # Stop Instance
                else:
                    try:
                        client_ec2.stop_instances(
                            InstanceIds=[instance_id], DryRun=True
                        )
                    except ClientError as e:
                        if e.response["Error"].get("Code") == "DryRunOperation":
                            try:
                                client_ec2.stop_instances(InstanceIds=[instance_id])
                            except ClientError as err:
                                # case when someone stop an EC2 instance still initializing. This use case is not handle by the DryRun so we need
                                return SocaError.VIRTUAL_DESKTOP_STOP_ERROR(
                                    session_number=_session_number,
                                    session_owner=user,
                                    helper=f"Unable to stop instance, maybe the instance is not running yet. Trace {err}",
                                ).as_flask()

                            try:
                                check_session.session_state = "stopped"
                                db.session.commit()
                            except Exception as err:
                                return SocaError.DB_ERROR(
                                    query=check_session,
                                    helper=f"Unable to set session_state to stopped due to {err}",
                                ).as_flask()
                            return SocaResponse(success=True,
                                                message=f"Session {_session_number} stopped successfully.").as_flask()

                        else:
                            return SocaError.VIRTUAL_DESKTOP_STOP_ERROR(
                                session_number=_session_number,
                                session_owner=user,
                                helper=f"Unable to stop instance ({instance_id}) due to {e}",
                            ).as_flask()
            else:
                # user can have - _ or . which are not allowed on CFN (- is allowed but we remove it for consistency)
                _sanitized_user = re.sub(r"[._-]", "", user)
                stack_name = f"{SocaConfig(key='/configuration/ClusterId').get_value().message}-{session_name}-{_sanitized_user}"
                logger.debug(
                    f"Trying to terminate the desktop by deleting associated cloudformation stack {stack_name}"
                )

                try:
                    client_cfn.delete_stack(StackName=stack_name)
                except Exception as err:
                    return SocaError.AWS_API_ERROR(
                        service_name="cloudformation",
                        helper=f"Unable to delete {stack_name} because of {err}",
                    ).as_flask()

                try:
                    check_session.is_active = False
                    check_session.deactivated_on = datetime.now(timezone.utc)
                    db.session.commit()
                except Exception as err:
                    return SocaError.DB_ERROR(
                        query=check_session,
                        helper=f"Unable to deactivate desktop in DB due to {err}",
                    ).as_flask()

                return SocaResponse(success=True, message=f"Your graphical session {session_name} is about to be terminated as requested").as_flask()


        else:
            return SocaError.VIRTUAL_DESKTOP_STOP_ERROR(
                session_number=_session_number,
                session_owner=user,
                helper="This session does not exist or is not active",
            ).as_flask()
