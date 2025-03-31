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
from models import db, VirtualDesktopSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.response import SocaResponse
from datetime import datetime, timezone
logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class StartVirtualDesktop(Resource):
    @private_api
    def put(self):
        """
        Start a DCV desktop session
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
        parser.add_argument("session_uuid", type=str, location="form")

        args = parser.parse_args()
        _session_uuid = args["session_uuid"]
        logger.info(f"Received parameter for restarting DCV desktop: {args}")

        if _session_uuid is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="_session_uuid"
            ).as_flask()

        _user = request.headers.get("X-SOCA-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        _check_session = VirtualDesktopSessions.query.filter_by(
            session_owner=_user, session_uuid=_session_uuid, is_active=True
        ).first()

        if _check_session:
            _instance_id = _check_session.instance_id
            _session_state = _check_session.session_state

            if _session_state == "pending":
                return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper="This DCV desktop is still being started. Please wait a little bit before restarting this session.",
                ).as_flask()

            if _session_state != "stopped":
                return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper="This virtual desktop seems to be already running.",
                ).as_flask()

            try:
                client_ec2.start_instances(InstanceIds=[_instance_id])

                try:
                    _check_session.session_state = "pending"
                    _check_session.session_state_latest_change_time = datetime.now(timezone.utc)
                    db.session.commit()
                except Exception as err:
                    return SocaError.DB_ERROR(
                        query=_check_session,
                        helper=f"Unable to update session state to 'pending' due to {err}",
                    ).as_flask()
            except ClientError as err:
                if "IncorrectInstanceState" in str(err):
                    return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                        session_number=_session_uuid,
                        session_owner=_user,
                        helper=f"Your current desktop is not yet stopped. Please wait a little longer if you just tried to stop your desktop.",
                    ).as_flask()
                else:
                    return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                        session_number=_session_uuid,
                        session_owner=_user,
                        helper=f"Unable to start instance due to {err}",
                    ).as_flask()
            except Exception as err:
                return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"Unable to start instance due to {err}",
                ).as_flask()

            return SocaResponse(
                success=True,
                message=f"Your virtual desktop is starting",
            ).as_flask()
        else:
            return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                session_number=_session_uuid,
                session_owner=_user,
                helper="Unable to find this session. Please refresh your browser and try again.",
            ).as_flask()
