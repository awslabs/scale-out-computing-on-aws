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
from models import db, VirtualDesktopSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.response import SocaResponse
from utils.error import SocaError

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_cfn = utils_boto3.get_boto(service_name="cloudformation").message


class StopVirtualDesktop(Resource):
    @private_api
    def put(self):
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
        parser.add_argument("session_uuid", type=str, location="form")

        args = parser.parse_args()
        _user = request.headers.get("X-SOCA-USER")
        _session_uuid = args.get("session_uuid", None)
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        logger.debug(f"Received stop_desktop request for {_session_uuid}, user {_user}")

        if _session_uuid is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="session_uuid"
            ).as_flask()

        _check_session = VirtualDesktopSessions.query.filter_by(
            session_owner=_user,
            session_uuid=_session_uuid,
            is_active=True,
        ).first()

        if _check_session:
            _instance_id = _check_session.instance_id
            if _check_session == "stopped":
                return SocaError.VIRTUAL_DESKTOP_STOP_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper="Your desktop is already stopped.",
                ).as_flask()

            # Check hibernate
            _hibernate_enabled = False
            try:
                _describe_instance = client_ec2.describe_instances(
                    InstanceIds=[_instance_id]
                )
                _response = _describe_instance["Reservations"][0]["Instances"]
                if _response:
                    _hibernate_enabled = (
                        _response[0]
                        .get("HibernationOptions", {})
                        .get("Configured", False)
                    )
            except Exception as err:
                logger.error(
                    f"Unable to check HibernationOptions for {_instance_id} due to {err}. Desktop will be stopped"
                )

            logger.info(
                f"About to stop/hibernate the instance. _hibernate_enabled flag {_hibernate_enabled}"
            )
            try:
                client_ec2.stop_instances(
                    InstanceIds=[_instance_id], Hibernate=_hibernate_enabled
                )
            except Exception as err:
                return SocaError.VIRTUAL_DESKTOP_STOP_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"Unable to stop/hibernate instance due to {err}",
                ).as_flask()

            try:
                _check_session.session_state = "stopped"
                _check_session.session_state_latest_change_time = datetime.now(timezone.utc)
                db.session.commit()
            except Exception as err:
                return SocaError.DB_ERROR(
                    query=_check_session,
                    helper=f"Unable to set session_state to stopped due to {err}",
                ).as_flask()

            return SocaResponse(
                success=True, message=f"Your desktop will be stopped soon."
            ).as_flask()
        else:
            return SocaError.VIRTUAL_DESKTOP_STOP_ERROR(
                session_number=_session_uuid,
                session_owner=_user,
                helper="Unable to find this session. Please refresh your browser and try again.",
            ).as_flask()
