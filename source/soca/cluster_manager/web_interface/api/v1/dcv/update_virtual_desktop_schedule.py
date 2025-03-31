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
from models import db, VirtualDesktopSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
import config

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class UpdateVirtualDesktopSchedule(Resource):
    @private_api
    def put(self):
        """
        Modify schedule of a DCV desktop session
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
        parser.add_argument("schedule", type=str, location="form")
        args = parser.parse_args()
        _session_uuid = args["session_uuid"]
        _schedule = args["schedule"]
        logger.debug(f"Received parameter for updating schedule DCV desktop: {args}")

        if config.Config.DCV_ALLOW_DEFAULT_SCHEDULE_UPDATE is not True:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="Your administrator has disabled virtual desktops schedule update"
            ).as_flask()

        _user = request.headers.get("X-SOCA-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        if _session_uuid is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="session_uuid"
            ).as_flask()

        if _schedule is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="schedule").as_flask()
        else:
            _verify_schedule_format = SocaCastEngine(data=_schedule).cast_as(
                expected_type=dict
            )
            if _verify_schedule_format.get("success"):
                _days = [
                    "monday",
                    "tuesday",
                    "wednesday",
                    "thursday",
                    "friday",
                    "saturday",
                    "sunday",
                ]
                _schedule_data = _verify_schedule_format.get("message")
                for _day in _days:

                    if _day not in _schedule_data:
                        return SocaError.CLIENT_MISSING_PARAMETER(
                            parameter=f"schedule.{_day} is missing"
                        ).as_flask()

                    for _time_check in ["start", "stop"]:
                        if not _time_check in _schedule_data[_day]:
                            return SocaError.CLIENT_MISSING_PARAMETER(
                                parameter=f"schedule.{_day}.{_time_check} is missing"
                            ).as_flask()
                        else:
                            try:
                                if 0 <= int(_schedule_data[_day][_time_check]) <= 1440:
                                    pass
                                else:
                                    return SocaError.CLIENT_MISSING_PARAMETER(
                                        parameter=f"schedule.{_day}.{_time_check} must be between 0 and 1440"
                                    ).as_flask()
                            except:
                                return SocaError.CLIENT_MISSING_PARAMETER(
                                    parameter=f"schedule.{_day}.{_time_check} must be between 0 and 1440 and a valid int"
                                ).as_flask()

            else:
                return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"Unable to parse schedule {_schedule} due to {_verify_schedule_format.get('message')}",
                ).as_flask()

        _check_session = VirtualDesktopSessions.query.filter_by(
            session_owner=_user, session_uuid=_session_uuid, is_active=True
        ).first()
        if _check_session:
            try:
                _check_session.schedule = _schedule
                db.session.commit()
                return SocaResponse(
                    success=True,
                    message=f"Your virtual desktop schedule has been updated",
                ).as_flask()
            except Exception as err:
                return SocaError.DB_ERROR(
                    query=_check_session,
                    helper=f"Unable to update session schedule due to {err}",
                ).as_flask()
        else:
            return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                session_number=_session_uuid,
                session_owner=_user,
                helper="Unable to find this session. Please refresh your browser and try again.",
            ).as_flask()
