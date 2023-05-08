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
from requests import get
import logging
from datetime import datetime
import read_secretmanager
from decorators import private_api
from botocore.exceptions import ClientError
import boto3
import errors
from models import db, LinuxDCVSessions, WindowsDCVSessions

logger = logging.getLogger("api")
client_ec2 = boto3.client("ec2", config=config.boto_extra_config())
client_cfn = boto3.client("cloudformation", config=config.boto_extra_config())


class UpdateDesktopSchedule(Resource):
    @private_api
    def put(self, session_number):
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
        parser.add_argument("os", type=str, location="form")
        parser.add_argument("monday", type=str, location="form")
        parser.add_argument("tuesday", type=str, location="form")
        parser.add_argument("wednesday", type=str, location="form")
        parser.add_argument("thursday", type=str, location="form")
        parser.add_argument("friday", type=str, location="form")
        parser.add_argument("saturday", type=str, location="form")
        parser.add_argument("sunday", type=str, location="form")

        args = parser.parse_args()
        logger.info(f"Received parameter for updating schedule DCV desktop: {args}")

        user = request.headers.get("X-SOCA-USER")
        if user is None:
            return errors.all_errors("X-SOCA-USER_MISSING")

        if session_number is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER",
                "session_number not found in URL. Endpoint is /api/dcv/desktop/<session_number>/schedule",
            )
        else:
            args["session_number"] = str(session_number)

        if args["os"] is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER", "os (str) is required."
            )

        if args["os"].lower() not in ["linux", "windows"]:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER", "os must be linux or windows"
            )

        week_days = [
            "monday",
            "tuesday",
            "wednesday",
            "thursday",
            "friday",
            "saturday",
            "sunday",
        ]
        schedule = {}
        for day in week_days:
            if day is None:
                return errors.all_errors(
                    "CLIENT_MISSING_PARAMETER", f"{day} (str) is required."
                )
            else:
                schedule_value = args[day].split("-")
                if len(schedule_value) == 2:
                    try:
                        start_time = int(schedule_value[0])
                        end_time = int(schedule_value[1])
                        if end_time < start_time:
                            return errors.all_errors(
                                "DCV_SCHEDULE_ERROR",
                                f"End time for {day} ({end_time}) must be greater than start time ({start_time})",
                            )
                        elif end_time > 1440:
                            return errors.all_errors(
                                "DCV_SCHEDULE_ERROR",
                                f"End time for {day} ({end_time}) ) cannot be greater than 1440 (12PM)",
                            )
                        elif start_time < 0:
                            return errors.all_errors(
                                "DCV_SCHEDULE_ERROR",
                                f"Start time for {day} ({start_time}) ) must be greater than 0 (12AM)",
                            )
                        elif start_time == end_time:
                            schedule[day] = "0-0"  # no run
                        else:
                            schedule[day] = f"{start_time}-{end_time}"
                    except ValueError:
                        return errors.all_errors(
                            "DCV_SCHEDULE_ERROR",
                            f"Schedule must use number1-number2 format where number1 and number2 are valid integer and not {schedule_value}",
                        )
                else:
                    return errors.all_errors(
                        "DCV_SCHEDULE_ERROR",
                        f"Schedule values must be number1-number2 format and not {schedule_value}",
                    )

        if args["os"].lower() == "linux":
            check_session = LinuxDCVSessions.query.filter_by(
                user=user, session_number=args["session_number"], is_active=True
            ).first()
        else:
            check_session = WindowsDCVSessions.query.filter_by(
                user=user, session_number=args["session_number"], is_active=True
            ).first()

        if check_session:
            session_name = check_session.session_name
            check_session.schedule_monday_start = schedule["monday"].split("-")[0]
            check_session.schedule_monday_stop = schedule["monday"].split("-")[1]
            check_session.schedule_tuesday_start = schedule["tuesday"].split("-")[0]
            check_session.schedule_tuesday_stop = schedule["tuesday"].split("-")[1]
            check_session.schedule_wednesday_start = schedule["wednesday"].split("-")[0]
            check_session.schedule_wednesday_stop = schedule["wednesday"].split("-")[1]
            check_session.schedule_thursday_start = schedule["thursday"].split("-")[0]
            check_session.schedule_thursday_stop = schedule["thursday"].split("-")[1]
            check_session.schedule_friday_start = schedule["friday"].split("-")[0]
            check_session.schedule_friday_stop = schedule["friday"].split("-")[1]
            check_session.schedule_saturday_start = schedule["saturday"].split("-")[0]
            check_session.schedule_saturday_stop = schedule["saturday"].split("-")[1]
            check_session.schedule_sunday_start = schedule["sunday"].split("-")[0]
            check_session.schedule_sunday_stop = schedule["sunday"].split("-")[1]
            db.session.commit()
            return {
                "success": True,
                "message": f"Schedule has been updated correctly for {session_name}",
            }, 200
        else:
            return errors.all_errors(
                "DCV_RESTART_ERROR",
                f"Unable to retrieve this session. It's possible your session has been deleted.",
            )
