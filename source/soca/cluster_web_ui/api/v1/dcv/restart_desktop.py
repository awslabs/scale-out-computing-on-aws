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
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER",
                "session_number not found in URL. Endpoint is /api/dcv/desktop/<session_number>/restart",
            )
        else:
            args["session_number"] = str(session_number)
        user = request.headers.get("X-SOCA-USER")
        if user is None:
            return errors.all_errors("X-SOCA-USER_MISSING")

        if args["os"] is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER", "os (str), action (str)  are required."
            )

        if args["os"].lower() not in ["linux", "windows"]:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER", "os must be linux or windows"
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
            instance_id = check_session.session_instance_id
            session_name = check_session.session_name
            if check_session.session_state != "stopped":
                return errors.all_errors(
                    "DCV_RESTART_ERROR",
                    f"This DCV desktop is not stopped. You can only restart a stopped desktop.",
                )
            try:
                client_ec2.start_instances(InstanceIds=[instance_id], DryRun=True)
            except ClientError as e:
                if e.response["Error"].get("Code") == "DryRunOperation":
                    try:
                        client_ec2.start_instances(InstanceIds=[instance_id])
                        check_session.session_state = "pending"
                        db.session.commit()
                        return {
                            "success": True,
                            "message": f"Your graphical session {session_name} is being restarted",
                        }, 200

                    except Exception as err:
                        return errors.all_errors(
                            "DCV_RESTART_ERROR",
                            f"Please wait a little bit before restarting this session as the underlying resource is still being stopped.",
                        )
                else:
                    return errors.all_errors(
                        "DCV_RESTART_ERROR",
                        f"Unable to restart instance {instance_id} due to {e}",
                    )
        else:
            return errors.all_errors(
                "DCV_RESTART_ERROR",
                f"Unable to retrieve this session. It's possible your session has been deleted.",
            )
