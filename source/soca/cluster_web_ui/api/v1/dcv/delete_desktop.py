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
        if session_number is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER",
                "session_number not found in URL. Endpoint is /api/dcv/desktop/<session_number>/<action>",
            )
        else:
            args["session_number"] = str(session_number)

        if user is None:
            return errors.all_errors("X-SOCA-USER_MISSING")

        if args["os"] is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "os (str)")

        if args["os"].lower() not in ["linux", "windows"]:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER", "os must be linux or windows"
            )

        if args["os"].lower() == "linux":
            check_session = LinuxDCVSessions.query.filter_by(
                user=user, session_number=str(args["session_number"]), is_active=True
            ).first()
        else:
            check_session = WindowsDCVSessions.query.filter_by(
                user=user, session_number=str(args["session_number"]), is_active=True
            ).first()

        if check_session:
            session_name = check_session.session_name

            # Terminate instance
            stack_name = str(
                read_secretmanager.get_soca_configuration()["ClusterId"]
                + "-"
                + session_name
                + "-"
                + user
            )
            try:
                client_cfn.delete_stack(StackName=stack_name)
                check_session.is_active = False
                check_session.deactivated_on = datetime.utcnow()
                db.session.commit()
                return {
                    "success": True,
                    "message": f"Your graphical session {session_name} is about to be terminated",
                }, 200
            except ClientError as e:
                return errors.all_errors(
                    "DCV_STOP_ERROR",
                    f"Unable to delete cloudformation stack ({stack_name}) due to {e}",
                )
            except Exception as e:
                return errors.all_errors(
                    "DCV_STOP_ERROR", f"Unable to update db due to {e}"
                )
        else:
            return errors.all_errors(
                "DCV_STOP_ERROR", f"This session does not exist or is not active"
            )
