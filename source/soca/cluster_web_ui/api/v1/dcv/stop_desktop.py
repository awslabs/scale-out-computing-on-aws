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
        if session_number is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER",
                "session_number not found in URL. Endpoint is /api/dcv/desktop/<session_number>/<action>",
            )
        else:
            args["session_number"] = str(session_number)

        if action is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER",
                "action not found in URL. Endpoint is /api/dcv/desktop/<session_number>/<action>",
            )
        else:
            args["action"] = action

        if user is None:
            return errors.all_errors("X-SOCA-USER_MISSING")

        if args["os"] is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "os (str)")

        if args["os"].lower() not in ["linux", "windows"]:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER", "os must be linux or windows"
            )

        if args["action"] not in ["terminate", "stop", "hibernate"]:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER",
                "action must be terminate, stop or hibernate",
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
            instance_id = check_session.session_instance_id
            session_name = check_session.session_name

            if args["action"] == "hibernate":
                if check_session.session_state == "stopped":
                    return errors.all_errors(
                        "DCV_STOP_ERROR", f"Your instance is already stopped."
                    )
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
                            check_session.session_state = "stopped"
                            db.session.commit()
                        else:
                            return errors.all_errors(
                                "DCV_STOP_ERROR",
                                f"Unable to hibernate instance ({instance_id}) due to {e}",
                            )

            elif args["action"] == "stop":
                if check_session.session_state in "stopped":
                    return errors.all_errors(
                        "DCV_STOP_ERROR", f"Your desktop is already stopped."
                    )
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
                                return errors.all_errors(
                                    "DCV_STOP_ERROR",
                                    f"Unable to stop instance, maybe the instance is not running yet. Error {err}",
                                )
                            check_session.session_state = "stopped"
                            db.session.commit()
                        else:
                            return errors.all_errors(
                                "DCV_STOP_ERROR",
                                f"Unable to stop instance ({instance_id}) due to {e}",
                            )

            else:
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
