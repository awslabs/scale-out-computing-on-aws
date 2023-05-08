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


class ModifyDesktop(Resource):
    @private_api
    def put(self, session_number):
        """
        Modify instance type associated to DCV desktop session
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
        parser.add_argument("instance_type", type=str, location="form")

        args = parser.parse_args()
        if session_number is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER",
                "session_number not found in URL. Endpoint is /api/dcv/desktop/<session_number>/modify",
            )
        else:
            args["session_number"] = str(session_number)

        logger.info(f"Received parameter for modifying DCV desktop: {args}")

        user = request.headers.get("X-SOCA-USER")
        if user is None:
            return errors.all_errors("X-SOCA-USER_MISSING")

        if (
            args["os"] is None
            or args["session_number"] is None
            or args["instance_type"] is None
        ):
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER",
                "os (str), session_number (str), instance_type (str)  are required.",
            )

        if args["os"].lower() not in ["linux", "windows"]:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER", "os must be linux or windows"
            )

        blocked_instances = config.Config.DCV_RESTRICTED_INSTANCE_TYPE
        all_instances_available = client_ec2._service_model.shape_for(
            "InstanceType"
        ).enum
        all_instances = [
            p
            for p in all_instances_available
            if not any(substr in p for substr in blocked_instances)
        ]
        if args["instance_type"].lower() not in all_instances:
            return errors.all_errors(
                "DCV_MODIFY_ERROR",
                f"{args['instance_type'].lower()} is not authorized by your Admin.",
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
            if check_session.session_state != "stopped":
                return errors.all_errors(
                    "DCV_RESTART_ERROR",
                    f"This DCV desktop is not stopped. You can only modify a stopped desktop.",
                )
            try:
                client_ec2.modify_instance_attribute(
                    InstanceId=instance_id,
                    InstanceType={"Value": args["instance_type"].lower()},
                    DryRun=True,
                )
            except ClientError as e:
                if e.response["Error"].get("Code") == "DryRunOperation":
                    try:
                        client_ec2.modify_instance_attribute(
                            InstanceId=instance_id,
                            InstanceType={"Value": args["instance_type"].lower()},
                        )
                        check_session.session_instance_type = args[
                            "instance_type"
                        ].lower()
                        db.session.commit()
                        return {
                            "success": True,
                            "message": f"Your DCV desktop has been updated successfully to {args['instance_type'].lower()}",
                        }, 200
                    except ClientError as err:
                        if (
                            "not supported for instances with hibernation configured."
                            in err.response["Error"].get("Code")
                        ):
                            return errors.all_errors(
                                "DCV_MODIFY_ERROR",
                                f"Your instance has been started with hibernation enabled. You cannot change the instance type. Start a new session with Hibernation disabled if you want to be able to change your instance type. ",
                            )
                        else:
                            return errors.all_errors(
                                "DCV_MODIFY_ERROR",
                                f"Unable to modify EC2 instance {instance_id} type due to {err}",
                            )
                else:
                    return errors.all_errors(
                        "DCV_MODIFY_ERROR",
                        f"Unable to modify EC2 instance {instance_id}  due to {e}",
                    )

        else:
            return errors.all_errors(
                "DCV_MODIFY_ERROR",
                f"Unable to retrieve this session. It's possible your session has been deleted.",
            )
