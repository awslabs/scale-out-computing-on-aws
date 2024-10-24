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

        logger.info(f"Received parameter for modifying DCV desktop: {args}")

        user = request.headers.get("X-SOCA-USER")
        if user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        if args["os"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="os").as_flask()

        if args["instance_type"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="instance_type").as_flask()

        if args["os"].lower() not in ["linux", "windows"]:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="os", helper="os must be linux or windows"
            ).as_flask()

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
            return SocaError.VIRTUAL_DESKTOP_MODIFY_ERROR(
                session_number=_session_number,
                session_owner=user,
                helper=f"{args['instance_type'].lower()} is not authorized by your Admin.",
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
            if check_session.session_state != "stopped":
                return SocaError.VIRTUAL_DESKTOP_MODIFY_ERROR(
                    session_number=_session_number,
                    session_owner=user,
                    helper=f"This DCV desktop is not stopped. You can only modify a stopped desktop.",
                ).as_flask()
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
                        try:
                            check_session.session_instance_type = args[
                                "instance_type"
                            ].lower()
                            db.session.commit()
                        except Exception as err:
                            db.session.rollback()
                            return SocaError.DB_ERROR(
                                query=check_session,
                                helper=f"Unable to update instance type on database due to {err}",
                            ).as_flask()

                        return SocaResponse(success=True, message= f"Your DCV desktop has been updated successfully to {args['instance_type'].lower()}").as_flask()

                    except ClientError as err:
                        if (
                            "not supported for instances with hibernation configured."
                            in err.response["Error"].get("Code")
                        ):
                            return SocaError.VIRTUAL_DESKTOP_MODIFY_ERROR(
                                session_number=_session_number,
                                session_owner=user,
                                helper=f"Your instance has been started with hibernation enabled. You cannot change the instance type. Start a new session with Hibernation disabled if you want to be able to change your instance type.",
                            ).as_flask()
                        else:
                            return SocaError.VIRTUAL_DESKTOP_MODIFY_ERROR(
                                session_number=_session_number,
                                session_owner=user,
                                helper=f"Unable to modify your virtual desktop hardware yet. If you stopped your desktop recently, please wait a little longer and try again. Error trace: {err}",
                            ).as_flask()
                else:
                    return SocaError.AWS_API_ERROR(
                        service_name="ec2",
                        helper=f"Unable to modify EC2 instance {instance_id}  due to {e}",
                    ).as_flask()

        else:
            return SocaError.VIRTUAL_DESKTOP_MODIFY_ERROR(
                session_number=_session_number,
                session_owner=user,
                helper=f"Unable to retrieve this session. It's possible your session has been deleted.",
            ).as_flask()
