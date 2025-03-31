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
from models import db, VirtualDesktopSessions, SoftwareStacks, VirtualDesktopProfiles
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.response import SocaResponse
import json

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class ResizeVirtualDesktop(Resource):
    @private_api
    def put(self):
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
        parser.add_argument("session_uuid", type=str, location="form")
        parser.add_argument("instance_type", type=str, location="form")
        args = parser.parse_args()
        logger.info(f"Received parameter for resizing DCV desktop: {args}")

        _session_uuid = args["session_uuid"]
        _instance_type = args["instance_type"]

        if _session_uuid is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="_session_uuid"
            ).as_flask()

        _user = request.headers.get("X-SOCA-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        if _instance_type is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="instance_type"
            ).as_flask()

        _check_session = (
            VirtualDesktopSessions.query.join(
                SoftwareStacks,
                SoftwareStacks.id == VirtualDesktopSessions.software_stack_id,
            )
            .join(
                VirtualDesktopProfiles,
                VirtualDesktopProfiles.id == SoftwareStacks.virtual_desktop_profile_id,
            )
            .filter(
                VirtualDesktopSessions.session_owner == _user,
                VirtualDesktopSessions.is_active == True,
                VirtualDesktopSessions.session_uuid == _session_uuid,
            )
            .add_columns(
                SoftwareStacks.ami_arch,
                VirtualDesktopProfiles.allowed_instance_types,
            )
        ).first()

        if _check_session:
            session_info = _check_session[0]  # VirtualDesktopSessions
            _ami_arch = _check_session[1]
            allowed_instance_types = json.loads(_check_session[2]).get(
                _ami_arch
            )  # VirtualDesktopProfiles
            if _instance_type not in allowed_instance_types:
                return SocaError.VIRTUAL_DESKTOP_MODIFY_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"Instance type {_instance_type} is not allowed by the software stack. Allowed instance types are: {allowed_instance_types}",
                ).as_flask()

            _instance_id = session_info.instance_id
            _session_state = session_info.session_state
            _software_stack = session_info.software_stack_id
            # Validate instance type provided is allowed by the software stack

            if _session_state != "stopped":
                return SocaError.VIRTUAL_DESKTOP_MODIFY_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"This Virtual Desktop is not stopped. You can only modify a stopped desktop.",
                ).as_flask()
            try:
                client_ec2.modify_instance_attribute(
                    InstanceId=_instance_id,
                    InstanceType={"Value": args["instance_type"].lower()},
                )

                try:
                    session_info.instance_type = args["instance_type"].lower()
                    db.session.commit()
                except Exception as err:
                    db.session.rollback()
                    return SocaError.DB_ERROR(
                        query=session_info,
                        helper=f"Unable to update instance type on database due to {err}",
                    ).as_flask()

            except Exception as err:
                return SocaError.VIRTUAL_DESKTOP_MODIFY_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"Unable to modify this desktop because of {err}.",
                ).as_flask()

            return SocaResponse(
                success=True,
                message=f"Your virtual desktop has been updated",
            ).as_flask()

        else:
            return SocaError.VIRTUAL_DESKTOP_MODIFY_ERROR(
                session_number=_session_uuid,
                session_owner=_user,
                helper=f"Unable to retrieve this session. It's possible your session has been deleted.",
            ).as_flask()
