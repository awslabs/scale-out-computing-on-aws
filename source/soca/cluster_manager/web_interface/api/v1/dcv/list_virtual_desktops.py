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
import json
from decorators import private_api
import os
import sys
from models import db, VirtualDesktopSessions, SoftwareStacks, VirtualDesktopProfiles
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.ssm_parameter_store import SocaConfig
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_cfn = utils_boto3.get_boto(service_name="cloudformation").message
client_ssm = utils_boto3.get_boto(service_name="ssm").message


class ListVirtualDesktops(Resource):
    @private_api
    def get(self):
        """
        List DCV desktop sessions for a given user
        ---
        tags:
          - DCV

        parameters:
          - in: body
            name: body
            schema:
              required:
                - os
                - state
              properties:
                session_number:
                  type: string
                  description: Session Number
                os:
                  type: string
                  description: DCV session type (Windows or Linux)
                state:
                  type: string
                  description: active or inactive

                run_state:
                  type: string
                  description: The state of the desktop (running, pending, stopped ..)
        responses:
          200:
            description: Pair of user/token is valid
          401:
            description: Invalid user/token pair
        """
        parser = reqparse.RequestParser()
        parser.add_argument("is_active", type=str, location="args")
        parser.add_argument("session_uuid", type=str, location="args")
        parser.add_argument("state", type=str, location="args")
        args = parser.parse_args()
        logger.debug(f"Received parameter for listing DCV desktop: {args}")

        user = request.headers.get("X-SOCA-USER")
        if user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        if args["is_active"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="is_active").as_flask()

        _check_active = SocaCastEngine(args["is_active"]).cast_as(expected_type=bool)
        if not _check_active.success:
            return SocaError.CLIENT_INVALID_PARAMETER(
                parameter="is_active", helper="is_active must be true or false"
            ).as_flask()
        else:
            _is_active = _check_active.message

        # Retrieve sessions
        logger.info(f"Retrieving DCV sessions for {user}")
        _all_dcv_sessions = (
            VirtualDesktopSessions.query.join(
                SoftwareStacks,
                SoftwareStacks.id == VirtualDesktopSessions.software_stack_id,
            )
            .join(
                VirtualDesktopProfiles,
                VirtualDesktopProfiles.id == SoftwareStacks.virtual_desktop_profile_id,
            )
            .filter(
                VirtualDesktopSessions.session_owner == f"{user}",
                VirtualDesktopSessions.is_active == _is_active,
            )
            .add_columns(
                SoftwareStacks.virtual_desktop_profile_id,
                SoftwareStacks.ami_arch,
                VirtualDesktopProfiles.allowed_instance_types,
            )
        )

        if args["state"] is not None:
            logger.debug(f"Adding filter for session_state to {args['state']}")
            _all_dcv_sessions = _all_dcv_sessions.filter(
                VirtualDesktopSessions.session_state == args["state"]
            )

        if args["session_uuid"] is not None:
            logger.debug(f"Adding filter for session_uuid to {args['session_uuid']}")
            _all_dcv_sessions = _all_dcv_sessions.filter(
                VirtualDesktopSessions.session_uuid == args["session_uuid"]
            )

        logger.debug(f"Found all DCV sessions {_all_dcv_sessions.all()}")

        user_sessions = {}
        logger.info("Getting Session information for all session")

        _get_soca_parameters = SocaConfig(key="/").get_value(return_as=dict)
        if _get_soca_parameters.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve SOCA Parameters: {_get_soca_parameters.get('message')}"
            ).as_flask()
        else:
            _soca_parameters = _get_soca_parameters.get("message")

        _thumbnails = {}

        for (
            session_info,
            virtual_desktop_profile_id,
            ami_arch,
            allowed_instance_types,
        ) in _all_dcv_sessions.all():
            try:
                # build connection string
                # console session Windows -> do not user external authenticator and rely on DCV login page
                # Linux -> use external authenticator
                if _soca_parameters.get("/configuration/UserDirectory/provider") in [
                    "existing_activedirectory",
                    "aws_ds_managed_activedirectory",
                    "aws_ds_simple_activedirectory",
                ]:
                    if session_info.os_family == "windows":
                        _username = f"{_soca_parameters.get('/configuration/UserDirectory/short_name')}\\{session_info.session_owner}"
                    else:
                        # no need to specify domain on Linux
                        _username = session_info.session_owner
                else:
                    _username = session_info.session_owner

                if session_info.session_type == "console":
                    # use system auth authenticator
                    _connection_string = f"https://{_soca_parameters.get('/configuration/DCVEntryPointDNSName')}/{session_info.instance_private_dns}/?username={_username}#{session_info.session_id}"
                else:
                    # use external authenticator
                    _connection_string = f"https://{_soca_parameters.get('/configuration/DCVEntryPointDNSName')}/{session_info.instance_private_dns}/?authToken={session_info.authentication_token}#{session_info.session_id}"

                _session_data = {
                    "session_uuid": session_info.session_uuid,
                    "session_name": session_info.session_name,
                    "session_owner": session_info.session_owner,
                    "session_state": session_info.session_state,
                    "session_type": session_info.session_type,
                    "session_state_latest_change_time": session_info.session_state_latest_change_time,
                    "session_local_admin_password": session_info.session_local_admin_password,
                    "schedule": session_info.schedule,
                    "session_thumbnail": session_info.session_thumbnail,
                    "session_id": session_info.session_id,
                    "session_token": session_info.session_token,
                    "authentication_token": session_info.authentication_token,
                    "instance_private_dns": session_info.instance_private_dns,
                    "instance_private_ip": session_info.instance_private_ip,
                    "instance_id": session_info.instance_id,
                    "instance_type": session_info.instance_type,
                    "instance_base_os": session_info.instance_base_os,
                    "os_family": session_info.os_family,
                    "support_hibernation": session_info.support_hibernation,
                    "stack_name": session_info.stack_name,
                    "software_stack_id": session_info.software_stack_id,
                    "ami_arch": ami_arch,  # joined
                    "virtual_desktop_profile_id": virtual_desktop_profile_id,  # joined
                    "allowed_instance_types": sorted(
                        json.loads(allowed_instance_types).get(ami_arch)
                    ),  # joined
                    "url": f"https://{_soca_parameters.get('/configuration/DCVEntryPointDNSName')}/{session_info.instance_private_dns}/",
                    "connection_string": _connection_string,
                }

                user_sessions[session_info.session_uuid] = _session_data
                logger.debug(f"Session Info {user_sessions[session_info.session_uuid]}")

            except Exception as err:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                return SocaError.GENERIC_ERROR(
                    helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
                ).as_flask()

        logger.debug(f"Complete User Sessions details to return: {user_sessions}")
        return SocaResponse(success=True, message=user_sessions).as_flask()
