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
from datetime import datetime, timezone
import json
from decorators import private_api
import base64
import os
import sys
from models import db, LinuxDCVSessions, WindowsDCVSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.ssm_parameter_store import SocaConfig
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
import re

logger = logging.getLogger("soca_logger")

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_cfn = utils_boto3.get_boto(service_name="cloudformation").message


def encrypt(message):
    key = config.Config.DCV_TOKEN_SYMMETRIC_KEY
    cipher_suite = Fernet(key)
    return cipher_suite.encrypt(message.encode("utf-8"))


def get_host_info(tag_uuid, cluster_id, operating_system):
    host_info = {}

    ec2_paginator = client_ec2.get_paginator("describe_instances")
    ec2_iterator = ec2_paginator.paginate(
        Filters=[
            {"Name": "tag:soca:DCVSessionUUID", "Values": [tag_uuid]},
            {"Name": "tag:soca:ClusterId", "Values": [cluster_id]},
            {"Name": "tag:soca:DCVSystem", "Values": [operating_system]},
        ],
    )

    for page in ec2_iterator:
        for reservation in page["Reservations"]:
            for instance in reservation["Instances"]:
                if instance["PrivateDnsName"].split(".")[0]:
                    host_info["private_dns"] = instance["PrivateDnsName"].split(".")[0]
                    host_info["private_ip"] = instance["PrivateIpAddress"]
                    host_info["instance_id"] = instance["InstanceId"]
                    host_info["status"] = instance["State"]["Name"]

    logger.debug(f"Host info: {host_info}")
    return host_info


class ListDesktops(Resource):
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
        parser.add_argument("os", type=str, location="args")
        parser.add_argument("is_active", type=str, location="args")
        parser.add_argument("session_number", type=str, location="args")
        parser.add_argument("state", type=str, location="args")
        args = parser.parse_args()
        logger.debug(f"Received parameter for listing DCV desktop: {args}")

        user = request.headers.get("X-SOCA-USER")
        if user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()
        if args["os"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="os").as_flask()

        if args["is_active"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="is_active").as_flask()

        if args["os"] not in ["windows", "linux"]:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="os", helper="os (str) must be windows or linux"
            ).as_flask()

        _check_active = SocaCastEngine(args["is_active"]).cast_as(expected_type=bool)
        if not _check_active.success:
            return SocaError.CLIENT_INVALID_PARAMETER(
                parameter="is_active", helper="is_active must be true or false"
            ).as_flask()
        else:
            args["is_active"] = _check_active.message

        # Retrieve sessions
        is_active = True if args["is_active"] else False
        if args["os"].lower() == "windows":
            logger.info(f"Retrieving Windows DCV sessions for {user}")
            all_dcv_sessions = WindowsDCVSessions.query.filter(
                WindowsDCVSessions.user == f"{user}"
            )

            if args["state"] is not None:
                all_dcv_sessions = all_dcv_sessions.filter(
                    WindowsDCVSessions.session_state == args["state"]
                )
            if args["session_number"] is not None:
                all_dcv_sessions = all_dcv_sessions.filter(
                    WindowsDCVSessions.session_number == args["session_number"]
                )

            all_dcv_sessions = all_dcv_sessions.filter(
                WindowsDCVSessions.is_active == is_active
            )
            logger.info(f"Found all DCV Windows sessions {all_dcv_sessions.all()}")

        else:
            logger.info(f"Retrieving Linux DCV sessions for {user}")
            all_dcv_sessions = LinuxDCVSessions.query.filter(
                LinuxDCVSessions.user == f"{user}"
            )
            if args["state"] is not None:
                all_dcv_sessions = all_dcv_sessions.filter(
                    LinuxDCVSessions.session_state == args["state"]
                )
            if args["session_number"] is not None:
                all_dcv_sessions = all_dcv_sessions.filter(
                    LinuxDCVSessions.session_number == args["session_number"]
                )
            all_dcv_sessions = all_dcv_sessions.filter(
                LinuxDCVSessions.is_active == is_active
            )
            logger.info(f"Found all DCV Linux sessions {all_dcv_sessions.all()}")

        user_sessions = {}
        logger.info("Getting Session information for all session")
        for session_info in all_dcv_sessions.all():
            try:
                logger.debug(session_info)
                session_number = session_info.session_number
                session_state = session_info.session_state
                tag_uuid = session_info.tag_uuid
                session_name = session_info.session_name
                session_host_private_dns = session_info.session_host_private_dns
                session_token = session_info.session_token
                session_local_admin_password = (
                    session_info.session_local_admin_password
                    if args["os"] == "windows"
                    else None
                )
                if args["os"].lower() != "windows":
                    session_linux_distribution = session_info.session_linux_distribution
                session_instance_type = session_info.session_instance_type
                session_instance_id = session_info.session_instance_id
                support_hibernation = session_info.support_hibernation
                dcv_authentication_token = session_info.dcv_authentication_token
                session_id = session_info.session_id

                session_schedule = {
                    "monday": f"{session_info.schedule_monday_start}-{session_info.schedule_monday_stop}",
                    "tuesday": f"{session_info.schedule_tuesday_start}-{session_info.schedule_tuesday_stop}",
                    "wednesday": f"{session_info.schedule_wednesday_start}-{session_info.schedule_wednesday_stop}",
                    "thursday": f"{session_info.schedule_thursday_start}-{session_info.schedule_thursday_stop}",
                    "friday": f"{session_info.schedule_friday_start}-{session_info.schedule_friday_stop}",
                    "saturday": f"{session_info.schedule_saturday_start}-{session_info.schedule_saturday_stop}",
                    "sunday": f"{session_info.schedule_sunday_start}-{session_info.schedule_sunday_stop}",
                }

                _sanitized_user = re.sub(r"[._-]", "",user)
                stack_name = f"{SocaConfig(key='/configuration/ClusterId').get_value().get('message')}-{session_name}-{_sanitized_user}"
                # user can have - _ or . which are not allowed on CFN (- is allowed but we remove it for consistency)

                if args["os"].lower() == "windows":
                    host_info = get_host_info(
                        tag_uuid,
                        SocaConfig(key="/configuration/ClusterId")
                        .get_value()
                        .get("message"),
                        "windows",
                    )
                else:
                    host_info = get_host_info(
                        tag_uuid,
                        SocaConfig(key="/configuration/ClusterId")
                        .get_value()
                        .get("message"),
                        session_linux_distribution,
                    )

                logger.info(f"Host Info {host_info}")
                if not host_info:
                    logger.debug(
                        f"Determining Host status via CloudFormation stack {stack_name}"
                    )
                    try:
                        check_stack = client_cfn.describe_stacks(StackName=stack_name)
                        _stack_status = check_stack["Stacks"][0]["StackStatus"]
                    except Exception as err:
                        _stack_status = False
                        logger.error(
                            f"Error checking CFN stack {stack_name} due to {err}, deleting record from database"
                        )

                    logger.info(
                        f"CloudFormation Stack {stack_name} status: {_stack_status}"
                    )
                    if _stack_status in [
                        False,
                        "CREATE_FAILED",
                        "ROLLBACK_COMPLETE",
                        "ROLLBACK_FAILED",
                    ]:
                        logger.info(f"Host Info DEACTIVATE")
                        # no host detected, session no longer active
                        try:
                            session_info.is_active = False
                            session_info.deactivated_on = datetime.now(timezone.utc)
                            db.session.commit()
                        except Exception as err:
                            return SocaError.DB_ERROR(
                                query=session_info,
                                helper=f"No host detected for {session_name} for user {user}. Unable to deactivate session in DB due to {err}",
                            ).as_flask()
                else:
                    # detected EC2 host for the session
                    if not dcv_authentication_token:
                        session_info.session_host_private_dns = host_info["private_dns"]
                        session_info.session_host_private_ip = host_info["private_ip"]
                        session_info.session_instance_id = host_info["instance_id"]

                        authentication_data = json.dumps(
                            {
                                "system": "windows"
                                if args["os"].lower() == "windows"
                                else session_linux_distribution,
                                "session_instance_id": host_info["instance_id"],
                                "session_token": session_token,
                                "session_user": user,
                            }
                        )

                        try:
                            session_authentication_token = base64.b64encode(
                                encrypt(authentication_data)
                            ).decode("utf-8")
                            session_info.dcv_authentication_token = (
                                session_authentication_token
                            )
                            db.session.commit()
                        except Exception as err:
                            return SocaError.DB_ERROR(
                                query=session_info,
                                helper=f"Unable to update dcv auth token in DB due to {err}",
                            ).as_flask()

                if "status" not in host_info.keys():
                    try:
                        check_stack = client_cfn.describe_stacks(StackName=stack_name)
                        _stack_status = check_stack["Stacks"][0]["StackStatus"]
                    except Exception as err:
                        _stack_status = False
                        logger.error(
                            f"Error checking CFN stack {stack_name} due to {err}, deleting record from database"
                        )

                    logger.info(f"Host Info check_stack {_stack_status}")
                    if _stack_status in [
                        False,
                        "CREATE_FAILED",
                        "ROLLBACK_COMPLETE",
                        "ROLLBACK_FAILED",
                    ]:
                        logger.info(f"Host Info DEACTIVATE")
                        # no host detected, session no longer active
                        try:
                            session_info.is_active = False
                            session_info.deactivated_on = datetime.now(timezone.utc)
                            db.session.commit()
                        except Exception as err:
                            return SocaError.DB_ERROR(
                                query=session_info,
                                helper=f"No host detected for {session_name} for user {user}. Unable to deactivate session in DB due to {err}",
                            ).as_flask()

                else:
                    if (
                        host_info["status"] in ["stopped", "stopping"]
                        and session_state != "stopped"
                    ):
                        try:
                            session_state = "stopped"
                            session_info.session_state = "stopped"
                            db.session.commit()
                        except Exception as err:
                            return SocaError.DB_ERROR(
                                query=session_info,
                                helper=f"Unable to set session_state to stopped because of {err}",
                            ).as_flask()

                if session_state == "pending" and session_host_private_dns is not False:
                    logger.debug(
                        f"Session State is pending - checking DCV status via LoadBalancer for {session_host_private_dns}"
                    )
                    check_dcv_state = get(
                        f"https://{SocaConfig(key='/configuration/LoadBalancerDNSName').get_value().message}/{session_host_private_dns}/",
                        allow_redirects=False,
                        verify=False,
                    )  # nosec

                    logger.debug(f"LoadBalancer check result: {check_dcv_state}")

                    if check_dcv_state.status_code == 200:
                        logger.debug(
                            f"Updating session status in Database to running due to status_code 200"
                        )
                        try:
                            session_info.session_state = "running"
                            db.session.commit()
                        except Exception as err:
                            return SocaError.DB_ERROR(
                                query=session_info,
                                helper=f"Unable to set session_state to running because of {err}",
                            ).as_flask()

                user_sessions[session_number] = {
                    "url": f"https://{SocaConfig(key='/configuration/LoadBalancerDNSName').get_value().message}/{session_host_private_dns}/",
                    "session_local_admin_password": session_local_admin_password,
                    "session_state": session_state,
                    "session_authentication_token": dcv_authentication_token,
                    "session_id": session_id,
                    "session_name": session_name,
                    "session_instance_id": session_instance_id,
                    "session_instance_type": session_instance_type,
                    "tag_uuid": tag_uuid,
                    "support_hibernation": support_hibernation,
                    "session_schedule": session_schedule,
                    "connection_string": f"https://{SocaConfig(key='/configuration/LoadBalancerDNSName').get_value().message}/{session_host_private_dns}/?authToken={dcv_authentication_token}#{session_id}",
                }

            except Exception as err:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                return SocaError.GENERIC_ERROR(
                    helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
                ).as_flask()

        logger.debug(f"Complete User Sessions details to return: {user_sessions}")
        return SocaResponse(success=True, message=user_sessions).as_flask()
