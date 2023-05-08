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
import json
import read_secretmanager
from decorators import private_api
import base64
import boto3
import os
import sys
import errors
from models import db, LinuxDCVSessions, WindowsDCVSessions

logger = logging.getLogger("api")
client_ec2 = boto3.client("ec2", config=config.boto_extra_config())
client_cfn = boto3.client("cloudformation", config=config.boto_extra_config())


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
        logger.info(f"Received parameter for listing DCV desktop: {args}")

        user = request.headers.get("X-SOCA-USER")
        if user is None:
            return errors.all_errors("X-SOCA-USER_MISSING")

        if args["os"] is None or args["is_active"] is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER", "os (str), is_active (str)  are required."
            )

        if args["os"] not in ["windows", "linux"]:
            return errors.all_errors(
                "CLIENT_INVALID_PARAMETER", "os (str) must be windows or linux"
            )

        if args["is_active"].lower() not in ["true", "false"]:
            return errors.all_errors(
                "CLIENT_INVALID_PARAMETER", "is_active (str) must be true, false"
            )

        # Retrieve sessions
        is_active = True if args["is_active"].lower() == "true" else False
        if args["os"].lower() == "windows":
            all_dcv_sessions = WindowsDCVSessions.query.filter(
                WindowsDCVSessions.user == user
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

        else:
            all_dcv_sessions = LinuxDCVSessions.query.filter(
                LinuxDCVSessions.user == user
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

        logger.info(f"Checking {args['os']} desktops for {user}")
        user_sessions = {}
        for session_info in all_dcv_sessions.all():
            try:
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

                stack_name = f"{read_secretmanager.get_soca_configuration()['ClusterId']}-{session_name}-{user}"
                if args["os"].lower() == "windows":
                    host_info = get_host_info(
                        tag_uuid,
                        read_secretmanager.get_soca_configuration()["ClusterId"],
                        "windows",
                    )
                else:
                    host_info = get_host_info(
                        tag_uuid,
                        read_secretmanager.get_soca_configuration()["ClusterId"],
                        session_linux_distribution,
                    )

                logger.info(f"Host Info {host_info}")
                if not host_info:
                    try:
                        check_stack = client_cfn.describe_stacks(StackName=stack_name)
                        logger.info(f"Host Info check_stack {check_stack}")
                        if check_stack["Stacks"][0]["StackStatus"] in [
                            "CREATE_FAILED",
                            "ROLLBACK_COMPLETE",
                            "ROLLBACK_FAILED",
                        ]:
                            logger.info(f"Host Info DEACTIVATE")
                            # no host detected, session no longer active
                            session_info.is_active = False
                            session_info.deactivated_on = datetime.utcnow()
                            db.session.commit()
                    except Exception as err:
                        logger.error(
                            f"Error checking CFN stack {stack_name} due to {err}"
                        )
                        session_info.is_active = False
                        session_info.deactivated_on = datetime.utcnow()
                        db.session.commit()
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
                        session_authentication_token = base64.b64encode(
                            encrypt(authentication_data)
                        ).decode("utf-8")
                        session_info.dcv_authentication_token = (
                            session_authentication_token
                        )
                        db.session.commit()

                if "status" not in host_info.keys():
                    try:
                        check_stack = client_cfn.describe_stacks(StackName=stack_name)
                        logger.info(f"Host Info check_stack {check_stack}")
                        if check_stack["Stacks"][0]["StackStatus"] in [
                            "CREATE_FAILED",
                            "ROLLBACK_COMPLETE",
                            "ROLLBACK_FAILED",
                        ]:
                            logger.info(f"Host Info DEACTIVATE")
                            # no host detected, session no longer active
                            session_info.is_active = False
                            session_info.deactivated_on = datetime.utcnow()
                            db.session.commit()

                    except Exception as err:
                        logger.error(
                            f"Error checking CFN stack {stack_name} due to {err}"
                        )
                        session_info.is_active = False
                        session_info.deactivated_on = datetime.utcnow()
                        db.session.commit()
                else:
                    if (
                        host_info["status"] in ["stopped", "stopping"]
                        and session_state != "stopped"
                    ):
                        session_state = "stopped"
                        session_info.session_state = "stopped"
                        db.session.commit()

                if session_state == "pending" and session_host_private_dns is not False:
                    check_dcv_state = get(
                        f"https://{read_secretmanager.get_soca_configuration()['LoadBalancerDNSName']}/{session_host_private_dns}/",
                        allow_redirects=False,
                        verify=False,
                    )  # nosec

                    logger.info(
                        "Checking {} for {} and received status {} ".format(
                            "https://"
                            + read_secretmanager.get_soca_configuration()[
                                "LoadBalancerDNSName"
                            ]
                            + "/"
                            + session_host_private_dns
                            + "/",
                            session_info,
                            check_dcv_state.status_code,
                        )
                    )

                    if check_dcv_state.status_code == 200:
                        session_info.session_state = "running"
                        db.session.commit()

                user_sessions[session_number] = {
                    "url": f"https://{read_secretmanager.get_soca_configuration()['LoadBalancerDNSName']}/{session_host_private_dns}/",
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
                    "connection_string": f"https://{read_secretmanager.get_soca_configuration()['LoadBalancerDNSName']}/{session_host_private_dns}/?authToken={dcv_authentication_token}#{session_id}",
                }

                # logger.info(user_sessions)
            except Exception as err:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                logger.error(exc_type, fname, exc_tb.tb_lineno)
                return errors.all_errors(type(err).__name__, err)

        return {"success": True, "message": user_sessions}, 200
