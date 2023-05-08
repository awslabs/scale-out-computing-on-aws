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
from requests import get
import logging
from datetime import datetime
import read_secretmanager
from decorators import private_api
from flask import request
import re
import boto3
import uuid
import errors
import os
import random
import string
from botocore.exceptions import ClientError
from models import db, WindowsDCVSessions, AmiList
import dcv_cloudformation_builder
import sys

logger = logging.getLogger("api")
client_ec2 = boto3.client("ec2", config=config.boto_extra_config())
client_cfn = boto3.client("cloudformation", config=config.boto_extra_config())
client_lambda = boto3.client("lambda", config=config.boto_extra_config())


def validate_ec2_image(image_id):
    image_exist = (
        AmiList.query.filter(AmiList.is_active == True, AmiList.ami_id == image_id)
        .filter(AmiList.ami_type == "windows")
        .first()
    )
    if image_exist:
        return True
    else:
        return False


def can_launch_instance(launch_parameters):
    try:
        client_ec2.run_instances(
            BlockDeviceMappings=[
                {
                    "DeviceName": "/dev/xvda"
                    if launch_parameters["base_os"] == "amazonlinux2"
                    else "/dev/sda1",
                    "Ebs": {
                        "DeleteOnTermination": True,
                        "VolumeSize": launch_parameters["disk_size"],
                        "VolumeType": "gp3",
                        "Encrypted": True,
                    },
                },
            ],
            MaxCount=1,
            MinCount=1,
            SecurityGroupIds=[launch_parameters["security_group_id"]],
            InstanceType=launch_parameters["instance_type"],
            IamInstanceProfile={"Arn": launch_parameters["instance_profile"]},
            SubnetId=random.choice(launch_parameters["soca_private_subnets"])
            if not launch_parameters["subnet_id"]
            else launch_parameters["subnet_id"],
            Placement={"Tenancy": launch_parameters["tenancy"]},
            UserData=launch_parameters["user_data"],
            ImageId=launch_parameters["image_id"],
            DryRun=True,
            HibernationOptions={"Configured": launch_parameters["hibernate"]},
        )

    except ClientError as err:
        if err.response["Error"].get("Code") == "DryRunOperation":
            return True
        else:
            return f"Dry run failed. Unable to launch capacity due to: {err}"


def session_already_exist(session_number):
    user_sessions = {}
    get_desktops = get(
        config.Config.FLASK_ENDPOINT + "/api/dcv/desktops",
        headers={
            "X-SOCA-USER": request.headers.get("X-SOCA-USER"),
            "X-SOCA-TOKEN": request.headers.get("X-SOCA-TOKEN"),
        },
        params={
            "os": "windows",
            "is_active": "true",
            "session_number": str(session_number),
        },
        verify=False,
    )
    if get_desktops.status_code == 200:
        user_sessions = get_desktops.json()["message"]
        user_sessions = {
            int(k): v for k, v in user_sessions.items()
        }  # convert all keys (session number) back to integer

    if int(session_number) in user_sessions.keys():
        return True
    else:
        return False


class CreateWindowsDesktop(Resource):
    @private_api
    def post(self, session_number):
        """
        Create a new DCV desktop session (Windows)
        ---
        tags:
          - DCV

        parameters:
          - in: body
            name: body
            schema:
              required:
                - instance_type
                - disk_size
                - session_number
                - instance_ami
                - subnet_id
                - hibernate
              properties:
                instance_type:
                  type: string
                  description: Type of EC2 instance to provision
                disk_size:
                  type: string
                  description: EBS size to provision for root device
                session_number:
                  type: string
                  description: DCV Session Number
                session_name:
                  type: string
                  description: DCV Session Name
                instance_ami:
                  type: string
                  description: Custom AMI to use
                subnet_id:
                  type: string
                  description: Specify a subnet id to launch the EC2
                hibernate:
                  type: string
                  description: True/False.
                user:
                  type: string
                  description: owner of the session
                tenancy:
                  type: string
                  description: EC2 tenancy (default or dedicated)
        responses:
          200:
            description: Pair of user/token is valid
          401:
            description: Invalid user/token pair
        """

        parser = reqparse.RequestParser()
        parser.add_argument("instance_type", type=str, location="form")
        parser.add_argument("disk_size", type=str, location="form")
        parser.add_argument("session_name", type=str, location="form")
        parser.add_argument("instance_ami", type=str, location="form")
        parser.add_argument("subnet_id", type=str, location="form")
        parser.add_argument("hibernate", type=str, location="form")
        parser.add_argument("tenancy", type=str, location="form")
        args = parser.parse_args()
        logger.info(f"Received parameter for new Windows DCV session: {args}")

        try:
            user = request.headers.get("X-SOCA-USER")
            if user is None:
                return errors.all_errors("X-SOCA-USER_MISSING")
            if not args["subnet_id"]:
                args["subnet_id"] = False
            if not args["hibernate"]:
                args["hibernate"] = False
            elif args["hibernate"].lower() == "false":
                args["hibernate"] = False
            elif args["hibernate"].lower() == "true":
                args["hibernate"] = True
            else:
                return errors.all_errors(
                    "DCV_LAUNCH_ERROR", f"hibernate must be either true or false"
                )

            if session_number is None:
                return errors.all_errors(
                    "CLIENT_MISSING_PARAMETER",
                    "session_number not found in URL. Endpoint is /api/dcv/desktop/<session_number>/windows",
                )
            else:
                args["session_number"] = str(session_number)

            if args["instance_type"] is None:
                return errors.all_errors(
                    "CLIENT_MISSING_PARAMETER", "instance_type (str) is required."
                )

            args["disk_size"] = 30 if args["disk_size"] is None else args["disk_size"]
            try:
                args["disk_size"] = int(args["disk_size"])
            except ValueError:
                return errors.all_errors(
                    "DCV_LAUNCH_ERROR", f"disk_size must be an integer"
                )

            try:
                if int(args["session_number"]) > int(
                    config.Config.DCV_WINDOWS_SESSION_COUNT
                ):
                    return errors.all_errors(
                        "DCV_LAUNCH_ERROR",
                        f"session_number {args['session_number']} is greater than the max number of session allowed ({config.Config.DCV_WINDOWS_SESSION_COUNT}). Contact admin for increase.",
                    )
            except Exception as err:
                return errors.all_errors(
                    "DCV_LAUNCH_ERROR",
                    f"Session Number {args['session_number']} must be a number. Err: {err}",
                )

            session_uuid = str(uuid.uuid4())
            region = os.environ["AWS_DEFAULT_REGION"]
            instance_type = args["instance_type"]
            soca_configuration = read_secretmanager.get_soca_configuration()
            instance_profile = soca_configuration["ComputeNodeInstanceProfileArn"]
            security_group_id = soca_configuration["ComputeNodeSecurityGroup"]

            if session_already_exist(args["session_number"]) is True:
                return errors.all_errors(
                    "DCV_LAUNCH_ERROR",
                    f"Session Number {args['session_number']} is already used by an active desktop. Terminate it first before being able to use the same number",
                )

            # sanitize session_name, limit to 255 chars
            if args["session_name"] is None:
                session_name = "WindowsDesktop" + str(args["session_number"])
            else:
                session_name = re.sub(r"\W+", "", args["session_name"])[:255]
                if session_name == "":
                    # handle case when session name specified by user only contains invalid char
                    session_name = "WindowsDesktop" + str(args["session_number"])

            # Official DCV AMI
            # https://aws.amazon.com/marketplace/pp/B07TVL513S + https://aws.amazon.com/marketplace/pp/B082HYM34K
            # Non graphics is everything but g3/g4
            if args["instance_ami"] is None or args["instance_ami"] == "base":
                dcv_windows_ami = config.Config.DCV_WINDOWS_AMI
                if instance_type.startswith("g"):
                    if instance_type.startswith("g4ad"):
                        if (
                            region not in dcv_windows_ami["graphics-amd"].keys()
                            and args["instance_ami"] is None
                        ):
                            return errors.all_errors(
                                "DCV_LAUNCH_ERROR",
                                f"Sorry, Windows Desktop is not available on your AWS region. Base AMI are only available on { dcv_windows_ami['graphics-amd'].keys()}",
                            )
                        else:
                            image_id = dcv_windows_ami["graphics-amd"][region]
                    else:
                        if (
                            region not in dcv_windows_ami["graphics"].keys()
                            and args["instance_ami"] is False
                        ):
                            return errors.all_errors(
                                "DCV_LAUNCH_ERROR",
                                f"Sorry, Windows Desktop is not available on your AWS region. Base AMI are only available on {dcv_windows_ami['graphics'].keys()}",
                            )
                        else:
                            image_id = dcv_windows_ami["graphics"][region]
                else:
                    if (
                        region not in dcv_windows_ami["non-graphics"].keys()
                        and args["instance_ami"] is False
                    ):
                        return errors.all_errors(
                            "DCV_LAUNCH_ERROR",
                            f"Sorry, Windows Desktop is not available on your AWS region. Base AMI are only available on {dcv_windows_ami['non-graphics'].keys()}",
                        )
                    else:
                        image_id = dcv_windows_ami["non-graphics"][region]
            else:
                if not args["instance_ami"].startswith("ami-"):
                    return errors.all_errors(
                        "DCV_LAUNCH_ERROR",
                        f"AMI {args['instance_ami']} does not seems to be valid. Must start with ami-<id>",
                    )
                else:
                    if validate_ec2_image(args["instance_ami"]) is False:
                        return errors.all_errors(
                            "DCV_LAUNCH_ERROR",
                            f"AMI {args['instance_ami']} does not seems to be registered on SOCA. Refer to https://awslabs.github.io/scale-out-computing-on-aws/web-interface/create-virtual-desktops-images/",
                        )
                    else:
                        image_id = args["instance_ami"]

            digits = [
                random.choice("".join(random.choice(string.digits) for _ in range(10)))
                for _ in range(3)
            ]
            uppercase = [
                random.choice(
                    "".join(random.choice(string.ascii_uppercase) for _ in range(10))
                )
                for _ in range(3)
            ]
            lowercase = [
                random.choice(
                    "".join(random.choice(string.ascii_lowercase) for _ in range(10))
                )
                for _ in range(3)
            ]
            pw = digits + uppercase + lowercase
            session_local_admin_password = "".join(random.sample(pw, len(pw)))
            user_data_script = open(
                "/apps/soca/"
                + soca_configuration["ClusterId"]
                + "/cluster_node_bootstrap/windows/ComputeNodeInstallDCVWindows.ps",
                "r",
            )
            user_data = user_data_script.read()
            user_data_script.close()
            user_data = user_data.replace(
                "%SOCA_LOCAL_ADMIN_PASSWORD%", session_local_admin_password
            )
            user_data = user_data.replace(
                "%SOCA_SchedulerPrivateIP%",
                soca_configuration["SchedulerPrivateIP"]
                + ":"
                + str(config.Config.FLASK_PORT),
            )
            user_data = user_data.replace(
                "%SOCA_LoadBalancerDNSName%", soca_configuration["LoadBalancerDNSName"]
            )
            user_data = user_data.replace("%SOCA_LOCAL_USER%", user)

            # required for EBS tagging
            user_data = user_data.replace("%SOCA_JOB_ID%", str(session_name))
            user_data = user_data.replace("%SOCA_JOB_OWNER%", user)
            user_data = user_data.replace("%SOCA_JOB_PROJECT%", "dcv")
            user_data = user_data.replace(
                "%SOCA_AUTH_PROVIDER%", soca_configuration["AuthProvider"]
            )
            user_data = user_data.replace(
                "%SOCA_DS_JOIN_USERNAME%",
                "false"
                if soca_configuration["AuthProvider"] == "openldap"
                else soca_configuration["DSDomainAdminUsername"],
            )
            user_data = user_data.replace(
                "%SOCA_DS_JOIN_PASSWORD%",
                "false"
                if soca_configuration["AuthProvider"] == "openldap"
                else soca_configuration["DSDomainAdminPassword"],
            )
            user_data = user_data.replace(
                "%SOCA_DS_NETBIOS%",
                "false"
                if soca_configuration["AuthProvider"] == "openldap"
                else soca_configuration["DSDomainNetbios"],
            )
            user_data = user_data.replace(
                "%SOCA_DS_DOMAIN%",
                "false"
                if soca_configuration["AuthProvider"] == "openldap"
                else soca_configuration["DSDomainName"],
            )

            if config.Config.DCV_WINDOWS_AUTOLOGON is True:
                user_data = user_data.replace("%SOCA_WINDOWS_AUTOLOGON%", "true")
            else:
                user_data = user_data.replace("%SOCA_WINDOWS_AUTOLOGON%", "false")

            if args["hibernate"]:
                try:
                    check_hibernation_support = client_ec2.describe_instance_types(
                        InstanceTypes=[instance_type],
                        Filters=[{"Name": "hibernation-supported", "Values": ["true"]}],
                    )
                    logger.info(
                        f"Checking in {instance_type} support Hibernation : {check_hibernation_support}"
                    )
                    if len(check_hibernation_support["InstanceTypes"]) == 0:
                        if config.Config.DCV_FORCE_INSTANCE_HIBERNATE_SUPPORT is True:
                            return errors.all_errors(
                                "DCV_LAUNCH_ERROR",
                                f"Sorry your administrator limited <a href='https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Hibernate.html' target='_blank' rel='noopener,noreferrer'>DCV to instances that support hibernation mode</a> <br> Please choose a different type of instance.",
                            )
                        else:
                            return errors.all_errors(
                                "DCV_LAUNCH_ERROR",
                                f"Sorry you have selected {instance_type} with hibernation support, but this instance type does not support it. Either disable hibernation support or pick a different instance type",
                            )

                except ClientError as e:
                    return errors.all_errors(
                        "DCV_LAUNCH_ERROR",
                        f"Error while checking hibernation support due to {e}",
                    )

            launch_parameters = {
                "security_group_id": security_group_id,
                "instance_profile": instance_profile,
                "instance_type": instance_type,
                "soca_private_subnets": soca_configuration["PrivateSubnets"],
                "user_data": user_data,
                "subnet_id": args["subnet_id"],
                "tenancy": args["tenancy"],
                "image_id": image_id,
                "session_name": session_name,
                "session_uuid": session_uuid,
                "base_os": "windows",
                "disk_size": args["disk_size"],
                "cluster_id": soca_configuration["ClusterId"],
                "metadata_http_tokens": soca_configuration["MetadataHttpTokens"],
                "hibernate": args["hibernate"],
                "user": user,
                "Version": soca_configuration.get("Version", ""),
                "Region": soca_configuration.get("Region", ""),
                "Misc": soca_configuration.get("Misc", ""),
                "DefaultMetricCollection": True
                if soca_configuration["DefaultMetricCollection"] == "true"
                else False,
                "SolutionMetricsLambda": soca_configuration["SolutionMetricsLambda"],
                "ComputeNodeInstanceProfileArn": soca_configuration[
                    "ComputeNodeInstanceProfileArn"
                ],
            }
            dry_run_launch = can_launch_instance(launch_parameters)
            if dry_run_launch is True:
                launch_template = dcv_cloudformation_builder.main(**launch_parameters)
                if launch_template["success"] is True:
                    cfn_stack_name = str(
                        launch_parameters["cluster_id"]
                        + "-"
                        + launch_parameters["session_name"]
                        + "-"
                        + launch_parameters["user"]
                    )
                    cfn_stack_tags = [
                        {
                            "Key": "soca:JobName",
                            "Value": str(launch_parameters["session_name"]),
                        },
                        {"Key": "soca:JobOwner", "Value": user},
                        {"Key": "soca:JobProject", "Value": "desktop"},
                        {
                            "Key": "soca:ClusterId",
                            "Value": str(launch_parameters["cluster_id"]),
                        },
                        {"Key": "soca:NodeType", "Value": "dcv"},
                        {"Key": "soca:DCVSystem", "Value": "windows"},
                    ]
                    try:
                        client_cfn.create_stack(
                            StackName=cfn_stack_name,
                            TemplateBody=launch_template["output"],
                            Tags=cfn_stack_tags,
                        )
                    except Exception as e:
                        logger.error(
                            f"Error while trying to provision {cfn_stack_name} due to {e}"
                        )
                        return errors.all_errors(
                            "DCV_LAUNCH_ERROR",
                            f"Error while trying to provision {cfn_stack_name} due to {e}",
                        )
                else:
                    return errors.all_errors(
                        "DCV_LAUNCH_ERROR", f"{launch_template['output']}"
                    )
            else:
                return errors.all_errors(
                    "DCV_LAUNCH_ERROR", f" Dry Run error: {dry_run_launch}"
                )

            new_session = WindowsDCVSessions(
                user=user,
                session_number=args["session_number"],
                session_name=session_name,
                session_state="pending",
                session_host_private_dns=False,
                session_host_private_ip=False,
                session_instance_type=instance_type,
                dcv_authentication_token=None,
                session_local_admin_password=session_local_admin_password,
                session_id="console",
                tag_uuid=session_uuid,
                session_token=str(uuid.uuid4()),
                is_active=True,
                support_hibernation=args["hibernate"],
                created_on=datetime.utcnow(),
                schedule_monday_start=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_tuesday_start=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_wednesday_start=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_thursday_start=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_friday_start=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_saturday_start=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE[
                    "weekend"
                ]["start"],
                schedule_sunday_start=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE[
                    "weekend"
                ]["start"],
                schedule_monday_stop=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_tuesday_stop=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_wednesday_stop=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_thursday_stop=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_friday_stop=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_saturday_stop=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE[
                    "weekend"
                ]["stop"],
                schedule_sunday_stop=config.Config.DCV_WINDOWS_DEFAULT_SCHEDULE[
                    "weekend"
                ]["stop"],
            )
            db.session.add(new_session)
            db.session.commit()
            return {
                "success": True,
                "message": f"Session {session_name} with ID {args['session_number']} started successfully.",
            }, 200
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logger.error(exc_type, fname, exc_tb.tb_lineno)
            return errors.all_errors(type(err).__name__, err)
