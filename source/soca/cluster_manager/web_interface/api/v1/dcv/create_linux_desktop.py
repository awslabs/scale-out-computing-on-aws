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
import logging
from datetime import datetime, timezone
from utils.aws.ssm_parameter_store import SocaConfig
from decorators import private_api
from flask import request
import re
import uuid
import sys
import os
from botocore.exceptions import ClientError
from models import db, LinuxDCVSessions, WindowsDCVSessions, AmiList
import dcv_cloudformation_builder
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from jinja2 import Environment, select_autoescape, FileSystemLoader
import pathlib
import base64
import remote_desktop_common
import stat

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_cfn = utils_boto3.get_boto(service_name="cloudformation").message


def get_arch_for_instance_type(instancetype: str) -> str:
    _found_arch = None
    _resp = client_ec2.describe_instance_types(InstanceTypes=[instancetype])
    _instance_info = _resp.get("InstanceTypes", {})
    for _i in _instance_info:
        _instance_name = _i.get("InstanceType", None)
        # This shouldn't happen with an exact-match search
        if _instance_name != instancetype:
            continue

        _proc_info = _i.get("ProcessorInfo", {})
        if _proc_info:
            _arch = sorted(_proc_info.get("SupportedArchitectures", []))
            _found_arch = _arch[0]

    return _found_arch


class CreateLinuxDesktop(Resource):
    @private_api
    def post(self, session_number):
        """
        Create a new DCV desktop session (Linux)
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
        logger.info(f"Received parameter for new Linux DCV session: {args}")

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

        # sanitize session_name
        if args["session_name"] is None:
            session_name = f"LinuxDesktop{_session_number}"
        else:
            session_name = re.sub(r"\W+", "", args["session_name"])[:255]
            if session_name == "":
                # handle case when session name specified by user only contains invalid char
                session_name = f"LinuxDesktop{_session_number}"

        session_name = re.sub(
            pattern=r"[-_=]+", repl="", string=str(session_name)[:32]
        )[:32]
        logger.debug(f"Session name {session_name}")

        if not args["subnet_id"]:
            args["subnet_id"] = False

        try:
            user = request.headers.get("X-SOCA-USER")
            if user is None:
                return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

            if not args["hibernate"]:
                args["hibernate"] = False
            else:
                _check_hibernate = SocaCastEngine(args["hibernate"]).cast_as(
                    expected_type=bool
                )
                if _check_hibernate.success:
                    args["hibernate"] = _check_hibernate.message
                else:
                    args["hibernate"] = None

            if args["hibernate"] is None:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_number,
                    session_owner=user,
                    helper=f"hibernate must be either true or false, detected {args['hibernate']}",
                ).as_flask()

            if args["instance_type"] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(parameter="instance_type").as_flask()
            else:
                instance_type = args["instance_type"]

            args["disk_size"] = (
                40
                if args["disk_size"] is None
                else SocaCastEngine(args["disk_size"])
                .cast_as(expected_type=int)
                .message
            )
            if args["disk_size"] is None:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_number,
                    session_owner=user,
                    helper="disk_size must be set and at least 40",
                ).as_flask()

            if _session_number > int(config.Config.DCV_LINUX_SESSION_COUNT):
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_number,
                    session_owner=user,
                    helper=f"session_number {_session_number} is greater than the max number of session allowed ({config.Config.DCV_LINUX_SESSION_COUNT})",
                ).as_flask()

            session_uuid = str(uuid.uuid4())

            _instance_architecture = get_arch_for_instance_type(
                instancetype=instance_type
            )

            instance_profile = (
                SocaConfig(key="/configuration/ComputeNodeInstanceProfileArn")
                .get_value()
                .message
            )
            security_group_id = (
                SocaConfig(key="/configuration/ComputeNodeSecurityGroup")
                .get_value()
                .message
            )

            if (
                remote_desktop_common.session_already_exist(
                    os="linux", session_number=_session_number
                )
                is True
            ):
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_number,
                    session_owner=user,
                    helper=f"Session Number {_session_number} is already used by an active desktop. Terminate it first before being able to use the same number",
                ).as_flask()

            if args.get("instance_ami", None) is None:
                base_os = (
                    SocaConfig(key="/configuration/BaseOS").get_value().get("message")
                )
                image_id = (
                    SocaConfig(key="/configuration/CustomAMIMap")
                    .get_value(return_as=dict)
                    .message.get(_instance_architecture)
                    .get(base_os)
                )
                logger.debug(
                    f"ImageID (AMI) lookup result for {base_os}/{_instance_architecture} - {image_id}"
                )

            else:
                if len(args["instance_ami"].split(",")) != 2:
                    logger.error(f"Invalid format for instance_ami,base_os")
                    return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                        session_number=_session_number,
                        session_owner=user,
                        helper=f"Invalid format for instance_ami,base_os : {args['instance_ami']}",
                    ).as_flask()

                image_id = args["instance_ami"].split(",")[0]
                base_os = args["instance_ami"].split(",")[1]
                if not image_id.startswith("ami-"):
                    return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                        session_number=_session_number,
                        session_owner=user,
                        helper=f"AMI {image_id} does not seems to be valid. Must start with ami-<id>",
                    ).as_flask()
                else:
                    if (
                        remote_desktop_common.validate_ec2_dcv_image(
                            os=base_os, image_id=image_id
                        )
                        is False
                    ):
                        return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                            session_number=_session_number,
                            session_owner=user,
                            helper=f"AMI {image_id} does not seems to be registered on SOCA.",
                        ).as_flask()

            jinja2_env = Environment(
                loader=FileSystemLoader(
                    f"/apps/soca/{os.environ.get('SOCA_CONFIGURATION')}/cluster_node_bootstrap/"
                ),
                autoescape=select_autoescape(
                    enabled_extensions=("j2", "jinja2"),
                    default_for_string=True,
                    default=True,
                ),
            )

            # Retrieve SOCA specific variable from AWS Parameter Store
            _get_soca_parameters = (
                SocaConfig(
                    key=f"/",
                )
                .get_value(return_as=dict)
                .get("message")
            )
            if not _get_soca_parameters:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_number,
                    session_owner=user,
                    helper="Unable to query SSM for this SOCA environment",
                ).as_flask()
            else:
                soca_parameters = _get_soca_parameters

            # Add SOCA job specific variables
            # job/xxx -> Job Specific (JobId, InstanceType, JobProject ...)
            # configuration/xxx -> SOCA environment specific (ClusterName, Base OS, Region ...)
            # system/xxx -> system related information (e.g: packages to install, DCV version, EFA version ...)

            # Add custom bootstrap path specific to current job id
            soca_parameters[
                "/job/BootstrapPath"
            ] = f"/apps/soca/{soca_parameters.get('/configuration/ClusterId')}/cluster_node_bootstrap/logs/dcv_node/{user}/{session_name}/{session_uuid}"

            # add custom dcv parameter
            soca_parameters["/job/NodeType"] = "dcv_node"
            soca_parameters["/dcv/SessionOwner"] = user
            soca_parameters["/dcv/SessionId"] = session_uuid
            soca_parameters["/dcv/SessionName"] = session_name
            soca_parameters[
                "/dcv/AuthTokenVerifier"
            ] = f"https://{SocaConfig(key='/configuration/ControllerPrivateDnsName').get_value().get('message')}:{config.Config.FLASK_PORT}/api/dcv/authenticator"

            # Replace default SOCA wide BaseOs value with job specific
            soca_parameters["/configuration/BaseOS"] = base_os

            logger.debug(f"soca_parameters for DCV User Data: {soca_parameters}")

            # Create User Data
            user_data = jinja2_env.get_template("compute_node/01_user_data.sh.j2").render(
                context=soca_parameters
            )

            # Create bootstrap setup invoked by user data
            # Create directory structure
            _mode = 0o755
            _bootstrap_path = pathlib.Path(soca_parameters.get("/job/BootstrapPath"))
            _bootstrap_path.mkdir(parents=True, exist_ok=True, mode=_mode)

            # If the structure does not exist, Path.mkdir will create all folder with 777 permissions.
            # This code will update all permissions back to 755
            for parent in reversed(_bootstrap_path.parents):
                if parent.exists():
                    os.chmod(parent, _mode)

            # Write rendered template
            # Bootstrap Sequence:
            _bootstrap_sequence = ["02_setup", "03_setup_post_reboot"]
            for _t in _bootstrap_sequence:
                # Render Template
                _bootstrap_setup_template = jinja2_env.get_template(
                    f"compute_node/{_t}.sh.j2"
                ).render(context=soca_parameters)

                # Write rendered template
                with open(
                    f"{soca_parameters.get('/job/BootstrapPath')}/{_t}.sh", "w"
                ) as output_file:
                    output_file.write(_bootstrap_setup_template)
                    os.chmod(f"{soca_parameters.get('/job/BootstrapPath')}/{_t}.sh", stat.S_IRUSR + stat.S_IWUSR)
                logger.debug(
                    f"bootstrap script {soca_parameters.get('/job/BootstrapPath')}/{_t}.sh"
                )

            if args["hibernate"]:
                try:
                    check_hibernation_support = client_ec2.describe_instance_types(
                        InstanceTypes=[instance_type],
                        Filters=[{"Name": "hibernation-supported", "Values": ["true"]}],
                    )
                    logger.debug(
                        f"Checking instance {instance_type} for Hibernation support: {check_hibernation_support}"
                    )
                    if len(check_hibernation_support.get("InstanceTypes", {})) == 0:
                        if config.Config.DCV_FORCE_INSTANCE_HIBERNATE_SUPPORT is True:
                            return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                                session_number=_session_number,
                                session_owner=user,
                                helper=f"Sorry your administrator limited DCV to instances that support hibernation mode",
                            ).as_flask()
                        else:
                            return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                                session_number=_session_number,
                                session_owner=user,
                                helper=f"Sorry you have selected {instance_type} with hibernation support, but this instance type does not support it. Either disable hibernation support or pick a different instance type",
                            ).as_flask()
                except ClientError as e:
                    return SocaError.AWS_API_ERROR(
                        service_name="ec2",
                        helper=f"Error while checking hibernation support of instance {instance_type} because of {e}",
                    ).as_flask()

            launch_parameters = {
                "security_group_id": security_group_id,
                "instance_profile": instance_profile,
                "instance_type": instance_type,
                "soca_private_subnets": SocaConfig(
                    key="/configuration/PrivateSubnets",
                )
                .get_value(return_as=list)
                .get("message"),
                "user_data": base64.b64encode(user_data.encode("utf-8")).decode(
                    "utf-8"
                ),
                "subnet_id": args["subnet_id"],
                "tenancy": args["tenancy"],
                "image_id": image_id,
                "session_name": session_name,
                "session_uuid": session_uuid,
                "base_os": base_os,
                "disk_size": args["disk_size"],
                "volume_type": SocaConfig(key="/configuration/DefaultVolumeType")
                .get_value()
                .message,
                "cluster_id": SocaConfig(key="/configuration/ClusterId")
                .get_value()
                .message,
                "metadata_http_tokens": SocaConfig(
                    key="/configuration/MetadataHttpTokens"
                )
                .get_value()
                .message,
                "hibernate": args["hibernate"],
                "user": user,
                "Version": SocaConfig(key="/configuration/Version")
                .get_value()
                .get("message"),
                "Region": SocaConfig(key="/configuration/Region")
                .get_value()
                .get("message"),
                "DefaultMetricCollection": SocaConfig(
                    key="/configuration/DefaultMetricCollection",
                )
                .get_value(return_as=bool)
                .get("message"),
                "SolutionMetricsLambda": SocaConfig(
                    key="/configuration/SolutionMetricsLambda"
                )
                .get_value()
                .message,
                "ComputeNodeInstanceProfileArn": SocaConfig(
                    key="/configuration/ComputeNodeInstanceProfileArn"
                )
                .get_value()
                .message,
            }
            dry_run_launch = remote_desktop_common.can_launch_instance(
                launch_parameters
            )
            if dry_run_launch.get("success"):
                launch_template = dcv_cloudformation_builder.main(**launch_parameters)
                if launch_template["success"] is True:
                    # user can have - _ or . which are not allowed on CFN (- is allowed but we remove it for consistency)
                    _sanitized_user = re.sub(r"[._-]", "", launch_parameters["user"])
                    cfn_stack_name = f"{launch_parameters['cluster_id']}-{launch_parameters['session_name']}-{_sanitized_user}"
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
                        {"Key": "soca:NodeType", "Value": "dcv_node"},
                        {"Key": "soca:BaseOS", "Value": base_os},
                    ]
                    try:
                        client_cfn.create_stack(
                            StackName=cfn_stack_name,
                            TemplateBody=launch_template["output"],
                            Tags=cfn_stack_tags,
                        )
                    except Exception as e:
                        return SocaError.AWS_API_ERROR(
                            service_name="cloudformation",
                            helper=f"Error while trying to provision {cfn_stack_name} because of {e}",
                        ).as_flask()

                else:
                    return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                        session_number=_session_number,
                        session_owner=user,
                        helper=f"Unable to launch CloudFormation stack because of {launch_template['output']}.",
                    ).as_flask()
            else:
                return SocaError.AWS_API_ERROR(
                    service_name="ec2",
                    helper=f"Dry Run failed because of {dry_run_launch}",
                ).as_flask()

            new_session = LinuxDCVSessions(
                user=user,
                session_number=_session_number,
                session_name=session_name,
                session_state="pending",
                session_host_private_dns=False,
                session_host_private_ip=False,
                session_instance_type=instance_type,
                session_linux_distribution=base_os,
                dcv_authentication_token=None,
                session_id=session_uuid,
                tag_uuid=session_uuid,
                session_token=str(uuid.uuid4()),
                is_active=True,
                support_hibernation=args["hibernate"],
                created_on=datetime.now(timezone.utc),
                schedule_monday_start=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_tuesday_start=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_wednesday_start=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_thursday_start=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_friday_start=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_saturday_start=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekend"
                ]["start"],
                schedule_sunday_start=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekend"
                ]["start"],
                schedule_monday_stop=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_tuesday_stop=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_wednesday_stop=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_thursday_stop=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_friday_stop=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_saturday_stop=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekend"
                ]["stop"],
                schedule_sunday_stop=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekend"
                ]["stop"],
            )
            try:
                db.session.add(new_session)
                db.session.commit()
            except Exception as err:
                logger.error(
                    "Cloudformation stack created but DB error, deleting cloudformation stack"
                )
                try:
                    client_cfn.delete_stack(StackName=cfn_stack_name)
                except Exception as e:
                    return SocaError.AWS_API_ERROR(
                        service_name="cloudformation",
                        helper=f"Unable to delete CloudFormation stack {cfn_stack_name} due to {e}",
                    ).as_flask()

                return SocaError.DB_ERROR(
                    query=new_session,
                    helper=f"Unable to add new Linux desktop db entry due to {err}",
                ).as_flask()

            logger.info(
                f"Session {session_name} with ID {_session_number} started successfully."
            )
            return SocaResponse(success=True, message= f"Session {session_name} with ID {_session_number} started successfully.").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()
