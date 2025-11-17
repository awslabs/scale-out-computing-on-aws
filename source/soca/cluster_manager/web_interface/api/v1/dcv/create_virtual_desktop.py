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
import botocore.exceptions
import config
from flask_restful import Resource, reqparse
import logging
from datetime import datetime, timezone

import json
from utils.aws.ssm_parameter_store import SocaConfig
from decorators import private_api, feature_flag
from flask import request
import re
import uuid
import sys
import os
from botocore.exceptions import ClientError
from models import db, VirtualDesktopSessions
import dcv_cloudformation_builder
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.ec2_helper import create_capacity_dry_run
from utils.aws.odcr_helper import create_capacity_reservation
from utils.aws.cloudformation_helper import SocaCfnClient
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.jinjanizer import SocaJinja2Generator
from helpers.software_stacks import SoftwareStacksHelper
import pathlib
import base64
import remote_desktop_common
import random
import string

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


def clean_user_data(text_to_remove: list, data: str) -> str:
    _ec2_user_data = data
    for _t in text_to_remove:
        _ec2_user_data = re.sub(f"{_t}", "", _ec2_user_data, flags=re.IGNORECASE)

    # Remove leading spaces
    _ec2_user_data = re.sub(r"^[ \t]+", "", _ec2_user_data, flags=re.MULTILINE)

    # Remove lines that start with '#' but not '#!'
    _ec2_user_data = re.sub(r"^(?!#!)#.*\n?", "", _ec2_user_data, flags=re.MULTILINE)

    # Finally remove blank lines
    _ec2_user_data = re.sub(r"^\s*\n", "", _ec2_user_data, flags=re.MULTILINE)

    return _ec2_user_data


class CreateVirtualDesktop(Resource):
    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def post(self):
        """
        Create a new DCV virtual desktop session
        ---
        openapi: 3.1.0
        operationId: createVirtualDesktop
        tags:
          - Virtual Desktops
        summary: Create new virtual desktop session
        description: Provisions a new EC2 instance with DCV for remote desktop access
        parameters:
          - name: X-SOCA-USER
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
            description: SOCA username for authentication
            example: "john.doe"
          - name: X-SOCA-TOKEN
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 256
            description: SOCA authentication token
            example: "abc123token456"
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - instance_type
                  - session_name
                  - software_stack_id
                properties:
                  instance_type:
                    type: string
                    pattern: '^[a-z0-9]+\.[a-z0-9]+$'
                    description: EC2 instance type for the virtual desktop
                    example: "m5.large"
                  disk_size:
                    type: string
                    pattern: '^[0-9]+$'
                    description: EBS root volume size in GB
                    example: "50"
                  session_name:
                    type: string
                    minLength: 1
                    maxLength: 32
                    pattern: '^[a-zA-Z0-9]+$'
                    description: Name for the DCV session (alphanumeric only, max 32 chars)
                    example: "MyDesktop01"
                  software_stack_id:
                    type: string
                    pattern: '^[0-9]+$'
                    description: ID of the software stack to use
                    example: "1"
                  subnet_id:
                    type: string
                    pattern: '^subnet-[a-f0-9]{8,17}$'
                    description: Subnet ID where to launch the EC2 instance
                    example: "subnet-12345678"
                  project:
                    type: string
                    minLength: 1
                    maxLength: 100
                    pattern: '^[a-zA-Z0-9._-]+$'
                    description: Project to map the VDI desktop to
                    example: "myproject"
                  hibernate:
                    type: string
                    enum: ["true", "false"]
                    description: Enable hibernation support
                    example: "false"
                  tenancy:
                    type: string
                    enum: ["default", "dedicated"]
                    description: EC2 tenancy type
                    example: "default"
                  session_type:
                    type: string
                    enum: ["default", "console", "virtual"]
                    description: Type of DCV session
                    example: "default"
        responses:
          '200':
            description: Virtual desktop session creation initiated successfully
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: string
                      example: "Session MyDesktop01 started successfully."
          '400':
            description: Invalid request parameters
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 400
                    message:
                      type: string
                      example: "Missing required parameter: instance_type"
          '401':
            description: Authentication failed
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 401
                    message:
                      type: string
                      example: "Invalid authentication credentials"
          '403':
            description: Feature not enabled or insufficient permissions
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 403
                    message:
                      type: string
                      example: "Virtual desktops feature is not enabled"
          '500':
            description: Internal server error during session creation
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 500
                    message:
                      type: string
                      example: "Failed to create virtual desktop session"
        """

        parser = reqparse.RequestParser()
        parser.add_argument("instance_type", type=str, location="form")
        parser.add_argument("disk_size", type=str, location="form")
        parser.add_argument("session_name", type=str, location="form")
        parser.add_argument("project", type=str, location="form")
        parser.add_argument("software_stack_id", type=str, location="form")
        parser.add_argument("subnet_id", type=str, location="form")
        parser.add_argument("hibernate", type=str, location="form")
        parser.add_argument("tenancy", type=str, location="form")
        parser.add_argument("session_type", type=str, location="form")
        args = parser.parse_args()

        _session_uuid = str(uuid.uuid4())

        logger.info(
            f"Received parameter for new DCV session request: {args}, setting up session uuid {_session_uuid}"
        )
        try:
            _user = request.headers.get("X-SOCA-USER")
            if _user is None:
                return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

            # sanitize session_name
            if args["session_name"] is None:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helpers="session_name cannot be null",
                ).as_flask()

            else:
                _session_name = re.sub(
                    pattern=r"[^a-zA-Z0-9]",
                    repl="",
                    string=str(args["session_name"])[:32],
                )[:32]

            if args["project"] is None:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helpers="project cannot be null",
                ).as_flask()

            logger.debug(f"Session name {_session_name}")

            # Retrieve SOCA specific variable from AWS Parameter Store
            _get_soca_parameters = (
                SocaConfig(
                    key="/",
                )
                .get_value(return_as=dict)
                .get("message")
            )

            if not _get_soca_parameters:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_name,
                    session_owner=_user,
                    helper="Unable to query SSM for this SOCA environment",
                ).as_flask()
            else:
                soca_parameters = _get_soca_parameters

            _stack_name = f"{_get_soca_parameters.get('/configuration/ClusterId')}-{_session_name}-{_user}"
            logger.debug(f"VDI will be provisioned by {_stack_name=}")

            # Validate input
            if args["instance_type"] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="instance_type"
                ).as_flask()
            else:
                instance_type = args["instance_type"]

            if args["session_type"] not in ["default", "console", "virtual"]:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"session_type must be default, console or virtual. Detected {args['session_type']}",
                ).as_flask()

            if args["session_type"] not in config.Config.DCV_ALLOWED_SESSION_TYPES:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"session_type must be one of {config.Config.DCV_ALLOWED_SESSION_TYPES}. Detected {args['session_type']}",
                ).as_flask()

            if args["software_stack_id"] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="software_stack_id"
                ).as_flask()
            else:
                _software_stack_id = SocaCastEngine(
                    data=args["software_stack_id"]
                ).cast_as(expected_type=int)
                if _software_stack_id.get("success"):
                    _get_software_stack = SoftwareStacksHelper(
                        software_stack_id=_software_stack_id.get("message"),
                        is_active=True,
                    )

                else:
                    return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                        session_number=_session_uuid,
                        session_owner=_user,
                        helper=f"software_stack_id does not seems to be a valid integer: {_software_stack_id.message}",
                    ).as_flask()

            # Validate Software Stack Information
            _get_software_stack_info = _get_software_stack.get_stack_info()
            if _get_software_stack_info.get("success") is True:
                _software_stack_info = _get_software_stack_info.get("message")
            else:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"{_get_software_stack_info.get('message')}",
                ).as_flask()

            _check_disk_size = SocaCastEngine(args["disk_size"]).cast_as(
                expected_type=int
            )
            if _check_disk_size.get("success") is True:
                args["disk_size"] = _check_disk_size.get("message")
            else:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"disk_size error: {_check_disk_size.message} ",
                ).as_flask()

            if not args["hibernate"]:
                args["hibernate"] = False
            else:
                _check_hibernate = SocaCastEngine(args["hibernate"]).cast_as(
                    expected_type=bool
                )
                if _check_hibernate.get("success"):
                    args["hibernate"] = _check_hibernate.get("message")
                else:
                    args["hibernate"] = False

            if not args["subnet_id"]:
                logger.info("No subnet_id specified, default to 'auto'")
                args["subnet_id"] = "auto"

            # Note: if subnet_id is set to `auto`, SOCA will cycle trough the list until capacity is available
            _selected_subnet = None
            _soca_private_subnets = (
                SocaCastEngine(
                    _get_soca_parameters.get("/configuration/PrivateSubnets")
                )
                .cast_as(expected_type=list)
                .get("message")
            )

            if (
                SocaConfig(key="/configuration/FeatureFlags/EnableCapacityReservation")
                .get_value(return_as=bool)
                .get("message")
                is False
            ):
                logger.info(
                    "/configuration/FeatureFlags/EnableCapacityReservation flag is set to False, SOCA will NOT verify capacity availability"
                )

                if args["subnet_id"] == "auto":
                    logger.info(
                        f"subnet_id is 'auto' and capacity reservation check is not enabled, SOCA will pick a random subnet from {_soca_private_subnets}"
                    )
                    _selected_subnet = random.choice(_soca_private_subnets)
                else:
                    _selected_subnet = args["subnet_id"]

                logger.info(f"Selected Subnet: {_selected_subnet}")

            else:
                logger.info(
                    "/configuration/FeatureFlags/EnableCapacityReservation flag is set to True, SOCA will verify capacity availability"
                )
                if args["subnet_id"] != "auto":
                    logger.info(
                        f"Specific subnet_id has been specified {args.get('subnet_id')}, checking if capacity is available"
                    )
                    _selected_subnet = args.get("subnet_id")
                    logger.info(
                        f"Probing capacity availability for {args.get('instance_type')}, instance_count=1, subnet_ids={_selected_subnet}, {_software_stack_info.get('ami_id')}"
                    )
                    _request_on_demand_capacity_reservation = (
                        create_capacity_reservation(
                            desired_capacity=1,
                            capacity_reservation_name=_stack_name,
                            instance_type=args.get("instance_type"),
                            subnet_id=_selected_subnet,
                            instance_ami=_software_stack_info.get("ami_id"),
                            tenancy=args.get("tenancy"),
                        )
                    )
                    if _request_on_demand_capacity_reservation.get("success") is True:
                        logger.info(
                            f"ODCR succeeded, capacity is available in subnet_id {_selected_subnet}: {_request_on_demand_capacity_reservation.get('message')}"
                        )

                    else:
                        return SocaError.GENERIC_ERROR(
                            helper=f"Unable to create capacity reservation due to {_request_on_demand_capacity_reservation.message}"
                        ).as_flask()

                else:
                    logger.info(
                        "subnet_id is 'auto'. SOCA will try pick a random subnet and cycle through others subnet id until capacity is available"
                    )
                    random.shuffle(_soca_private_subnets)
                    for _subnet_id in _soca_private_subnets:
                        logger.info(
                            f"Requesting ODCR for {args.get('instance_type')}, instance_count=1, capacity_reservation_name={_stack_name}, subnet_id={[_subnet_id]}, {_software_stack_info.get('ami_id')}"
                        )
                        _request_on_demand_capacity_reservation = (
                            create_capacity_reservation(
                                desired_capacity=1,
                                instance_type=args.get("instance_type"),
                                capacity_reservation_name=_stack_name,
                                subnet_id=_subnet_id,
                                instance_ami=_software_stack_info.get("ami_id"),
                                tenancy=args.get("tenancy"),
                            )
                        )
                        if (
                            _request_on_demand_capacity_reservation.get("success")
                            is True
                        ):
                            _selected_subnet = _subnet_id
                            logger.info(
                                f"ODCR succeeded, capacity is available in subnet_id {_selected_subnet} : {_request_on_demand_capacity_reservation.get("message")}"
                            )
                            break
                        else:
                            logger.warning(
                                f"Unable to create capacity reservation due to {_request_on_demand_capacity_reservation.message}, trying the next subnet in list"
                            )

            if _selected_subnet is None:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to find available capacity in all subnets provided {_soca_private_subnets}. Try again later."
                ).as_flask()

            # Validate Software Stack Permissions
            _get_software_stack_permissions = _get_software_stack.validate(
                instance_type=instance_type,
                root_size=args["disk_size"],
                subnet_id=_subnet_id,
                session_owner=_user,
                project=args.get("project"),
            )

            if _get_software_stack_permissions.get("success") is False:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_name,
                    session_owner=_user,
                    helper=_get_software_stack_permissions.get("message"),
                ).as_flask()

            # Validate if user does not have hit maximum number of desktop
            if (
                remote_desktop_common.max_concurrent_desktop_limit_reached(
                    os_family=_software_stack_info.get("os_family"), session_owner=_user
                )
                is True
            ):
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_name,
                    session_owner=_user,
                    helper=f"Max number of Linux or Windows session already reached for this user (Linux: Max {config.Config.DCV_LINUX_SESSION_COUNT}, Windows: max {config.Config.DCV_WINDOWS_SESSION_COUNT})",
                ).as_flask()

            # Configure Session Type
            if args["session_type"] == "default":
                logger.info("Detected default session type, setting up automatically)")
                if _software_stack_info.get("os_family") == "windows":
                    _session_type = "console"
                else:
                    # Ubuntu does not work well with virtual session, default to console
                    # GPU instance also use console session by default
                    # Also edit cluster_node_bootstrap/templates/linux/dcv/dcv_server.sh.j2 if you modify this list
                    if _software_stack_info.get("ami_base_os") in [
                        "ubuntu2204",
                        "ubuntu2404",
                    ]:
                        _session_type = "console"
                    elif args["instance_type"].startswith("p") or args[
                        "instance_type"
                    ].startswith("g"):
                        # GPU use console by default
                        _session_type = "console"
                    else:
                        _session_type = "virtual"
            else:
                _session_type = args["session_type"]

            logger.info(f"Detected session type: {_session_type}")
            if (
                _session_type == "virtual"
                and _software_stack_info.get("os_family") == "windows"
            ):
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_name,
                    session_owner=_user,
                    helper=f"Windows only support console or default session type, detected {args['session_type']}",
                ).as_flask()

            # Add SOCA job specific variables
            # job/xxx -> Job Specific (JobId, InstanceType, JobProject ...)
            # configuration/xxx -> SOCA environment specific (ClusterName, Base OS, Region ...)
            # system/xxx -> system related information (e.g: packages to install, DCV version, EFA version ...)

            # Create bootstrap UUID for this job
            _bootstrap_uuid = str(uuid.uuid4())

            # Add custom bootstrap path specific to current job id
            soca_parameters["/job/BootstrapPath"] = (
                f"/apps/soca/{soca_parameters.get('/configuration/ClusterId')}/shared/logs/bootstrap/dcv_node/{_user}/{_session_name}/{_session_uuid}/{_bootstrap_uuid}"
            )

            _bootstrap_s3_location_folder = f"{soca_parameters.get('/configuration/ClusterId')}/config/do_not_delete/bootstrap/dcv_node/{_bootstrap_uuid}/{_session_uuid}"

            soca_parameters["/job/BootstrapScriptsS3Location"] = (
                f"s3://{soca_parameters.get('/configuration/S3Bucket')}/{_bootstrap_s3_location_folder}/"
            )

            # add custom dcv parameter
            soca_parameters["/job/NodeType"] = "dcv_node"
            soca_parameters["/dcv/SessionOwner"] = _user
            soca_parameters["/dcv/JobProject"] = args.get("project")
            soca_parameters["/dcv/SessionType"] = _session_type
            if _software_stack_info.get("os_family") == "windows":
                soca_parameters["/dcv/SessionId"] = "console"
            else:
                soca_parameters["/dcv/SessionId"] = _session_uuid

            soca_parameters["/dcv/SessionName"] = _session_name
            soca_parameters["/dcv/AuthTokenVerifier"] = (
                f"https://{SocaConfig(key='/configuration/ControllerPrivateDnsName').get_value().get('message')}:{config.Config.FLASK_PORT}/api/dcv/authenticator"
            )
            if _software_stack_info.get("os_family") == "windows":
                _session_local_admin_password = "".join(
                    random.sample(
                        random.choices(string.digits, k=3)
                        + random.choices(string.ascii_uppercase, k=3)
                        + random.choices(string.ascii_lowercase, k=3),
                        9,
                    )
                )

                soca_parameters["/dcv/LocalAdminPassword"] = (
                    _session_local_admin_password
                )
                soca_parameters["/dcv/WindowsAutoLogon"] = (
                    "true" if config.Config.DCV_WINDOWS_AUTOLOGON is True else "false"
                )
            else:
                _session_local_admin_password = None

            # Replace default SOCA wide BaseOs value with job specific
            soca_parameters["/configuration/BaseOS"] = _software_stack_info.get(
                "ami_base_os"
            )

            logger.debug(f"soca_parameters for DCV User Data: {soca_parameters}")

            # Create User Data
            if _software_stack_info.get("os_family") == "windows":
                _user_data_template = "windows_virtual_desktop/01_user_data.ps1.j2"
            else:
                _user_data_template = "compute_node/01_user_data.sh.j2"

            _generate_user_data = SocaJinja2Generator(
                get_template=_user_data_template,
                template_dirs=[
                    f"/opt/soca/{os.environ.get('SOCA_CLUSTER_ID')}/cluster_node_bootstrap/"
                ],
                variables=soca_parameters,
            ).to_stdout(autocast_values=True)

            if _generate_user_data.get("success") is False:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_name,
                    session_owner=_user,
                    helper=f"Unable to generate UserData Jinja2 template because of {_generate_user_data.get('message')}",
                ).as_flask()
            else:
                user_data = clean_user_data(
                    text_to_remove=[
                        "# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.",
                        "# SPDX-License-Identifier: Apache-2.0",
                    ],
                    data=_generate_user_data.get("message"),
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

            # Bootstrap Sequence: Generate template and upload them to S3
            if _software_stack_info.get("os_family") == "windows":
                _templates_to_render = [
                    "windows_virtual_desktop/02_setup.ps1",
                    "windows_virtual_desktop/03_setup_post_reboot.ps1",
                ]
            else:
                _templates_to_render = [
                    "templates/linux/system_packages/install_required_packages.sh",
                    "templates/linux/filesystems_automount.sh",
                    "compute_node/02_setup.sh",
                    "compute_node/03_setup_post_reboot.sh",
                    "compute_node/04_setup_user_customization.sh",
                ]

            for _t in _templates_to_render:
                # Render Template
                _render_bootstrap_setup_template = SocaJinja2Generator(
                    get_template=f"{_t}.j2",
                    template_dirs=[
                        f"/opt/soca/{os.environ.get('SOCA_CLUSTER_ID')}/cluster_node_bootstrap/"
                    ],
                    variables=soca_parameters,
                ).to_s3(
                    bucket_name=soca_parameters.get("/configuration/S3Bucket"),
                    key=f"{_bootstrap_s3_location_folder}/{_t.split('/')[-1]}",
                    autocast_values=True,
                )

                if _render_bootstrap_setup_template.get("success") is False:
                    return SocaResponse(
                        success=False,
                        message=f"Unable to generate {_t}.j2 Jinja2 template because of {_render_bootstrap_setup_template.get('message')}",
                    ).as_flask()

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
                                session_number=args["session_name"],
                                session_owner=_user,
                                helper=f"Sorry your administrator limited DCV to instances that support hibernation mode",
                            ).as_flask()
                        else:
                            return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                                session_number=args["session_name"],
                                session_owner=_user,
                                helper=f"Sorry you have selected {instance_type} with hibernation support, but this instance type does not support it. Either disable hibernation support or pick a different instance type",
                            ).as_flask()
                except ClientError as e:
                    return SocaError.AWS_API_ERROR(
                        service_name="ec2",
                        helper=f"Error while checking hibernation support of instance {instance_type} because of {e}",
                    ).as_flask()

            launch_parameters = {
                "security_group_id": _get_soca_parameters.get(
                    "/configuration/ComputeNodeSecurityGroup"
                ),
                "instance_profile": _get_soca_parameters.get(
                    "/configuration/ComputeNodeInstanceProfileArn"
                ),
                "instance_type": instance_type,
                "subnet_id": _selected_subnet,
                "tenancy": args.get("tenancy"),
                "project": args.get("project"),
                "image_id": _software_stack_info.get("ami_id"),
                "session_name": _session_name,
                "session_uuid": _session_uuid,
                "base_os": _software_stack_info.get("ami_base_os"),
                "disk_size": args["disk_size"],
                "volume_type": _get_soca_parameters.get(
                    "/configuration/DefaultVolumeType"
                ),
                "cluster_id": _get_soca_parameters.get("/configuration/ClusterId"),
                "metadata_http_tokens": _get_soca_parameters.get(
                    "/configuration/MetadataHttpTokens"
                ),
                "hibernate": args["hibernate"],
                "user": _user,
                "Version": _get_soca_parameters.get("/configuration/Version"),
                "Region": _get_soca_parameters.get("/configuration/Region"),
                "DefaultMetricCollection": SocaCastEngine(
                    _get_soca_parameters.get("/configuration/DefaultMetricCollection")
                )
                .cast_as(expected_type=bool)
                .get("message"),
                "SolutionMetricsLambda": _get_soca_parameters.get(
                    "/configuration/SolutionMetricsLambda"
                ),
                "ComputeNodeInstanceProfileArn": _get_soca_parameters.get(
                    "/configuration/ComputeNodeInstanceProfileArn"
                ),
                "user_data": base64.b64encode(user_data.encode("utf-8")).decode(
                    "utf-8"
                ),
                "custom_tags": {},
            }

            # Get custom tags if specified
            logger.info("Checking if custom tags exist")
            _tags_allowed = SocaConfig(
                key="/configuration/FeatureFlags/VirtualDesktops/AllowCustomTags"
            ).get_value(return_as=bool)
            if _tags_allowed.get("success") is True:
                if _tags_allowed.get("message") is True:
                    _get_tags = SocaConfig(key="/configuration/CustomTags/").get_value(
                        allow_unknown_key=True
                    )
                    if _get_tags.get("success") is True:
                        _tag_dict = SocaCastEngine(
                            data=_get_tags.get("message")
                        ).autocast(preserve_key_name=True)
                        if _tag_dict.get("success") is True:
                            logger.info(f"Adding new tags: {_tag_dict.get('message')}")
                            launch_parameters["custom_tags"] = _tag_dict.get("message")
                        else:
                            logger.error(
                                f"Unable to autocast custom tags {_tag_dict=} "
                            )
                    else:
                        logger.warning(
                            "/configuration/CustomTags/ does not exist in this environment, ignoring ..."
                        )
                else:
                    logger.warning(
                        f"Unable to determine if tags are allowed because of: {_tags_allowed=} "
                    )

            else:
                logger.warning(
                    "Custom tags are not allowed. AllowCustomTagsVDI is set to false"
                )

            logger.debug(f"Launch parameters for DCV: {launch_parameters}")
            dry_run_launch = create_capacity_dry_run(
                disk_size=launch_parameters.get("disk_size"),
                instance_type=launch_parameters.get("instance_type"),
                image_id=launch_parameters.get("image_id"),
                security_group_id=[launch_parameters.get("security_group_id")],
                subnet_id=launch_parameters.get("subnet_id"),
                user_data=launch_parameters.get("user_data"),
                instance_profile=launch_parameters.get("instance_profile"),
                custom_tags=launch_parameters.get("custom_tags"),
                volume_type=launch_parameters.get("volume_type"),
                hibernate=launch_parameters.get("hibernate"),
                metadata_http_tokens=launch_parameters.get("metadata_http_tokens"),
                key_name=_get_soca_parameters.get("/configuration/SSHKeyPair"),
                desired_capacity=1,
            )
            logger.info(f"Dry Run Result: {dry_run_launch}")

            if dry_run_launch.get("success"):
                launch_template = dcv_cloudformation_builder.main(**launch_parameters)
                if launch_template.get("success") is True:
                    _cfn_stack_name = re.sub(
                        r"[^a-zA-Z0-9\-]",
                        "",
                        _stack_name,
                    )

                    _cfn_stack_tags = [
                        {
                            "Key": "soca:JobName",
                            "Value": str(launch_parameters["session_name"]),
                        },
                        {"Key": "soca:JobOwner", "Value": _user},
                        {"Key": "soca:JobProject", "Value": "desktop"},
                        {
                            "Key": "soca:ClusterId",
                            "Value": str(launch_parameters["cluster_id"]),
                        },
                        {"Key": "soca:JobProject", "Value": args.get("project")},
                        {"Key": "soca:NodeType", "Value": "dcv_node"},
                        {
                            "Key": "soca:BaseOS",
                            "Value": _software_stack_info.get("ami_base_os"),
                        },
                    ]

                    _create_stack = SocaCfnClient(
                        stack_name=_cfn_stack_name
                    ).create_stack(
                        template_body=launch_template.get("message"),
                        tags=_cfn_stack_tags,
                    )
                    if _create_stack.get("success") is True:
                        logger.info(
                            f"CloudFormation stack {_cfn_stack_name} successfully created"
                        )

                    else:
                        return SocaError.GENERIC_ERROR(
                            helper=f"{_create_stack.get('message')}"
                        ).as_flask()
            else:
                return SocaError.AWS_API_ERROR(
                    service_name="ec2",
                    helper=f"{dry_run_launch.get('message')}",
                ).as_flask()

            logger.info(
                "New Virtual Desktop CloudFormation request successful, adding session on the database"
            )

            # Adding Software Stack thumbnail, maybe one day we will add a live screenshot from DCV
            _session_thumbnail = _software_stack_info.get("thumbnail")

            new_session = VirtualDesktopSessions(
                is_active=True,
                created_on=datetime.now(timezone.utc),
                deactivated_on=None,
                session_owner=_user,
                session_uuid=_session_uuid,
                session_project=args.get("project"),
                session_id=soca_parameters["/dcv/SessionId"],
                session_name=_session_name,
                stack_name=_cfn_stack_name,
                session_local_admin_password=_session_local_admin_password,
                authentication_token=None,
                session_token=str(uuid.uuid4()),
                session_thumbnail=_session_thumbnail,
                schedule=json.dumps(config.Config.DCV_DEFAULT_SCHEDULE),
                session_state="pending",
                session_state_latest_change_time=datetime.now(timezone.utc),
                instance_private_dns=None,
                instance_private_ip=None,
                instance_id=None,
                instance_type=args["instance_type"],
                instance_base_os=_software_stack_info.get("ami_base_os"),
                os_family=_software_stack_info.get("os_family"),
                support_hibernation=args["hibernate"],
                software_stack_id=_software_stack_id.message,
                session_type=_session_type,
            )

            try:
                db.session.add(new_session)
                db.session.commit()
            except Exception as err:
                logger.error(
                    "Cloudformation stack created but DB error, deleting cloudformation stack"
                )
                _delete_stack = SocaCfnClient(stack_name=_cfn_stack_name).delete_stack()
                if _delete_stack.get("success") is False:
                    return SocaError.AWS_API_ERROR(
                        service_name="cloudformation",
                        helper=f"Unable to delete CloudFormation stack {_cfn_stack_name} due to {_delete_stack.get("success")}",
                    ).as_flask()
                db.session.rollback()
                return SocaError.DB_ERROR(
                    query=new_session,
                    helper=f"Unable to add desktop db entry due to {err}",
                ).as_flask()

            logger.info(
                f"Session {_session_name} with UUID {_session_uuid} started successfully."
            )

            return SocaResponse(
                success=True,
                message=f"Session {_session_name} started successfully.",
            ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()
