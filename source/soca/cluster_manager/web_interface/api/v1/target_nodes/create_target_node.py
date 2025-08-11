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
from models import db, TargetNodeSessions, SoftwareStacks
import target_nodes_cloudformation_builder
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.odcr_helper import (
    create_capacity_reservation_vdi,
    cancel_capacity_reservation,
)
import remote_desktop_common
import utils.aws.cloudformation_helper as cloudformation_helper
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.jinjanizer import SocaJinja2Renderer
from helpers.target_node_software_stacks import TargetNodeSoftwareStacksHelper
import pathlib
import base64
import random
import string
from pathlib import Path
import base64
import re

from werkzeug.debug.repr import helper

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


def parse_user_data_variables(s: str) -> dict:
    pair_pattern = r"\s*([^=,\s]+)\s*=\s*([^,]*)\s*"

    matches = list(re.finditer(pair_pattern, s))
    if not matches:
        return {}

    # Join matched substrings exactly as they appeared (preserving spacing)
    matched_str = ",".join(match.group(0).strip() for match in matches)
    normalized_input = s.strip()

    if matched_str != normalized_input:
        raise ValueError(f"Invalid input format: unmatched portion in '{s}'")

    result = {}
    for match in matches:
        key, value = match.groups()
        result[key] = value
    return result


def get_user_pubkeys(username: str):
    _ssh_dir = Path(config.Config.USER_HOME) / username / ".ssh"
    _public_keys = []
    if not _ssh_dir.exists():
        logger.error(
            f"Unable to retrieve pubkey for {username=} because {_ssh_dir} does not exist."
        )
        return False

    _pub_files = list(_ssh_dir.glob("*.pub"))
    if not _pub_files:
        logger.error(f"No pubkey found for  {username=} under {_ssh_dir}")
        return False

    for pub_file in _pub_files:
        try:
            with pub_file.open("r") as f:
                content = f.read().strip()
                _public_keys.append(content)
        except Exception as e:
            logger.warning(f"Error reading {pub_file.name}: {e}")

    return _public_keys


class CreateTargetNode(Resource):
    @private_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def post(self):
        """
        Create a new target node session
        ---
        openapi: 3.1.0
        operationId: createTargetNodeSession
        tags:
          - Target Nodes
        summary: Create a new target node session for CAE simulations
        description: Creates a new target node session with specified configuration including instance type, software stack, and networking parameters
        parameters:
          - name: X-SOCA-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: john.doe
          - name: X-SOCA-TOKEN
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: Authentication token for the SOCA user
            example: abc123token
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
                  - project
                properties:
                  instance_type:
                    type: string
                    pattern: '^[a-z0-9]+\.[a-z0-9]+$'
                    description: AWS EC2 instance type for the target node
                    example: m5.large
                  session_name:
                    type: string
                    pattern: '^[a-zA-Z0-9-]{1,32}$'
                    maxLength: 32
                    description: Name for the target node session (max 32 chars, alphanumeric and hyphens only)
                    example: my-simulation-session
                  software_stack_id:
                    type: string
                    pattern: '^[0-9]+$'
                    description: ID of the software stack to use
                    example: "123"
                  project:
                    type: string
                    minLength: 1
                    description: Project name for the target node session
                    example: default
                  disk_size:
                    type: string
                    pattern: '^[0-9]+$'
                    description: Root disk size in GB
                    example: "100"
                  subnet_id:
                    type: string
                    pattern: '^subnet-[a-f0-9]{8,17}$'
                    description: AWS subnet ID (random private subnet used if not specified)
                    example: subnet-12345678
                  tenancy:
                    type: string
                    enum: [default, dedicated, host]
                    description: EC2 tenancy type
                    example: default
        responses:
          '200':
            description: Target node session created successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: string
                      example: Session my-simulation-session started successfully.
          '400':
            description: Bad request - missing or invalid parameters
          '401':
            description: Authentication required
          '403':
            description: Forbidden - user quota exceeded or access denied
          '500':
            description: Internal server error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("instance_type", type=str, location="form")
        parser.add_argument("disk_size", type=str, location="form")
        parser.add_argument("session_name", type=str, location="form")
        parser.add_argument("software_stack_id", type=str, location="form")
        parser.add_argument("subnet_id", type=str, location="form")
        parser.add_argument("tenancy", type=str, location="form")
        parser.add_argument("project", type=str, location="form")
        args = parser.parse_args()

        _session_uuid = str(uuid.uuid4())

        logger.info(
            f"Received parameter for new target node session request: {args}, setting up session uuid {_session_uuid}"
        )
        try:
            _user = request.headers.get("X-SOCA-USER")
            if _user is None:
                return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

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

            if args["session_name"] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    helper="session_name",
                ).as_flask()
            else:
                _session_name = re.sub(
                    pattern=r"[^a-zA-Z0-9]",
                    repl="",
                    string=str(args["session_name"])[:32],
                )[:32]

            logger.debug(f"Session name {_session_name}")

            # Validate input
            if args["instance_type"] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="instance_type"
                ).as_flask()
            else:
                instance_type = args["instance_type"]

            if args.get("project") is None:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="project"
                ).as_flask()

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

            _max_session_count = config.Config.TARGET_NODE_SESSION_COUNT
            logger.debug(
                f"Max Target Node Session Count per user: {_max_session_count}"
            )

            _find_active_target_nodes_sessions = TargetNodeSessions.query.filter(
                TargetNodeSessions.is_active == True,
                TargetNodeSessions.session_owner == _user,
            ).count()

            logger.debug(
                f"Found {_find_active_target_nodes_sessions} active session(s) for {_user}"
            )

            if _find_active_target_nodes_sessions >= _max_session_count:
                return SocaError.GENERIC_ERROR(
                    helper=f"User already has {_find_active_target_nodes_sessions} target nodes. Delete one of contact SOCA admin to increase the quota."
                ).as_flask()

            _selected_subnet = (
                random.choice(
                    SocaCastEngine(
                        _get_soca_parameters.get("/configuration/PrivateSubnets")
                    )
                    .cast_as(expected_type=list)
                    .get("message")
                )
                if not args["subnet_id"]
                else args["subnet_id"]
            )

            # Get all public key for the user
            _user_public_keys = get_user_pubkeys(username=_user)  # return a list

            if args["software_stack_id"] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(
                    parameter="software_stack_id"
                ).as_flask()
            else:
                _software_stack_id = SocaCastEngine(
                    data=args["software_stack_id"]
                ).cast_as(expected_type=int)
                if _software_stack_id.get("success"):
                    _get_software_stack = TargetNodeSoftwareStacksHelper(
                        software_stack_id=_software_stack_id.get("message"),
                        is_active=True,
                    )
                else:
                    return SocaError.GENERIC_ERROR(
                        helper=f"software_stack_id does not seems to be a valid integer: {_software_stack_id.message}",
                    ).as_flask()

            # Validate Software Stack Information
            _get_software_stack_info = _get_software_stack.get_stack_info()
            if _get_software_stack_info.get("success") is True:
                _software_stack_info = _get_software_stack_info.get("message")
            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to get Software Stack Info: {_get_software_stack_info.get('message')}",
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

            # Validate Software Stack Permissions
            _get_software_stack_permissions = _get_software_stack.validate(
                instance_type=instance_type,
                root_size=args["disk_size"],
                subnet_id=args["subnet_id"],
                session_owner=_user,
                project=args.get("project"),
            )

            if _get_software_stack_permissions.get("success") is False:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_name,
                    session_owner=_user,
                    helper=_get_software_stack_permissions.get("message"),
                ).as_flask()

            # Get the user data template associated to the software stack
            _encoded_user_data_template = _software_stack_info.get("user_data").get(
                "user_data"
            )
            _decoded_user_data_template = base64.b64decode(
                _encoded_user_data_template
            ).decode("utf-8")

            # software_stack ensure ami_user_data_variables is in the correct format
            _extra_user_data_variables = parse_user_data_variables(
                _software_stack_info.get("ami_user_data_variables")
            )
            logger.info(
                f"Retrieve extra  user data variable {_extra_user_data_variables=}"
            )

            # Validate Software Stack Permissions
            _get_software_stack_permissions = _get_software_stack.validate(
                instance_type=instance_type,
                root_size=args["disk_size"],
                subnet_id=_selected_subnet,
                session_owner=_user,
                project=args.get("project"),
            )

            if _get_software_stack_permissions.get("success") is False:
                return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                    session_number=_session_name,
                    session_owner=_user,
                    helper=_get_software_stack_permissions.get("message"),
                ).as_flask()

            logger.debug(f"Retrieved associated {_decoded_user_data_template}")

            # Must add the variable specific to the software stack
            _user_data_variables = {
                "SOCA_USER": _user,  # default
                "SOCA_USER_PUBLIC_KEYS": _user_public_keys,  # default
                **_extra_user_data_variables,
            }

            logger.info(f"{_user_data_variables=} requested for target node")

            get_user_data = SocaJinja2Renderer().from_string(
                data=_decoded_user_data_template, variables=_user_data_variables
            )
            if get_user_data.get("success") is True:
                _rendered_user_data = get_user_data.get("message")

                byte_size = len(_rendered_user_data.encode("utf-8"))
                kb_size = byte_size / 1024
                logger.debug(
                    f"EC2 User Data must be less than 16 KB, detected {kb_size:.1f}"
                )
                if byte_size > 16 * 1024:
                    return SocaError.GENERIC_ERROR(
                        helper=f"User Data on EC2 are limited to 16 KB. Current size is {kb_size:.1f} KB"
                    ).as_flask()

            else:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to generate User data due to {get_user_data.get('message')}"
                )

            launch_parameters = {
                "security_group_id": _get_soca_parameters.get(
                    "/configuration/TargetNodeSecurityGroup"
                ),
                "instance_profile": _get_soca_parameters.get(
                    "/configuration/TargetNodeInstanceProfileArn"
                ),
                "instance_type": instance_type,
                "project": args.get("project"),
                "subnet_id": _selected_subnet,
                "tenancy": args["tenancy"],
                "image_id": _software_stack_info.get("ami_id"),
                "session_name": _session_name,
                "session_uuid": _session_uuid,
                "disk_size": args["disk_size"],
                "volume_type": _get_soca_parameters.get(
                    "/configuration/DefaultVolumeType"
                ),
                "cluster_id": _get_soca_parameters.get("/configuration/ClusterId"),
                "metadata_http_tokens": _get_soca_parameters.get(
                    "/configuration/MetadataHttpTokens"
                ),
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
                "TargetNodeInstanceProfileArn": _get_soca_parameters.get(
                    "/configuration/TargetNodeInstanceProfileArn"
                ),
                "user_data": base64.b64encode(
                    _rendered_user_data.encode("utf-8")
                ).decode("utf-8"),
                "capacity_reservation_id": None,
                "custom_tags": {}
            }
            
            # Get custom tags if specified
            _tags_allowed = SocaConfig(key="/configuration/FeatureFlags/AllowCustomTagsTargetNodes").get_value(return_as=bool)
            if _tags_allowed.get("success") is True:
                if _tags_allowed.get("message") is True:
                    _get_tags = SocaConfig(key="/configuration/CustomTags/").get_value(allow_unknown_key=True)
                    if _get_tags.get("success") is True:
                        _tag_dict = SocaCastEngine(data=_get_tags.get("message")).autocast(preserve_key_name=True)
                        if _tag_dict.get("success") is True:
                            logger.info(f"Adding new tags: {_tag_dict.get('message')}")
                            launch_parameters["custom_tags"] = _tag_dict.get("message")
                        else:
                            logger.error(f"Unable to autocast custom tags {_tag_dict=} ")
                    else:
                        logger.warning("/configuration/CustomTags/ does not exist in this environment, ignoring ...")
                else:
                    logger.warning(f"Unable to determine if tags are allowed because of: {_tags_allowed=} ")
                     
            else:
                logger.warning("Custom tags are not allowed. AllowCustomTagsTargetNodes is set to false")

            logger.debug(f"Launch parameters for target node: {launch_parameters}")


            _custom_tags = []
            if launch_parameters.get("custom_tags"):
                for tag in launch_parameters["custom_tags"].values():
                    if tag.get("Enabled", ""):
                        _custom_tags.append({"Key": tag["Key"], "Value": tag["Value"]})
                    else:
                        logger.warning(f"{tag} does not have Enabled key or Enabled is False.")
            
            try:
                logger.debug(f"Trying to perform DryRun with {launch_parameters}")
                client_ec2.run_instances(
                    MaxCount=1,
                    MinCount=1,
                    SecurityGroupIds=[launch_parameters["security_group_id"]],
                    InstanceType=launch_parameters["instance_type"],
                    IamInstanceProfile={"Arn": launch_parameters["instance_profile"]},
                    SubnetId=(
                        random.choice(launch_parameters["soca_private_subnets"])
                        if not launch_parameters["subnet_id"]
                        else launch_parameters["subnet_id"]
                    ),
                    Placement={"Tenancy": launch_parameters["tenancy"]},
                    UserData=launch_parameters["user_data"],
                    ImageId=launch_parameters["image_id"],
                    DryRun=True,
                    TagSpecifications=[{"ResourceType": "instance", "Tags": _custom_tags}] if _custom_tags else [],
                    )
            except ClientError as err:
                if err.response["Error"].get("Code") == "DryRunOperation":
                    dry_run_launch = {"success": True, "message": "DryRun succeeded"}
                else:
                    dry_run_launch = {"success": True, "message": err}
                    
            if dry_run_launch.get("success"):
                _stack_name = f"{launch_parameters['cluster_id']}-{launch_parameters['session_name']}-{launch_parameters['user']}"
                # Request On-Demand Capacity Reservation
                # This is to ensure capacity is available on the selected subnet.
                if (
                    SocaConfig(key="/configuration/FeatureFlags/EnableCapacityReservation")
                    .get_value(return_as=bool)
                    .get("message")
                    is False
                ):
                    logger.info(
                        "/configuration/FeatureFlags/EnableCapacityReservation flag is set to False, SOCA will not request a new capacity reservation"
                    )
                else:
                    logger.info(
                        f"Requesting ODCR for {launch_parameters['instance_type']=}, instance_count=1, capacity_reservation_name={_stack_name}, subnet_ids={[_selected_subnet]}, {launch_parameters["image_id"]}"
                    )
                    _request_on_demand_capacity_reservation = (
                        create_capacity_reservation_vdi(
                            instance_type=launch_parameters["instance_type"],
                            capacity_reservation_name=_stack_name,
                            subnet_id=_selected_subnet,
                            instance_ami=launch_parameters["image_id"],
                            tenancy=launch_parameters["tenancy"],
                        )
                    )
                    if _request_on_demand_capacity_reservation.get("success") is True:
                        launch_parameters["capacity_reservation_id"] = (
                            _request_on_demand_capacity_reservation.get("message")
                        )

                    else:
                        return SocaError.GENERIC_ERROR(
                            helper=f"Unable to create capacity reservation due to {_request_on_demand_capacity_reservation.message}"
                        ).as_flask()

                launch_template = target_nodes_cloudformation_builder.main(
                    **launch_parameters
                )
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
                        {
                            "Key": "soca:TargetNodeSessionUUID",
                            "Value": str(launch_parameters["session_uuid"]),
                        },
                        {"Key": "soca:JobProject", "Value": args.get("project")},
                        {"Key": "soca:JobOwner", "Value": _user},
                        {
                            "Key": "soca:ClusterId",
                            "Value": str(launch_parameters["cluster_id"]),
                        },
                        {"Key": "soca:NodeType", "Value": "target_node"},
                    ]

                    _create_stack = cloudformation_helper.create_stack(
                        stack_name=_cfn_stack_name,
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
                    for _reservation_id in launch_parameters[
                        "capacity_reservation_id"
                    ].split(","):
                        cancel_capacity_reservation(reservation_id=_reservation_id)
                    return SocaError.VIRTUAL_DESKTOP_LAUNCH_ERROR(
                        session_number=_session_name,
                        session_owner=_user,
                        helper=f"{launch_template.get('message')}.",
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

            new_session = TargetNodeSessions(
                is_active=True,
                created_on=datetime.now(timezone.utc),
                deactivated_on=None,
                session_owner=_user,
                session_name=_session_name,
                session_project=args.get("project"),
                stack_name=_cfn_stack_name,
                session_uuid=_session_uuid,
                session_thumbnail=_session_thumbnail,
                schedule=json.dumps(config.Config.DCV_DEFAULT_SCHEDULE),
                session_state_latest_change_time=datetime.now(timezone.utc),
                instance_private_dns=None,
                instance_private_ip=None,
                instance_state="pending",
                instance_id=None,
                os_family=_software_stack_info.get("os_family"),
                instance_type=args["instance_type"],
                session_connection_instructions="instruction will go here",
                target_node_software_stack_id=_software_stack_info.get("id"),
                session_state="pending",
            )

            try:
                db.session.add(new_session)
                db.session.commit()
            except Exception as err:
                logger.error(
                    "Cloudformation stack created but DB error, deleting cloudformation stack"
                )
                _delete_stack = cloudformation_helper.delete_stack(
                    stack_name=_cfn_stack_name
                )
                if _delete_stack.get("success") is False:
                    return SocaError.AWS_API_ERROR(
                        service_name="cloudformation",
                        helper=f"Unable to delete CloudFormation stack {_cfn_stack_name} due to {_delete_stack.get("success")}",
                    ).as_flask()

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
