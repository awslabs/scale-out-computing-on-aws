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
import logging
from decorators import admin_api, restricted_api, private_api
from datetime import datetime, timezone
from models import (
    db,
    project_software_stack_association,
    VirtualDesktopProfiles,
    SoftwareStacks,
    Projects,
)
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from flask import request
from sqlalchemy.orm import joinedload
import re


logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


def is_valid_csv(csv_string: str):
    """
    Validate if a given string is in a proper CSV format.

    A valid CSV string:
    - Can be empty ("").
    - Can be a single "*", meaning "all".
    - Uses commas as delimiters.
    - Each value is non-empty after stripping whitespace.

    Returns:
    - True if valid, False otherwise.
    """
    if not isinstance(csv_string, str):
        return False

    if csv_string == "":  # Allow empty string as valid
        return True

    if csv_string.strip() == "*":  # Allow single "*"
        return True

    # Regex: Allows numbers, letters, spaces, *
    csv_pattern = r"^\s*[\w\s\.\-\'\*]+(\s*,\s*[\w\s\.\-\'\*]+)*\s*$"

    return bool(re.match(csv_pattern, csv_string))


class ProjectsManager(Resource):

    @admin_api
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("project_id", type=str, location="args")
        args = parser.parse_args()

        logger.debug(f"List SOCA projects with {request.args}")
        _project_info = {}
        if args["project_id"] is None:
            _list_project_profiles = Projects.query.filter_by(is_active=True).options(
                joinedload(Projects.software_stacks)
            )
        else:
            if (
                cast_result := SocaCastEngine(data=args["project_id"]).cast_as(int)
            ).get("success"):
                _project_id = cast_result.get("message")
                _list_project_profiles = Projects.query.filter_by(
                    id=_project_id, is_active=True
                )
            else:
                return SocaError.GENERIC_ERROR(
                    helper="profile_id does not seems to be a valid integer"
                )

        if _list_project_profiles.count() == 0:
            logger.warning("No Project found")
            return SocaResponse(
                success=True, message="No Project found"
            ).as_flask()
        else:
            for _project in _list_project_profiles.all():
                project_data = _project.as_dict()
                project_data["software_stack_ids"] = [
                    stack.id for stack in _project.software_stacks
                ]
                _project_info[_project.id] = project_data
            return SocaResponse(success=True, message=_project_info).as_flask()

    @admin_api
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("project_name", type=str, location="form")
        parser.add_argument("description", type=str, location="form")
        parser.add_argument("allowed_users", type=str, location="form")
        parser.add_argument("software_stack_ids", type=str, location="form")

        args = parser.parse_args()

        logger.debug(f"Received ProjectsManager Create Request args {args}")
        _project_name = args["project_name"]
        _description = args["description"]
        _allowed_users = "" if args["allowed_users"] is None else args["allowed_users"]
        if is_valid_csv(csv_string=_allowed_users) is False:
            return SocaError.GENERIC_ERROR(
                helper="allowed_users must be a valid CSV string"
            ).as_flask()

        _software_stack_ids = args["software_stack_ids"]

        _user = request.headers.get("X-SOCA-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        _required_input = [
            "project_name",
            "description",
            "allowed_users",
        ]

        for _input in _required_input:
            if args[_input] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(parameter=_input).as_flask()

        if len(_description) > 500:
            return SocaError.GENERIC_ERROR(
                helpers="Description cannot be greater than 500 characters"
            ).as_flask()

        if Projects.query.filter_by(is_active=True, project_name=_project_name).first():
            return SocaError.GENERIC_ERROR(
                helper=f"Project name {_project_name} already exists, pick a different name or deactivate the existing one",
            ).as_flask()

        _new_project_creation = Projects(
            project_name=_project_name,
            description=_description,
            allowed_users=_allowed_users,
            allowed_groups="*",  # not in use for now
            is_active=True,
            created_on=datetime.now(timezone.utc),
            created_by=_user,
        )

        _add_software_stack_ids = [
            item.strip() for item in _software_stack_ids.split(",")
        ]
        _software_stacks = SoftwareStacks.query.filter(
            SoftwareStacks.id.in_(_add_software_stack_ids)
        ).all()
        _new_project_creation.software_stacks.extend(_software_stacks)

        try:
            db.session.add(_new_project_creation)
            db.session.commit()
        except Exception as err:
            return SocaError.DB_ERROR(
                query=_new_project_creation,
                helper=f"Unable to add new project to DB due to {err}",
            )

        return SocaResponse(
            success=True,
            message=f"Project has been created successfully",
        ).as_flask()

    @admin_api
    def delete(self):
        parser = reqparse.RequestParser()
        parser.add_argument("project_id", type=str, location="form")

        args = parser.parse_args()
        logger.debug(f"Received Project Delete for {args}")

        if args["project_id"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="project_id").as_flask()

        _validate_project_id = SocaCastEngine(data=args["project_id"]).cast_as(int)

        if _validate_project_id.get("success") is True:
            _project_id = _validate_project_id.get("message")
        else:
            return SocaError.IMAGE_DEREGISTER_ERROR(
                image_label=args["project_id"],
                helper=f"profile_id does not seems to be a valid integer {args['project_id']}",
            ).as_flask()

        _user = request.headers.get("X-SOCA-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        _check_project = Projects.query.filter_by(
            id=_project_id, is_active=True
        ).first()

        if _check_project:
            if _check_project.id == 1 or _check_project.project_name == "default":
                return SocaError.GENERIC_ERROR(
                    helper=f"Profile {_check_project.project_name} is a default profile and cannot be deleted"
                ).as_flask()

            _software_stack_using_project = SoftwareStacks.query.join(
                project_software_stack_association
            ).filter(
                project_software_stack_association.c.project_id == _check_project.id,
                SoftwareStacks.is_active == True,
            )

            if _software_stack_using_project.count() > 0:
                return SocaError.GENERIC_ERROR(
                    helper=f"Project {_check_project.project_name} is using {_software_stack_using_project.count()} active software stacks. Update them first."
                ).as_flask()

            try:
                _check_project.is_active = False
                _check_project.deactivated_on = datetime.now(timezone.utc)
                _check_project.deactivated_by = _user
                db.session.commit()
            except Exception as err:
                return SocaError.DB_ERROR(
                    query=_check_project,
                    helper=f"Unable to deactivate project {_project_id} due to {err}",
                ).as_flask()

            return SocaResponse(
                success=True, message=f"Project deleted successfully"
            ).as_flask()

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"Project not found or already deactivated",
            ).as_flask()

    @admin_api
    def put(self):
        parser = reqparse.RequestParser()
        parser.add_argument("project_id", type=str, location="form")
        parser.add_argument("allowed_users", type=str, location="form")
        parser.add_argument("software_stack_ids", type=str, location="form")
        parser.add_argument("description", type=str, location="form")

        args = parser.parse_args()
        _allowed_users = "" if args["allowed_users"] is None else args["allowed_users"]
        if is_valid_csv(csv_string=_allowed_users) is False:
            return SocaError.GENERIC_ERROR(
                helper="allowed_users must be a valid CSV string"
            ).as_flask()
        _software_stack_ids = args["software_stack_ids"]
        _project_id = args["project_id"]
        _description = args["description"]

        logger.info(f"Receive Project Update request with {args}")

        _user = request.headers.get("X-SOCA-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        _required_input = [
            "description",
            "software_stack_ids",
            "allowed_users",
            "project_id",
        ]

        for _input in _required_input:
            if args[_input] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(parameter=_input).as_flask()

        if SocaCastEngine(data=_project_id).cast_as(int).get("success") is True:
            _project_to_update = Projects.query.filter_by(
                id=_project_id, is_active=True
            ).first()
            if not _project_to_update:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to find existing project with id {_project_id}",
                ).as_flask()
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"project_id does not seems to be a valid integer",
            ).as_flask()

        if len(_description) > 500:
            return SocaError.GENERIC_ERROR(
                helpers="Description cannot be greater than 500 characters"
            ).as_flask()

        try:
            _project_to_update.description = _description
            _project_to_update.allowed_users = _allowed_users

            _project_to_update.software_stacks.clear()

            # Prepare new software stacks
            _add_software_stack_ids = [
                item.strip() for item in _software_stack_ids.split(",")
            ]
            _software_stacks = SoftwareStacks.query.filter(
                SoftwareStacks.id.in_(_add_software_stack_ids)
            ).all()

            # Add new software stacks
            _project_to_update.software_stacks.extend(_software_stacks)

            db.session.commit()
        except Exception as err:
            return SocaError.DB_ERROR(
                query=_project_to_update,
                helper=f"Unable to add new project to DB due to {err}",
            )

        return SocaResponse(
            success=True,
            message=f"Project has been updated successfully",
        ).as_flask()
