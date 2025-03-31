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
import json
from datetime import datetime, timezone
from models import db, VirtualDesktopProfiles, SoftwareStacks
import math
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.aws.ssm_parameter_store import SocaConfig
import utils.aws.ec2_helper as ec2_helper
from flask import request
from sqlalchemy.orm import joinedload


logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class VirtualDesktopProfilesManager(Resource):

    @admin_api
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("profile_id", type=str, location="args")
        args = parser.parse_args()

        logger.debug(f"List Virtual Desktops Profile with {request.args}")
        _profile_info = {}
        if args["profile_id"] is None:
            _list_vdi_profiles = VirtualDesktopProfiles.query.filter_by(
                is_active=True
            ).options(joinedload(VirtualDesktopProfiles.software_stacks))
        else:
            if (
                cast_result := SocaCastEngine(data=args["profile_id"]).cast_as(int)
            ).get("success"):
                _profile_id = cast_result.get("message")
                _list_vdi_profiles = VirtualDesktopProfiles.query.filter_by(
                    id=_profile_id, is_active=True
                ).options(joinedload(VirtualDesktopProfiles.software_stacks))
            else:
                return SocaError.GENERIC_ERROR(
                    helper="profile_id does not seems to be a valid integer"
                )

        if _list_vdi_profiles.count() == 0:
            logger.warning("No Virtual Desktop Profiles found")
            return SocaResponse(
                success=True, message="No Virtual Desktop Profiles found"
            ).as_flask()
        else:
            for _profile in _list_vdi_profiles.all():
                _profile_info[_profile.id] = _profile.as_dict()
                _profile_info[_profile.id]["software_stack_ids"] = [
                    stack.id for stack in _profile.software_stacks
                ]

            return SocaResponse(success=True, message=_profile_info).as_flask()

    @admin_api
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("profile_name", type=str, location="form")
        parser.add_argument("pattern_allowed_instance_types", type=str, location="form")
        parser.add_argument("allowed_subnet_ids", type=str, location="form")
        parser.add_argument("max_root_size", type=str, location="form")

        args = parser.parse_args()

        logger.debug(
            f"Received VirtualDesktopProfilesManager Registration Request args {args}"
        )
        _profile_name = args["profile_name"]
        _pattern_allowed_instance_types = args["pattern_allowed_instance_types"]
        _allowed_subnet_ids = args["allowed_subnet_ids"]
        _max_root_size = args["max_root_size"]

        _user = request.headers.get("X-SOCA-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        _required_input = [
            "profile_name",
            "pattern_allowed_instance_types",
            "allowed_subnet_ids",
            "max_root_size",
        ]

        for _input in _required_input:
            if args[_input] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(parameter=_input).as_flask()

        # Validate Subnets
        _soca_private_subnets = (
            SocaConfig(key="/configuration/PrivateSubnets")
            .get_value(return_as=list)
            .get("message")
        )

        try:
            _proposed_subnets = [
                item.strip() for item in args["allowed_subnet_ids"].split(",")
            ]
        except Exception:
            return SocaError.GENERIC_ERROR(
                helper="allowed_subnet_ids must be a comma separated strings of subnets"
            ).as_flask()

        for _subnet in _proposed_subnets:
            if _subnet not in _soca_private_subnets:
                return SocaError.GENERIC_ERROR(
                    helper=f"Subnet {_subnet} is not a valid private subnet. Update the value or add this subnet to /configuration/PrivateSubnets",
                ).as_flask()

        # Validate list of EC2 instances
        _proposed_pattern_allowed_instance_types = [
            item.strip() for item in args["pattern_allowed_instance_types"].split(",")
        ]
        _instances_list = ec2_helper.get_instance_types_by_architecture(
            instance_type_pattern=_proposed_pattern_allowed_instance_types
        )
        if _instances_list.get("success") is True:
            _allowed_instance_types = _instances_list.get("message")
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"pattern_allowed_instance_types must be a valid EC2 instance type pattern",
            ).as_flask()

        try:
            # Round up to the next integer size versus using int() or round() which can round _down_
            _max_root_size: int = math.ceil(float(args["max_root_size"]))
        except ValueError:
            return SocaError.GENERIC_ERROR(
                helper=f"_max_root_size must be a valid integer",
            ).as_flask()

        if VirtualDesktopProfiles.query.filter_by(
            is_active=True, profile_name=_profile_name
        ).first():
            return SocaError.GENERIC_ERROR(
                helper=f"Profile name {_profile_name} already exists, pick a different name or deactivate the existing one",
            ).as_flask()

        _new_profile_creation = VirtualDesktopProfiles(
            profile_name=_profile_name,
            allowed_subnet_ids=",".join(_proposed_subnets),
            pattern_allowed_instance_types=_pattern_allowed_instance_types,
            allowed_instance_types=json.dumps(_allowed_instance_types),
            max_root_size=_max_root_size,
            is_active=True,
            created_on=datetime.now(timezone.utc),
            created_by=_user,
        )

        try:
            db.session.add(_new_profile_creation)
            db.session.commit()
        except Exception as err:
            return SocaError.DB_ERROR(
                query=_new_profile_creation,
                helper=f"Unable to add VDI Profile {_profile_name} to DB due to {err}",
            )

        return SocaResponse(
            success=True,
            message=f"{_profile_name} registered successfully in SOCA",
        ).as_flask()

    @admin_api
    def delete(self):
        parser = reqparse.RequestParser()
        parser.add_argument("profile_id", type=str, location="form")

        args = parser.parse_args()
        logger.debug(f"Received Profile Delete for {args}")

        if args["profile_id"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="profile_id").as_flask()

        _validate_profile_id = SocaCastEngine(data=args["profile_id"]).cast_as(int)

        if _validate_profile_id.get("success") is True:
            _profile_id = _validate_profile_id.get("message")
        else:
            return SocaError.IMAGE_DEREGISTER_ERROR(
                image_label=args["profile_id"],
                helper=f"profile_id does not seems to be a valid integer {args['profile_id']}",
            ).as_flask()

        _user = request.headers.get("X-SOCA-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        _check_profile = VirtualDesktopProfiles.query.filter_by(
            id=_profile_id, is_active=True
        ).first()

        if _check_profile:

            if _check_profile.id == 1 or _check_profile.profile_name == "default":
                return SocaError.GENERIC_ERROR(
                    helper=f"Profile {_check_profile.profile_name} is a default profile and cannot be deleted"
                ).as_flask()

            _software_stack_using_profile = SoftwareStacks.query.filter_by(
                virtual_desktop_profile_id=_check_profile.id, is_active=True
            )
            if _software_stack_using_profile.count() > 0:
                return SocaError.GENERIC_ERROR(
                    helper=f"Profile {_check_profile.profile_name} is used by {_software_stack_using_profile.count()} software stacks. Update them first."
                ).as_flask()

            try:
                _check_profile.is_active = False
                _check_profile.deactivated_on = datetime.now(timezone.utc)
                _check_profile.deactivated_by = _user
                db.session.commit()
            except Exception as err:
                return SocaError.DB_ERROR(
                    query=_check_profile,
                    helper=f"Unable to deactivate software stack {_profile_id} due to {err}",
                ).as_flask()

            logger.info(f"VDI Profile deleted from SOCA")
            return SocaResponse(
                success=True, message=f"VDI Profile removed from SOCA"
            ).as_flask()

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"VDI Profile not found or already deactivated",
            ).as_flask()

    @admin_api
    def put(self):
        parser = reqparse.RequestParser()
        parser.add_argument("profile_id", type=str, location="form")
        parser.add_argument("pattern_allowed_instance_types", type=str, location="form")
        parser.add_argument("allowed_subnet_ids", type=str, location="form")
        parser.add_argument("max_root_size", type=str, location="form")

        args = parser.parse_args()
        _pattern_allowed_instance_types = args["pattern_allowed_instance_types"]
        _allowed_subnet_ids = args["allowed_subnet_ids"]
        _max_root_size = args["max_root_size"]
        _profile_id = args["profile_id"]

        _user = request.headers.get("X-SOCA-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        _required_input = [
            "pattern_allowed_instance_types",
            "allowed_subnet_ids",
            "max_root_size",
            "profile_id",
        ]

        for _input in _required_input:
            if args[_input] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(parameter=_input).as_flask()

        if SocaCastEngine(data=_profile_id).cast_as(int).get("success") is True:
            _profile_to_update = VirtualDesktopProfiles.query.filter_by(
                id=_profile_id, is_active=True
            ).first()
            if not _profile_to_update:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to find existing virtual desktop profile with id {_profile_id}",
                ).as_flask()
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"profile_id does not seems to be a valid integer",
            ).as_flask()

        # Validate Subnets
        _soca_private_subnets = (
            SocaConfig(key="/configuration/PrivateSubnets")
            .get_value(return_as=list)
            .get("message")
        )

        try:
            _proposed_subnets = [
                item.strip() for item in args["allowed_subnet_ids"].split(",")
            ]
        except Exception:
            return SocaError.GENERIC_ERROR(
                helper="allowed_subnet_ids must be a comma separated strings of subnets"
            ).as_flask()

        for _subnet in _proposed_subnets:
            if _subnet not in _soca_private_subnets:
                return SocaError.GENERIC_ERROR(
                    helper=f"Subnet {_subnet} is not a valid private subnet. Update the value or add this subnet to /configuration/PrivateSubnets",
                ).as_flask()

        # Validate list of EC2 instances
        _proposed_pattern_allowed_instance_types = [
            item.strip() for item in args["pattern_allowed_instance_types"].split(",")
        ]
        _instances_list = ec2_helper.get_instance_types_by_architecture(
            instance_type_pattern=_proposed_pattern_allowed_instance_types
        )
        if _instances_list.get("success") is True:
            _allowed_instance_types = _instances_list.get("message")
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"pattern_allowed_instance_types must be a valid EC2 instance type pattern",
            ).as_flask()

        try:
            # Round up to the next integer size versus using int() or round() which can round _down_
            _max_root_size: int = math.ceil(float(args["max_root_size"]))
        except ValueError:
            return SocaError.GENERIC_ERROR(
                helper=f"_max_root_size must be a valid integer",
            ).as_flask()

        try:
            _profile_to_update.allowed_subnet_ids = ",".join(_proposed_subnets)
            _profile_to_update.pattern_allowed_instance_types = (
                _pattern_allowed_instance_types
            )
            _profile_to_update.allowed_instance_types = json.dumps(
                _allowed_instance_types
            )
            _profile_to_update.max_root_size = _max_root_size
            db.session.add(_profile_to_update)
            db.session.commit()
        except Exception as err:
            return SocaError.DB_ERROR(
                query=_profile_to_update,
                helper=f"Unable to edit VDI Profile to DB due to {err}",
            ).as_flask()

        return SocaResponse(
            success=True,
            message=f"Profile updated successfully",
        ).as_flask()
