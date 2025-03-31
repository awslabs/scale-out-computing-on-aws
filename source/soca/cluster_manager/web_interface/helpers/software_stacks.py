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

import logging
import utils.aws.boto3_wrapper as utils_boto3
from models import db, SoftwareStacks, VirtualDesktopSessions, VirtualDesktopProfiles
from utils.error import SocaError
from utils.response import SocaResponse
from functools import wraps
from typing import Optional

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
logger = logging.getLogger("soca_logger")


def require_software_stack_info(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if not self._software_stack_id:
            return SocaResponse(
                success=False,
                message="software_stack_id is missing",
            )
        return func(self, *args, **kwargs)

    return wrapper


class SoftwareStacksHelper:
    def __init__(
        self, software_stack_id: Optional[int] = None, is_active: Optional[bool] = True
    ):
        self._software_stack_id = software_stack_id
        self._is_active = is_active
        self._software_stack_data = None

        if is_active not in [True, False]:
            logger.warning(
                f"Invalid is_active flag, detected {self._is_active } default to True"
            )
            self._is_active = True

        if self._software_stack_id is None:
            self._software_stack_data = SoftwareStacks.query.filter(
                SoftwareStacks.is_active == self._is_active
            )
        else:
            self._software_stack_data = SoftwareStacks.query.filter(
                SoftwareStacks.is_active == self._is_active,
                SoftwareStacks.id == self._software_stack_id,
            )
        self._software_stack_info = None

    def list(self) -> [list, dict]:
        if self._software_stack_id is not None:
            _software_stack = self._software_stack_data.first()
            if _software_stack:
                self._software_stack_info = _software_stack.as_dict()
        else:
            _software_stack = self._software_stack_data.all()
            if _software_stack:
                self._software_stack_info = [
                    stack.as_dict() for stack in _software_stack
                ]

        logger.info(f"SoftwareStack {self._software_stack_info}")
        if self._software_stack_info is not None:
            return SocaResponse(success=True, message=self._software_stack_info)
        else:
            return SocaResponse(
                success=False,
                message="Unable to find software stack, this stack does not exist or is no longer active",
            )

    @require_software_stack_info
    def validate(
        self, instance_type: str, root_size: int, subnet_id: str, session_owner: str
    ) -> dict:
        # Validate if:
        # 1 - A user can use this AMI (to be added)
        # 2 - The instance type chose is valid
        # 3 - The root size is valid
        # 4 - The subnet is valid
        # 5 - The username is valid
        if not isinstance(self._software_stack_info, dict):
            return SocaError.GENERIC_ERROR(
                helper="Stack Info is not a dict. Ensure you have specified software_stack_id when calling SoftwareStacksHelper"
            )

        _vdi_profile_id = self._software_stack_info.get("virtual_desktop_profile_id")
        _vdi_profile_data = VirtualDesktopProfiles.query.filter(
            SoftwareStacks.is_active == True,
            VirtualDesktopProfiles.id == _vdi_profile_id,
        ).first()
        if not _vdi_profile_data:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to find VDI profile {_vdi_profile_id} or profile is no longer active"
            )

        _allowed_instance_types = _vdi_profile_data.allowed_instance_types
        _max_root_size = _vdi_profile_data.max_root_size
        _allowed_subnet_ids = _vdi_profile_data.allowed_subnet_ids

        if instance_type not in _allowed_instance_types:
            return SocaError.GENERIC_ERROR(
                helper=f"Instance type {instance_type} is not allowed for this stack"
            )
        if root_size > _max_root_size:
            return SocaError.GENERIC_ERROR(
                helper=f"Root size {root_size} is not allowed for this stack, maximum value if {_max_root_size}"
            )

        if subnet_id not in _allowed_subnet_ids:
            return SocaError.GENERIC_ERROR(
                helper=f"Subnet {subnet_id} is not allowed for this stack"
            )

        # Next: validate username
        return SocaResponse(success=True, message=True)
