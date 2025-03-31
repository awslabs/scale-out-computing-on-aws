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

import time
import logging
from utils.aws.ssm_parameter_store import SocaConfig
import utils.aws.boto3_wrapper as utils_boto3
from utils.cache import SocaCacheClient
from models import SoftwareStacks, VirtualDesktopSessions
import random
from botocore.exceptions import ClientError
from utils.error import SocaError
import boto3
import config
import botocore
import fnmatch
from utils.response import SocaResponse

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
logger = logging.getLogger("soca_logger")


def can_launch_instance(launch_parameters: dict) -> dict:
    try:
        logger.debug(f"Trying to perform DryRun with {launch_parameters}")
        if launch_parameters["base_os"] in {"amazonlinux2", "amazonlinux2023"}:
            _ebs_device_name = "/dev/xvda"
        else:
            _ebs_device_name = "/dev/sda1"

        client_ec2.run_instances(
            BlockDeviceMappings=[
                {
                    "DeviceName": _ebs_device_name,
                    "Ebs": {
                        "DeleteOnTermination": True,
                        "VolumeSize": launch_parameters.get("disk_size"),
                        "VolumeType": launch_parameters.get("VolumeType", "gp2"),
                        "Encrypted": True,
                    },
                },
            ],
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
            HibernationOptions={"Configured": launch_parameters["hibernate"]},
        )

    except ClientError as err:
        if err.response["Error"].get("Code") == "DryRunOperation":
            return {"success": True, "message": None}
        else:
            return SocaError.AWS_API_ERROR(
                service_name="ec2",
                helper=f"Unable to launch capacity: {err.response['Error']}",
            )


def max_concurrent_desktop_limit_reached(os_family: str, session_owner: str) -> bool:
    """
    Return True if the user can launch a virtual desktop, assuming user has not already reached the max number of VDI associated to his/her profile
    """

    logger.debug(
        f"Validating if {session_owner} has not reached the number of max session"
    )

    _max_dcv_session_count = (
        config.Config.DCV_LINUX_SESSION_COUNT
        if os_family == "linux"
        else config.Config.DCV_WINDOWS_SESSION_COUNT
    )
    logger.debug(f"Max DCV Session Count: {_max_dcv_session_count} for {os_family}")

    _find_live_session = VirtualDesktopSessions.query.filter(
        VirtualDesktopSessions.is_active == True,
        VirtualDesktopSessions.os_family == os_family,
    ).count()

    logger.debug(f"Found {_find_live_session} active session(s) for {os_family}")

    if _find_live_session >= _max_dcv_session_count:
        return True
    else:
        return False


def generate_allowed_instances_list(baseos: str, architecture: str) -> list:
    _start_time = time.perf_counter_ns()
    _allowed_list: list = []
    logger.debug(
        f"Starting generate_allowed_instances_list() for baseOS: {baseos} , architecture: {architecture}"
    )

    _cache_client = SocaCacheClient(is_admin=True)
    if not _cache_client.is_enabled().success:
        logger.error(
            "Unable to retrieve cache_client from extensions.get_cache_config()"
        )
        return _allowed_list

    _now_ms: float = (time.perf_counter_ns() - _start_time) / 1_000_000
    logger.debug(f"cache client initialization completed in {_now_ms} ms")

    # Check architecture - default to x86_64
    if architecture.lower() not in {"x86_64", "arm64"}:
        architecture = "x86_64"

    # the baseOS is generic linux/windows - not a per release/distro
    if baseos.lower() not in {"linux", "windows"}:
        baseos = "linux"

    _cache_configuration_key: str = f"dcv/allowed_instance_list_{baseos}_{architecture}"
    logger.debug(
        f"Checking for cached instance allow list at key: {_cache_configuration_key}"
    )

    _conf_ttl = _cache_client.ttl(_cache_configuration_key).message
    _config_check_ms = (time.perf_counter_ns() - _start_time) / 1_000_000
    logger.debug(f"Config TTL check completed in {_config_check_ms} ms")

    if _conf_ttl <= 0:
        _start_api_time: int = time.perf_counter_ns()
        _allowed_list: list = _generate_allowed_instances_list_aws_api()
        _api_check_ms: float = (time.perf_counter_ns() - _start_api_time) / 1_000_000
        logger.debug(f"AWS API polling completed in {_api_check_ms} ms")
        _redis_pipeline_start: int = time.perf_counter_ns()
        _cache_client.delete(_cache_configuration_key)
        _cache_client.rpush(_cache_configuration_key, *_allowed_list)
        _cache_client.expire(key=_cache_configuration_key, ttl=3600)
        _redis_pipeline_duration = (
            time.perf_counter_ns() - _redis_pipeline_start
        ) / 1_000_000
        logger.debug(
            f"Redis instance_type cache pipeline completed in {_redis_pipeline_duration} ms"
        )
    else:
        logger.debug(f"Valid TTL from Redis - {_conf_ttl}")
        _allowed_list = _cache_client.lrange(
            _cache_configuration_key, start=0, end=-1
        ).message

    _duration = (time.perf_counter_ns() - _start_time) / 1_000_000
    logger.debug(
        f"Completed instance_list ({len(_allowed_list)} entries) in {_duration} ms"
    )
    return _allowed_list


def _generate_allowed_instances_list_aws_api() -> list:
    logger.debug(f"Generating allowed_instances list")

    _allowed_list: list = []

    _config_allowed_list: list = (
        SocaConfig(key="/configuration/DCVAllowedInstances")
        .get_value(return_as=list)
        .get("message")
    )

    _config_allow_metal: bool = (
        SocaConfig(key="/configuration/DCVAllowBareMetal")
        .get_value(return_as=bool)
        .get("message")
    )

    _config_allow_prevgen: bool = (
        SocaConfig(key="/configuration/DCVAllowPreviousGenerations")
        .get_value(return_as=bool)
        .get("message")
    )

    logger.debug(
        f"Cluster configuration allowed DCV list: {_config_allowed_list}  BareMetal: {_config_allow_metal}, PreviousGeneration: {_config_allow_prevgen}"
    )

    _filters: list = []

    if not _config_allow_prevgen:
        _filters.append({"Name": "current-generation", "Values": ["true"]})

    if not _config_allow_metal:
        _filters.append({"Name": "bare-metal", "Values": ["false"]})

    # Add our instance types from config
    _filters.append({"Name": "instance-type", "Values": _config_allowed_list})

    _start = time.perf_counter_ns()
    _ec2_paginator = client_ec2.get_paginator("describe_instance_types")
    _ec2_iterator = _ec2_paginator.paginate(Filters=_filters)

    _page_count: int = 0
    for _page in _ec2_iterator:
        _page_count += 1
        _instance_list: list = _page.get("InstanceTypes", [])
        for _instance in _instance_list:
            _allowed_list.append(_instance.get("InstanceType", "unknown-instance-name"))
    _duration_ms = (time.perf_counter_ns() - _start) / 1_000_000
    logger.info(
        f"Refreshed instances list of {len(_allowed_list)} instances from AWS in {_duration_ms} ms ({_page_count} API pages)"
    )
    # TODO - Should these be sorted for the end-user?
    # For example - display the more recent / newer instance families first in the list
    return sorted(_allowed_list)


def generate_default_dcv_amis() -> dict:
    logger.debug(f"Generating generate_default_dcv_amis list")

    # Retrieve CustomAMIMap
    _get_all_soca_base_os = (
        SocaConfig(key="/configuration/CustomAMIMap")
        .get_value(return_as=dict)
        .get("message")
    )
    # Remove Empty
    _get_non_empty_soca_base_os = {
        arch: {k: v for k, v in ami_dict.items() if v}
        for arch, ami_dict in _get_all_soca_base_os.items()
    }

    _supported_dcv_base_os = config.Config.DCV_BASE_OS.keys()
    for arch in _get_non_empty_soca_base_os:
        distros_to_remove = []

        for _distro in _get_non_empty_soca_base_os[arch].keys():
            if _distro not in _supported_dcv_base_os:
                logger.debug(
                    f"Removing {_distro} from the list of default DCV AMIs as it is not supported"
                )
                distros_to_remove.append(_distro)

        # Remove after iteration
        for _distro in distros_to_remove:
            del _get_non_empty_soca_base_os[arch][_distro]

    return _get_non_empty_soca_base_os


def get_arch_for_instance_type(instancetype: str) -> str:
    """
    Return the architecture of the given instance type
    """
    logger.debug(f"Retrieving architecture for instance type: {instancetype}")
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