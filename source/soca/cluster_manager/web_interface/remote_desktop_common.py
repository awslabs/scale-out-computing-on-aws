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
from dateutil.parser import parse
from datetime import datetime
import utils.aws.boto3_wrapper as utils_boto3
from utils.cache import SocaCacheClient
from models import AmiList
import random
from botocore.exceptions import ClientError
from utils.error import SocaError
from requests import get
import config
from flask import request

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
logger = logging.getLogger("soca_logger")


def validate_ec2_dcv_image(os: str, image_id: str) -> bool:
    image_exist = (
        AmiList.query.filter(AmiList.is_active == True, AmiList.ami_id == image_id)
        .filter(AmiList.ami_type == os)
        .first()
    )
    if image_exist:
        return True
    else:
        return False


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
                service_name="cloudformation",
                helper=f"Dry run failed. Unable to launch capacity due to: {err}",
            )


def session_already_exist(session_number: int, os: str) -> bool:
    user_sessions = {}
    get_desktops = get(
        config.Config.FLASK_ENDPOINT + "/api/dcv/desktops",
        headers={
            "X-SOCA-USER": request.headers.get("X-SOCA-USER"),
            "X-SOCA-TOKEN": request.headers.get("X-SOCA-TOKEN"),
        },
        params={
            "os": os,
            "is_active": "true",
            "session_number": str(session_number),
        },
        verify=False,  # nosec
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


def generate_default_ami_linux() -> dict:
    logger.debug(f"Generating _generate_default_ami_linux list")
    _unsupported_os = ["rhel7", "centos7"]  # eol
    # Retrieve CustomAMIMap
    _get_all_soca_base_os = (
        SocaConfig(key="/configuration/CustomAMIMap")
        .get_value(return_as=dict)
        .get("message")
    )
    # Remove references to unsupported/EOL OS
    for arch in _get_all_soca_base_os:
        for _os in _unsupported_os:
            if _os in _get_all_soca_base_os[arch].keys():
                del _get_all_soca_base_os[arch][_os]

    return _get_all_soca_base_os


def resolve_windows_dcv_ami_id(
    region: str, owners: list[str], instance_type: str, version: str
) -> str:
    """
    Determine the best Windows DCV AMI ID to use based on the instance type and DCV version
    :param region: Region to use
    :param owners: A list of strings of the allowed AWS Account IDs / owners for the returned image (e.g. vendor supplied)
    :param instance_type: Instance type to use
    :param version: DCV version to use in AMI dotted format (e.g. 2023.1.1234)
    :return: DCV AMI ID to use for the specified instance type and DCV version. Returns an empty string if no AMI is found.
    """
    logger.debug(
        f"Trying to resolve the best Windows DCV AMI in region {region} for DCV version {version} running on instance {instance_type} owned by account {owners}"
    )
    _found_ami_id: str = ""

    if len(owners) == 0:
        logger.warning(
            f"No owners specified for DCV AMI search. Reverting to defaults of [877902723034]"
        )
        # TODO - This should also include the local account number?  Move this magic number someplace else
        owners = ["877902723034"]

    # Build up a search string
    _search_string: str = f"DCV-Windows-{version}"

    # Within each version there are specific AMIs depending on the underlying GPU hardware
    # TODO - This should eventually make use of proper InstanceType attributes when they are cached and available
    # TODO - For now - we will simply look at the name
    if instance_type.startswith("g") or instance_type.startswith("p"):
        _instance_family: str = instance_type.split(".")[0]
        if "a" in _instance_family:
            # AMD GPU
            logger.debug(f"AMD GPU detected by instance name")
            _search_string += "-AMD"
        else:
            # NVIDIA GPU
            logger.debug(f"NVIDIA GPU detected by instance name")
            _search_string += (
                "-NVIDIA"  # TODO - Avoid the 'NVIDIA-gaming-<version>' AMI
            )
    else:
        # Non-GPU
        logger.debug(f"No Hardware GPU detected by instance name")
        _search_string += "-DOD"

    _search_string += "*"
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(f"Using a final AMI search string of {_search_string}")

    # Since we may still get multiple responses - order them by the CreationDate for the most recent one
    try:
        ec2_paginator = client_ec2.get_paginator("describe_images")
        ec2_iterator = ec2_paginator.paginate(
            ExecutableUsers=["all"],
            Owners=owners,
            Filters=[
                {"Name": "name", "Values": [_search_string]},
                {
                    "Name": "architecture",
                    "Values": [
                        "x86_64"
                    ],  # For the moment Windows only support x86_64 arch
                },
            ],
        )

        _best_ami_id: str = ""
        _best_ami_date: datetime = datetime.min

        for _page in ec2_iterator:
            for _image in _page.get("Images", []):
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"Found potential AMI entry: {_image}")

                _image_id: str = _image.get("ImageId", "")
                _image_name: str = _image.get("Name", "")
                _image_date: datetime = parse(_image.get("CreationDate"))

                if _image_id == "":
                    logger.error(f"Invalid AMI entry: {_image}")
                    continue

                # TODO - Configurable?
                if "gaming" in _image_name.lower():
                    logger.debug(
                        f"Skipping NVIDIA gaming AMI: {_image_id}, Image Name: {_image_name}"
                    )
                    continue

                if _best_ami_id == "":
                    logger.debug(f"First AMI {_image_id} ({_image_date})")
                    _best_ami_id = _image_id
                    _best_ami_date = _image_date
                    continue

                # logger.debug(f"Comparing entry for Existing: {existing_ami_date} - New {ami_date}")
                if _image_date > _best_ami_date:
                    logger.debug(
                        f"Replacement AMI entry due to CreationDate: {_image_id} ({_image_date})  - Old: {_best_ami_id} ({_best_ami_date})"
                    )
                    _best_ami_id = _image_id
                    _best_ami_date = _image_date
                else:
                    # Our existing entry is better
                    pass

    except Exception as _e:
        logger.error(
            f"Error obtaining Windows DCV AMI for region {region} - Version {version} . Search_String: {_search_string} - Error: {_e}"
        )
        return ""

    logger.info(
        f"Returning best Windows DCV AMI ID for region: {region}, Version: {version}, Search_String: {_search_string} - AMI: {_best_ami_id} ({_best_ami_date})"
    )
    return _best_ami_id
