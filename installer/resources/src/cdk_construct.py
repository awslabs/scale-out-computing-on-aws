#!/usr/bin/env python3

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

"""
Do not trigger cdk deploy manually, Instead run ./soca_installer.sh.
All variables will be retrieved dynamically
"""
import shutil

from botocore.client import BaseClient

import cdk_construct_user_customization
from constructs import Construct
import os
import datetime
import typing
from aws_cdk import (
    Duration,
    Stack,
    App,
    Tags,
    Environment,
    Aws,
    CustomResource,
    CfnOutput,
    CfnDeletionPolicy,
    Fn,
    RemovalPolicy,
    aws_directoryservice as ds,
    aws_efs as efs,
    aws_ec2 as ec2,
    aws_globalaccelerator as globalaccelerator,
    aws_autoscaling as autoscaling,
    aws_opensearchservice as opensearch,
    aws_opensearchserverless as opensearchserverless,
    aws_elasticache as elasticache,
    aws_elasticloadbalancingv2 as elbv2,
    aws_elasticloadbalancingv2_targets as elbv2_targets,
    aws_events as events,
    aws_fsx as fsx,
    aws_lambda as aws_lambda,
    aws_logs as logs,
    aws_iam as iam,
    aws_backup as backup,
    aws_certificatemanager as acm,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_sns as sns,
    aws_route53resolver as route53resolver,
    aws_ssm as ssm,
    aws_kms as kms,
    CfnTag,
)

import json
import sys
import base64
import ast

from types import SimpleNamespace
from typing import Optional
import jinja2
from jinja2 import select_autoescape, FileSystemLoader

from helpers import (
    security_groups as security_groups_helper,
    secretsmanager as secretsmanager_helper,
    boto3_wrapper as boto3_helper,
    storage as storage_helper,
    user_data as user_data_helper,
)
import re
import pathlib
import logging
from rich.text import Text
from rich.table import Table
from rich.logging import RichHandler


# Note: cdk_construct.py is called via `cdk` CLI and not via install_soca.py, so we can't inherit the default logger and must create a new one
class CustomFormatter(logging.Formatter):
    def format(self, record):
        if not isinstance(record.msg, (Text, Table)):
            if record.levelno == logging.ERROR:
                record.msg = f"[bold red]{record.msg}[/bold red]"
            elif record.levelno == logging.WARNING:
                record.msg = f"[bold yellow]{record.msg} [/bold yellow]"
            elif record.levelno == logging.FATAL:
                record.msg = f"[bold red] FATAL {record.msg}[/bold red]"

        return super().format(record)


class CustomLogger(logging.getLoggerClass()):
    def fatal(self, msg, *args, **kwargs):
        self.critical(msg, *args, **kwargs)
        sys.exit(1)


_soca_debug = os.environ.get("SOCA_DEBUG", False)
if _soca_debug in ["1", "enabled", "true", "True", "on", "2", "trace"]:
    _log_level = logging.DEBUG
    _formatter = CustomFormatter("[%(asctime)s] %(levelname)s - %(message)s")
else:
    _log_level = logging.INFO
    _formatter = CustomFormatter("%(message)s")

_rich_handler = RichHandler(
    rich_tracebacks=True,
    markup=True,
    show_time=False,
    show_level=False,
    show_path=False,
)
_rich_handler.console.file = sys.stdout
_rich_handler.setFormatter(_formatter)

logging.basicConfig(level=_log_level, handlers=[_rich_handler])
logging.setLoggerClass(CustomLogger)
logging.root.manager.loggerDict.pop("soca_logger", None)
logger = logging.getLogger("soca_logger")

for _logger_name in ["boto3", "botocore"]:
    logging.getLogger(_logger_name).setLevel(
        logging.DEBUG if _soca_debug in {"trace", "2"} else logging.WARNING
    )


def get_lambda_runtime_version() -> aws_lambda.Runtime:
    return typing.cast(aws_lambda.Runtime, aws_lambda.Runtime.PYTHON_3_13)


def get_config_key(
    key_name: str,
    required: bool = True,
    default: typing.Any = None,
    expected_type: [str, int, float, bool, list, dict] = str,
) -> typing.Any:

    _result = install_props
    for key in key_name.split("."):
        _result = _result.get(key)
        if _result is None:
            break

    if required and _result is None:
        logger.fatal(f"{key_name} must be set but returned no value")

    if _result is None and default is not None:
        # logger.debug(f"Default specified as  [[ {default} ]] / Type: {type(default)} - Returning")
        return default
    else:
        # Empty result with no default - so we infer what the caller wants from the expected_type
        # and return a matching 'empty' that matches that type.
        # This makes sure that we return to the caller what they are expecting (e.g. a string) versus a NoneType.
        try:
            if _result is None:
                # logger.debug(
                #     f"Result lookup is empty - Expected {expected_type} for {key_name} / Returning empty equiv for the data type"
                # )
                if expected_type is str:
                    _ret_value: str = ""
                elif expected_type is int:
                    _ret_value: int = 0
                elif expected_type is float:
                    _ret_value: float = 0.0
                elif expected_type is bool:
                    _ret_value: bool = False
                elif expected_type is list:
                    _ret_value: list = []
                elif expected_type is dict:
                    _ret_value: dict = {}
                else:
                    # This shouldn't happen
                    logger.fatal(
                        f"Unsupported type passed to get_config_key(): {expected_type}"
                    )

                logger.debug(
                    f"Returning an empty equiv for key {key_name} - [[ {_ret_value} ]] / {type(_ret_value)}"
                )
                return _ret_value
            else:
                return expected_type(_result)
        except ValueError:
            logger.fatal(f"Expected {expected_type} for {key_name}")


def flatten_parameterstore_config(
    d: dict, parent_key: str = "", sep: str = "/"
) -> dict:
    _items = []
    for k, v in d.items():
        # Remove index number (/0, /1 etc ...) generated during the iterate process
        parent_key = re.sub(r"/\d+$|^\d+/", "", parent_key)
        # Create the new key, cast everything as string
        _new_key = f"{parent_key}{sep}{k}" if parent_key else str(k)
        if isinstance(v, dict):
            _items.extend(flatten_parameterstore_config(v, _new_key, sep=sep).items())
        elif isinstance(v, list):
            _items.append((_new_key, " ".join(v)))
        else:
            _items.append((_new_key, v))
    return dict(_items)


def get_subnet_route_table_by_subnet_id(subnet_ids: list) -> dict:
    """
    Return the route tables associated with a list of given subnets.
    The returned dict contains the subnetID and route-table IDs for those found.
    """
    _return_dict: dict = {}

    # Subnets to VPC lookup
    # Needed to resolve a subnet to a specific VPC-ID for the def route table
    # subnet-123 -> vpc-123
    _subnet_to_vpc: dict = {}

    # Store a mapping of VPCId to RTB ID for defaults
    # These do not explicitly show up in the return API as the default is a fallback
    # dict is simple lookup of:
    # vpc-123 -> rtb-123
    # This can therefore be applied to any subnets in vpc-123 that have not seen
    # explicit associations
    _default_rtb_id_by_vpc_id: dict = {}

    logger.debug(f"get_subnet_route_table_by_subnet_id() called with {subnet_ids=}")

    ec2_client = boto3_helper.get_boto(
        service_name="ec2",
        profile_name=user_specified_variables.profile,
        region_name=user_specified_variables.region,
    )

    # First - make sure we understand our subnets to VPC mappings

    logger.debug(f"Starting Subnet to VPC mapping lookup")
    _vpc_lu_paginator = ec2_client.get_paginator("describe_subnets")

    _vpc_lu_iterator = _vpc_lu_paginator.paginate(
        SubnetIds=subnet_ids
    )

    for _vpc_lu_i in _vpc_lu_iterator:
        logger.debug(f"Processing VPC LU: {_vpc_lu_i=}")
        for _vpc_lu_subnet in _vpc_lu_i.get("Subnets", []):
            _subnet_state: str = _vpc_lu_subnet.get("State", "")
            _subnet_vpc_id: str = _vpc_lu_subnet.get("VpcId", "")
            _subnet_subnet_id: str = _vpc_lu_subnet.get("SubnetId", "")

            if not _subnet_state:
                logger.fatal(f"Cannot determine subnet state for subnets {subnet_ids}")

            if not _subnet_vpc_id:
                logger.fatal(f"Cannot determine subnet VPC ids for subnets {subnet_ids}")

            if not _subnet_subnet_id:
                logger.fatal(f"Cannot determine subnet IDs for subnets {subnet_ids}")

            # Sanity
            if _subnet_state not in ["available"]:
                logger.warning(f"SubnetID {_subnet_subnet_id} in VPC {_subnet_vpc_id} - state ({_subnet_state}) is not available - skipping")
                continue

            logger.debug(f"Saving Subnet to VPC mapping of {_subnet_subnet_id} - {_subnet_vpc_id}")
            _subnet_to_vpc[_subnet_subnet_id] = _subnet_vpc_id

    logger.debug(f"Completed Subnet to VPC mapping lookup")

    # Grab the default route-tables for the VPCs
    # We need these for returns that don't have explicit associations

    _def_rtb_paginator = ec2_client.get_paginator("describe_route_tables")
    logger.debug(f"Scanning for VPC default route tables")
    _def_rtb_iterator = _def_rtb_paginator.paginate(
        Filters=[{"Name": "association.main", "Values": ['true']}]
    )
    for _rt_i in _def_rtb_iterator:
        for _rt in _rt_i.get("RouteTables", []):
            _vpc_id: str = _rt.get("VpcId", "")
            _owner_id: str = _rt.get("OwnerId", "")
            if not _vpc_id:
                logger.fatal(f"Unable to determine VPCId for Route Table entry")
            if not _owner_id:
                logger.fatal(f"Unable to determine OwnerID for Route Table entry")

            logger.debug(f"VPC {_vpc_id} / Owner {_owner_id}")

            for _associations in _rt.get("Associations", []):
                _rtb_id: str = _associations.get("RouteTableId", "")
                if not _rtb_id:
                    logger.fatal(f"Unable to determine RouteTableId for {_vpc_id}")

                if _associations.get("Main", False):
                    logger.debug(f"Default RTB VPC {_vpc_id} - {_rtb_id}")
                    _default_rtb_id_by_vpc_id[_vpc_id] = _rtb_id
                else:
                    logger.debug(f"VPC {_vpc_id} - Assoc {_associations=} . Non-Default. This can be normal.")


    # Now query the subnets we are actually interested in
    logger.debug(f"Querying route tables for subnets {subnet_ids=}")

    _rt_paginator = ec2_client.get_paginator("describe_route_tables")
    _rt_iterator = _rt_paginator.paginate(
        Filters=[{"Name": "association.subnet-id", "Values": subnet_ids}]
    )

    for _rt_i in _rt_iterator:
        logger.debug(f"Processing {_rt_i}")
        for _rt in _rt_i.get("RouteTables", []):
            logger.debug(f"Processing RouteTables {_rt=}")
            _rtb_id: str = _rt.get("RouteTableId", "")
            _vpc_id: str = _rt.get("VpcId", "")
            _owner_id: str = _rt.get("OwnerId", "")

            if not _vpc_id:
                logger.fatal(f"Unable to determine VPCId for Route Table entry")
            if not _owner_id:
                logger.fatal(f"Unable to determine OwnerID for Route Table entry")

            logger.debug(f"VPC {_vpc_id} / Owner {_owner_id}")

            for _associations in _rt.get("Associations", []):
                # SubnetIds only appear in explicit associations between the Route Tables and Subnets
                # The default route table may therefore apply to a subnet and not be explicitly listed
                # in the API return.
                # If we don't have an _rtb_id - assume that the subnet uses the default route table ID
                logger.debug(f"Scanning {_rtb_id=}")
                if not _rtb_id:
                    logger.debug(f"Performing lookup for default route table for {_vpc_id=}")
                    _def_rtb_id: str = _default_rtb_id_by_vpc_id.get(_vpc_id, "")

                    if not _def_rtb_id:
                        logger.fatal(f"Unable to find explicit route-table ID for subnet and no default exists for VPC {_vpc_id}")

                    _rtb_id = _def_rtb_id
                    logger.info(f"Using VPC {_vpc_id} default route table of {_rtb_id}")

                _subnet_id = _associations.get("SubnetId", "")
                if _subnet_id in subnet_ids:
                    if _subnet_id not in _return_dict:
                        _return_dict[_subnet_id] = _rtb_id
                    else:
                        logger.debug(
                            f"get_subnet_route_table_by_subnet_id() called with {subnet_ids=} / found duplicate subnet {_subnet_id=} in route table {_rtb_id}"
                        )
                else:
                    # The response came back for a subnetID we are not interested in?
                    logger.warning(
                        f"get_subnet_route_table_by_subnet_id() got information for {_subnet_id} - but I didnt ask for it!  Defect?"
                    )
                    continue

    # Sanity check - make sure we have a route table for each subnet and apply VPC default otherwise
    _missing_subnet_ids = [x for x in subnet_ids if x not in _return_dict.keys()]

    if _missing_subnet_ids:
        for _missing_subnet_id in _missing_subnet_ids:
            logger.debug(f"Trying to resolve default RTB for Subnet ID {_missing_subnet_id}")
            _vpc_def_rtb: str = _default_rtb_id_by_vpc_id.get(_subnet_to_vpc.get(_missing_subnet_id, ""), "")

            if not _vpc_def_rtb:
                logger.fatal(f"Unable to resolve Subnet route table information for {_missing_subnet_id}")
            _return_dict[_missing_subnet_id] = _vpc_def_rtb

        # logger.fatal(
        #     f"get_subnet_route_table_by_subnet_id() called with {subnet_ids=} / missing route table for {_missing_subnet_ids=}"
        # )

    logger.debug(
        f"get_subnet_route_table_by_subnet_id() called with {subnet_ids=} / returning {_return_dict=}"
    )
    return _return_dict


def get_arch_for_instance_type(region: str, instancetype: str) -> str:
    _found_arch = None
    logger.debug(
        f"get_arch_for_instance_type() called with {region=} / {instancetype=}"
    )
    ec2_client = boto3_helper.get_boto(
        service_name="ec2",
        profile_name=user_specified_variables.profile,
        region_name=user_specified_variables.region,
    )
    _resp = ec2_client.describe_instance_types(InstanceTypes=[instancetype])

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


def is_valid_backup_vault_arn(arn: str) -> bool:
    """
    Check if the provided ARN is a valid AWS Backup vault ARN
    """
    _backup_vault_arn_pattern = r"^arn:(aws|aws-us-gov|aws-cn):backup:[a-z0-9\-]+:[0-9]{12}:backup-vault:[a-zA-Z0-9\-]+$"
    return bool(re.match(_backup_vault_arn_pattern, arn))


def validate_kms_key_id(kms_client: BaseClient, key_id: str) -> [bool, str]:
    """
    Validate the KMS KeyID via the AWS API and return the ARN.
    This can take an ARN as the key_id or an alias name.
    """
    logger.debug(f"validate_kms_key_id() called with {kms_client=} / {key_id=}")

    if not key_id:
        logger.debug(f"No KMS key_id passed to is_valid_kms_key_id() - rejecting.")
        return False, ""
    if not kms_client:
        logger.fatal(
            f"No KMS client passed to is_valid_kms_key_id() - unable to continue. Probable code defect."
        )

    # If we are passed something that doesn't look like an ARN - fixup the name as it
    # is an alias lookup. E.g. 'MyEBSCMK' becomes 'alias/MyEBSCMK' for API calls.
    # This also covers AWS default keys. E.g. "aws/ebs" becomes "alias/aws/ebs"
    if is_arn_string(arn_string=key_id, arn_type="kms_key_id"):
        logger.debug(f"Looks like a KMS KeyID ARN: {key_id}")
    else:
        logger.debug(f"Alias KeyID: {key_id} -> alias/{key_id}")
        key_id = f"alias/{key_id}"

    try:
        _key_information = kms_client.describe_key(KeyId=key_id).get("KeyMetadata", {})
    # TODO - Add specific exceptions with proper errors/logging/returns
    except kms_client.exceptions.NotFoundException as e:
        logger.error(f"KMS KeyID: {key_id} not found: {e}")
        return False, ""
    except Exception as e:
        logger.error(f"Error performing KMS KeyID validation: {e}")
        return False, ""

    if _key_information:
        logger.debug(f"Found KMS KeyID: {key_id} - KeyInformation - {_key_information}")

        # Make sure the key is enabled
        # If it is not enabled - we purposely exit hard here versus assuming something
        # about encryption that could be incorrect. Never assume about security/encryption!
        if not _key_information.get("Enabled", False):
            logger.error(f"KMS KeyID: {key_id} is disabled. Unable to use this KeyID")
            return False
        else:
            logger.debug(f"KMS KeyID: {key_id} is enabled. Good.")

        # Enabled and ready to go
        _key_descr: str = _key_information.get("Description", "")
        _key_creation_str: str = str(_key_information.get("CreationDate", ""))
        _key_arn_str: str = _key_information.get("Arn", "")
        logger.debug(
            f"Acceptable KMS KeyID found: {key_id} - {_key_descr} - {_key_creation_str} - ARN: {_key_arn_str}"
        )
        return True, _key_arn_str


def is_arn_string(arn_string: str, arn_type: str = "") -> bool:
    """
    Check if the provided string is an ARN. Optionally with stricter enforcement for known ARN types (arn_type).
    """
    _service_arns: dict = {
        "kms_key_id": r"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|mrk-[0-9a-f]{32}|alias/[a-zA-Z0-9/_-]+|(arn:aws[-a-z]*:kms:[a-z0-9-]+:\d{12}:((key/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})|(key/mrk-[0-9a-f]{32})|(alias/[a-zA-Z0-9/_-]+))))$",
    }

    _re_pattern: str = ""
    if arn_type:
        logger.debug(f"Looking for specific ARN pattern for {arn_type}")
        _re_pattern = _service_arns.get(arn_type.lower(), "")
        if not _re_pattern:
            _re_pattern = "^arn:aws[-a-z]*:"
            logger.warning(
                f"No specific ARN pattern found for {arn_type} . Using basic ARN string validation: {_re_pattern}"
            )
        else:
            logger.debug(f"Using specific ARN pattern for {arn_type}: {_re_pattern}")

    else:
        _re_pattern = "^arn:aws[-a-z]*:"
        logger.debug(f"Performing basic ARN string validation: {_re_pattern}")

    return bool(re.match(pattern=_re_pattern, string=arn_string))


def return_ebs_volume_type(volume_string: str, fallback_volume: str = "gp2") -> str:
    """
    For a given string value of an EBS volume - return the proper CDK representation or the fallback volume.
    """
    logger.debug(
        f"Looking for EBS volume type: {volume_string} / Fallback: {fallback_volume}"
    )

    if not volume_string:
        logger.warning(
            f"No volume_string passed to return_ebs_volume_type() - probable defect"
        )
        if fallback_volume:
            volume_string = fallback_volume
        else:
            logger.fatal(
                f"No volume_string or fallback_volume passed to return_ebs_volume_type() - unable to continue. Probable code defect."
            )

    if not isinstance(volume_string, str):
        logger.fatal(
            f"volume_string must be a string - unable to continue. Probable code defect."
        )

    if not isinstance(fallback_volume, str):
        logger.fatal(
            f"fallback_volume must be a string - unable to continue. Probable code defect."
        )

    _ebs_volume_type_map = {
        "default": ec2.EbsDeviceVolumeType.GP3,
        "__fallback__": ec2.EbsDeviceVolumeType.GP2,  # Fallback is purposely kept at GP2
        "gp2": ec2.EbsDeviceVolumeType.GP2,
        "gp3": ec2.EbsDeviceVolumeType.GP3,
        "io1": ec2.EbsDeviceVolumeType.IO1,
        "io2": ec2.EbsDeviceVolumeType.IO2,
        "st1": ec2.EbsDeviceVolumeType.ST1,
        "sc1": ec2.EbsDeviceVolumeType.SC1,
        "standard": ec2.EbsDeviceVolumeType.GP3,  # Lies - but we don't want magnetic
    }
    # Fallback for our fallback
    _fallback_value = _ebs_volume_type_map.get(fallback_volume.lower())

    if not _fallback_value:
        _fallback_value = _ebs_volume_type_map.get("__fallback__")
        logger.warning(
            f"Invalid fallback value: {fallback_volume} - Defaulting to __fallback__: {_fallback_value}"
        )

    logger.debug(f"Looking for EBS volume type: {volume_string}")
    _volume_type = _ebs_volume_type_map.get(volume_string.lower(), _fallback_value)

    logger.debug(f"Returning {_volume_type}")

    return _volume_type


def get_kms_key_id(config_key_names: list, allow_global_default: bool = True) -> str:
    """
    Retrieve the KMS key ID (ARN) based on the provided key names from the config. If this key doesn't exist, check for the global KMS KeyID. If not - return an empty string.
    """
    _kms_client = boto3_helper.get_boto(
        service_name="kms",
        profile_name=user_specified_variables.profile,
        region_name=user_specified_variables.region,
    )
    _kms_key_id: str = ""
    _global_config_key_location: str = "Config.kms_key_id"

    # If we allow the global default - append it to the end of the list for ease of use
    # Since this is a 'first match wins' - it will be consulted in the last/lowest priority/fallback case.
    if allow_global_default:

        _global_key_id = get_config_key(
            key_name=_global_config_key_location,
            required=False,
            expected_type=str,
            default="",
        )
        logger.debug(
            f"Global KMS KeyID: {_global_key_id} /  Type: {type(_global_key_id)}"
        )
        if len(_global_key_id) > 0:
            if _global_config_key_location not in config_key_names:
                logger.debug(
                    f"Adding Global key ID location ({_global_config_key_location}) to list of key names to validate (allow_global_default) as it contains a valid entry ({_global_key_id})"
                )
                config_key_names.append(_global_config_key_location)
            else:
                # Warn the user - but it is non-fatal at this stage
                logger.warning(
                    f"Global KMS KeyID location ({_global_config_key_location}) is already in the list of config key names to validate. Check your configuration. Continuing anyway"
                )
        elif _global_key_id == "":
            logger.debug(
                f"Blank Global KMS KeyID found at {_global_config_key_location} for fallback."
            )
            config_key_names.append(_global_config_key_location)
    else:
        logger.warning(
            f"allow_global_default set to False. Skipping global default key ID check."
        )

    # No incoming configuration key list to validate
    # This only takes place when we are set for allow_global_default False and get an empty list of config keys to check
    if not config_key_names:
        logger.warning(
            f"No config_key_names passed to get_kms_key_id - returning empty"
        )
        return ""

    logger.debug(
        f"Looking for resource specific KMS KeyID: {config_key_names} / Allow Global Default: {allow_global_default}"
    )

    for _key_name in config_key_names:
        logger.debug(f"Determining KeyID validity: {_key_name}")

        _kms_key_id = get_config_key(
            key_name=_key_name, required=False, expected_type=str, default=""
        )

        if _kms_key_id == "" and _key_name == config_key_names[-1]:
            logger.debug(f"Last Empty KeyID found at {_key_name} - using defaults")
            break
        elif _kms_key_id == "":
            logger.debug(f"Empty KeyID found at {_key_name} - trying next entry")
            continue

        logger.debug(f"Preparing to API lookup keyID: {_kms_key_id}")
        _key_lu_result, _key_arn = validate_kms_key_id(
            kms_client=_kms_client, key_id=_kms_key_id
        )

        if _key_lu_result:
            logger.debug(
                f"Validated/Selected KeyID: {_key_name} /  {_kms_key_id} / ARN: {_key_arn}"
            )
            _kms_key_id = _key_arn
            break
        else:
            logger.warning(
                f"Invalid KeyID at {_key_name}  / {_kms_key_id}. Trying next entry"
            )
            continue

    # Exiting the for loop we should have a valid _kms_key_id

    logger.debug(f"Returning KMS KeyID: {_kms_key_id}")
    return _kms_key_id


class SOCAInstall(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        self.vpc_interface_endpoints = {}
        self.vpc_gateway_endpoints = {}
        self.tag_ec2_resource_lambda = None

        _template_dirs = [
            pathlib.Path.cwd().parent,  # for user_data folder
            pathlib.Path(
                f"{pathlib.Path.cwd()}/../../../source/soca/cluster_node_bootstrap/"  # for all templates
            ).resolve(),
        ]

        self.jinja2_env = jinja2.Environment(
            loader=FileSystemLoader(_template_dirs),
            extensions=["jinja2.ext.do"],
            autoescape=select_autoescape(
                enabled_extensions=("j2", "jinja2"),
                default_for_string=True,
                default=True,
            ),
        )

        # Init SOCA resources
        self.soca_resources = {
            "acm_certificate_lambda_role": None,
            "alb": None,
            "aoss_data_policy_lambda_role": None,
            "nlb": None,
            "alb_sg": None,
            "nlb_sg": None,
            "elasticache": None,
            "elasticache_sg": None,
            "backup_role": None,
            "custom_ami_map": {},
            "base_os": user_specified_variables.base_os,
            "compute_node_instance_profile": None,
            "compute_node_role": None,
            "compute_node_sg": None,
            "ami_id": None,
            "os_domain": None,
            "fs_apps": None,
            "efs_lambda_role": None,
            "fs_data": None,
            "get_es_private_ip_lambda_role": None,
            "login_node_sg": None,
            "nat_gateway_ips": [],
            "controller_eip": None,
            "controller_instance": None,
            "controller_role": None,
            "controller_sg": None,
            "spot_fleet_role": None,
            "solution_metrics_lambda_role": None,
            "vpc": None,
            "soca_secret": None,
            "soca_config": None,
        }
        self.soca_filesystems = {}

        self._base_os = user_specified_variables.base_os
        self._region = user_specified_variables.region
        self._partition = user_specified_variables.partition

        logger.debug(f"Creating SOCAInstall()")
        logger.debug(f"Base OS: {self._base_os}")
        logger.debug(f"Region: {self._region}")
        logger.debug(f"Partition: {self._partition}")

        _supported_base_os = get_config_key(
            key_name=f"Parameters.system.base_os.supported",
            required=True,
            expected_type=list,
        )
        _eol_base_os = get_config_key(
            key_name=f"Parameters.system.base_os.eol",
            required=True,
            expected_type=list,
        )
        # Store architectures as they may come in handy for jobs that differ from the Controller architecture
        # TODO - a bit of a hack
        for _arch in ["arm64", "x86_64"]:
            if _arch not in self.soca_resources["custom_ami_map"]:
                self.soca_resources["custom_ami_map"][_arch] = {}

            for _base_os_available in _eol_base_os + _supported_base_os:
                self.soca_resources[f"custom_ami_map"][_arch][_base_os_available] = (
                    ""
                    if not get_config_key(
                        key_name=f"RegionMap.{self._region}.{_arch}.{_base_os_available}",
                        required=False,
                    )
                    else get_config_key(
                        key_name=f"RegionMap.{self._region}.{_arch}.{_base_os_available}",
                        required=False,
                    )
                )

        # Determine our architecture base on controller
        # and our ami_id based on base_os/architecture
        # user_specified_variables.custom_ami

        _located_ami = None
        _instance_type: list = get_config_key(
            key_name="Config.controller.instance_type",
            expected_type=list,
            required=False,
            default=["m7i-flex.large", "m5.large"],
        )
        logger.debug(f"ControllerNode - Configured instance type: {_instance_type}")

        self._instance_type, self._instance_arch, _default_instance_ami = (
            self.select_best_instance(
                instance_list=_instance_type,
                region=user_specified_variables.region,
                fallback_instance="m5.large",
            )
        )

        logger.debug(
            f"ControllerNode - Selected instance type: { self._instance_type} / Arch: {self._instance_arch}"
        )

        #
        # Used later to store our ControllerEIP value (IP address)
        #
        self._controller_eip_value = None

        # Cache Info

        self.cache_info = {
            "enabled": get_config_key(
                key_name="Config.services.aws_elasticache.enabled",
                expected_type=bool,
                default=True,
                required=False,
            ),
            "engine": get_config_key(
                key_name="Config.services.aws_elasticache.engine", expected_type=str
            ),
            "port": None,
            "endpoint": None,
            "ttl": {
                "short": get_config_key(
                    key_name="Config.services.aws_elasticache.ttl.short",
                    expected_type=int,
                ),
                "long": get_config_key(
                    key_name="Config.services.aws_elasticache.ttl.long",
                    expected_type=int,
                ),
            },
        }
        # Our DS domain is used for route53 rule creation
        # This can be specified in the configuration as directoryservice.name - defaults to <cluster_id>.local
        _ds_domain_name = get_config_key(
            key_name="Config.directoryservice.domain_name",
            expected_type=str,
            required=False,
            default=f"{user_specified_variables.cluster_id}.local",
        ).lower()

        _ds_provider = get_config_key(
            key_name="Config.directoryservice.provider"
        ).lower()
        _use_existing_directory = False
        _endpoint = None

        if _ds_provider in {"existing_openldap", "existing_active_directory"}:
            _endpoint = get_config_key(
                key_name=f"Config.directoryservice.{_ds_provider}.endpoint",
                required=False,
                default=None,
            )
            _use_existing_directory = True

        self.directory_service_resource_setup = {
            "use_existing_directory": _use_existing_directory,
            "provider": _ds_provider,
            "domain_name": _ds_domain_name.lower(),
            "short_name": get_config_key(
                key_name="Config.directoryservice.short_name",
                expected_type=str,
                required=False,
                default=_ds_domain_name.split(".")[0].upper()[:15],
            ).upper(),
            "domain_base": get_config_key(
                key_name="Config.directoryservice.domain_base",
                expected_type=str,
                required=False,
                default=f"dc={',dc='.join(_ds_domain_name.split('.'))}".lower(),
            ).lower(),
            "endpoint": _endpoint.lower() if _endpoint is not None else _endpoint,
            "ad_aws_directory_service_id": False,
            "service_account_secret_arn": get_config_key(
                key_name=f"Config.directoryservice.{_ds_provider}.service_account_secret_name_arn",
                required=False,
                default=None,
            ),
            "domain_controller_ips": [],
        }

        # Retrieve Directory OU/CN settings based on config values
        # Default options that are created automatically by AWS DS and cannot be changed
        _aws_specific_default_value = {
            "aws_ds_simple_activedirectory": {
                "admins_search_base": f"{get_config_key(key_name=f'Config.directoryservice.aws_ds_simple_activedirectory.admins_search_base')},OU=Users,OU={self.directory_service_resource_setup.get('short_name')},{self.directory_service_resource_setup.get('domain_base')}",
                "people_search_base": f"cn=Users,{self.directory_service_resource_setup.get('domain_base')}",
                "group_search_base": f"cn=Users,{self.directory_service_resource_setup.get('domain_base')}",
            },
            "aws_ds_managed_activedirectory": {
                "admins_search_base": f"{get_config_key(key_name=f'Config.directoryservice.aws_ds_managed_activedirectory.admins_search_base')},OU=Users,OU={self.directory_service_resource_setup.get('short_name')},{self.directory_service_resource_setup.get('domain_base')}",
                "people_search_base": f"ou=Users,ou={self.directory_service_resource_setup.get('short_name')},{self.directory_service_resource_setup.get('domain_base')}",
                "group_search_base": f"ou=Users,ou={self.directory_service_resource_setup.get('short_name')},{self.directory_service_resource_setup.get('domain_base')}",
            },
        }

        if _ds_provider in _aws_specific_default_value.keys():
            self.directory_service_resource_setup["people_search_base"] = (
                _aws_specific_default_value[_ds_provider].get("people_search_base")
            )
            self.directory_service_resource_setup["group_search_base"] = (
                _aws_specific_default_value[_ds_provider].get("group_search_base")
            )
            self.directory_service_resource_setup["admins_search_base"] = (
                _aws_specific_default_value[_ds_provider].get("admins_search_base")
            )

        else:
            _admins_search_base = get_config_key(
                key_name=f"Config.directoryservice.{self.directory_service_resource_setup.get('provider')}.admins_search_base"
            ).lower()
            _people_search_base = get_config_key(
                key_name=f"Config.directoryservice.{self.directory_service_resource_setup.get('provider')}.people_search_base"
            ).lower()
            _group_search_base = get_config_key(
                key_name=f"Config.directoryservice.{self.directory_service_resource_setup.get('provider')}.group_search_base"
            ).lower()

            # People
            if (
                self.directory_service_resource_setup.get("domain_base")
                not in _people_search_base
            ):
                self.directory_service_resource_setup["people_search_base"] = (
                    f"{_people_search_base},{self.directory_service_resource_setup.get('domain_base')}"
                )
            else:
                self.directory_service_resource_setup["people_search_base"] = (
                    f"{_people_search_base}"
                )

            # Group
            if (
                self.directory_service_resource_setup.get("domain_base")
                not in _group_search_base
            ):
                self.directory_service_resource_setup["group_search_base"] = (
                    f"{_group_search_base},{self.directory_service_resource_setup.get('domain_base')}"
                )
            else:
                self.directory_service_resource_setup["group_search_base"] = (
                    f"{_group_search_base}"
                )

            # Admins
            if (
                self.directory_service_resource_setup.get("domain_base")
                not in _admins_search_base
            ):
                self.directory_service_resource_setup["admins_search_base"] = (
                    f"{_admins_search_base},{self.directory_service_resource_setup.get('domain_base')}"
                )
            else:
                self.directory_service_resource_setup["admins_search_base"] = (
                    f"{_admins_search_base}"
                )

        # Validate Directory Settings
        if (
            self._base_os in ("rhel8", "rhel9", "rocky8", "rocky9")
            and self.directory_service_resource_setup.get("provider") == "openldap"
        ):
            logger.fatal(
                f"{self._base_os} do not support openldap. Please use aws_ds_simple_activedirectory, aws_ds_managed_activedirectory or existing_openldap instead"
            )

        if self.directory_service_resource_setup.get("endpoint") is not None:
            if (
                re.match(
                    r"^(ldaps://|ldap://)",
                    self.directory_service_resource_setup.get("endpoint"),
                )
                is None
            ):
                logger.fatal(
                    f"Config.directoryservice.{_ds_provider}.use_existing_directory is set but does not start with ldaps:// or ldap://"
                )

        if (
            self.directory_service_resource_setup.get("use_existing_directory") is True
            and self.directory_service_resource_setup.get("service_account_secret_arn")
            is None
        ):
            logger.fatal(
                f"Config.directoryservice.{_ds_provider}.use_existing_directory is set to True but Config.directoryservice.service_account_secret_arn is not set"
            )

        if (
            self.directory_service_resource_setup.get("use_existing_directory") is None
            and self.directory_service_resource_setup.get("service_account_secret_arn")
            is not None
        ):
            logger.fatal(
                f"Config.directoryservice.{_ds_provider}.use_existing_directory is None but Config.directoryservice.service_account_secret_arn is set"
            )

        logger.debug(
            f"DS Environment Setup Name: {self.directory_service_resource_setup}"
        )

        # Validate Scheduler installation mechanism
        _scheduler_deployment_type = get_config_key("Config.scheduler.deployment_type")
        _scheduler_deployment_options = get_config_key(
            "Parameters.system.scheduler.openpbs", expected_type=dict
        )

        if _scheduler_deployment_type == "git":
            if (
                _scheduler_deployment_options.get(_scheduler_deployment_type).get(
                    "repo"
                )
                is None
            ):
                logger.fatal(
                    f"Parameters.system.scheduler.openpbs.{_scheduler_deployment_type}.repo is None but must be set since Config.scheduler.deployment_type is et to {_scheduler_deployment_type}"
                )

            if (
                _scheduler_deployment_options.get(_scheduler_deployment_type).get(
                    "version"
                )
                is None
            ):
                logger.fatal(
                    f"Parameters.system.scheduler.openpbs.{_scheduler_deployment_type}.version is None but must be set since Config.scheduler.deployment_type is et to {_scheduler_deployment_type}"
                )

        if _scheduler_deployment_type == "s3_tgz":
            if (
                _scheduler_deployment_options.get(_scheduler_deployment_type).get(
                    "s3_uri"
                )
                is None
            ):
                logger.fatal(
                    f"Parameters.system.scheduler.openpbs.{_scheduler_deployment_type}.s3_uri is None but must be set since Config.scheduler.deployment_type is et to {_scheduler_deployment_type}"
                )

            if (
                _scheduler_deployment_options.get(_scheduler_deployment_type).get(
                    "version"
                )
                is None
            ):
                logger.fatal(
                    f"Parameters.system.scheduler.openpbs.{_scheduler_deployment_type}.version is None but must be set since Config.scheduler.deployment_type is et to {_scheduler_deployment_type}"
                )

        _apps_provider = user_specified_variables.fs_apps_provider
        _data_provider = user_specified_variables.fs_data_provider

        if self.directory_service_resource_setup.get("provider") in [
            "openldap",
            "existing_openldap",
        ]:
            for fs_provider in [_apps_provider, _data_provider]:
                if fs_provider == "fsx_ontap":
                    logger.fatal(
                        f"Config.storage.apps.provider and/or Config.storage.data.provider are set to fsx_ontap but Config.directoryservice.provider is not ActiveDirectory. AD is required for FSx ONTAP"
                    )

        # The actual AMI ID for the controller (based on our selected instance_type)
        # print(f"DEBUG: Trying to resolve the AMI from the AMI - Arch: {_instance_arch} . BaseOS: {_base_os}")
        # print(f"DEBUG: AMI RegionMap: {self.soca_resources['custom_ami_map']}")

        self.soca_resources["ami_id"] = (
            self.soca_resources["custom_ami_map"]
            .get(self._instance_arch, "x86_64")
            .get(self._base_os, "amazonlinux2")
        )

        # Resolve our secretsmanager key for future use
        _sm_key_id: str = get_kms_key_id(
            config_key_names=[
                "Config.secretsmanager.kms_key_id",  # Current configuration for kms_key_id
            ],
            allow_global_default=True,
        )

        logger.debug(f"Resolved SecretsManager KMS Key ID configuration: {_sm_key_id}")
        self.soca_resources["secretsmanager_kms_key_id"] = (
            kms.Key.from_key_arn(self, id="SecretsManagerKMSKey", key_arn=_sm_key_id)
            if _sm_key_id
            else None
        )
        logger.debug(
            f"Resolved SecretsManager KMS Key ID: {_sm_key_id} : {self.soca_resources['secretsmanager_kms_key_id']}"
        )

        # Create SOCA environment
        self.generic_resources()
        self.network()  # Create Network environment
        self.security_groups()  # Create Security Groups
        self.iam_roles()  # Create IAM roles and policies for primary roles needed to deploy resources
        if get_config_key(
            key_name="Config.network.use_vpc_endpoints",
            expected_type=bool,
            required=False,
        ):
            self.create_vpc_endpoints()

        if get_config_key(
            key_name="Config.services.aws_elasticache.enabled",
            expected_type=bool,
            default=True,
            required=False,
        ):
            self.elasticache()  # Create ElastiCache backend (deps: subnets, SGs)

        if (
            get_config_key(
                key_name="Config.analytics.enabled",
                expected_type=bool,
                default=True,
                required=False,
            )
            is True
        ):
            self.analytics()  # Create Analytics domain

        self.directory_service()  # Create Directory Service (any flavor)

        self.storage()  # Create Storage

        self.controller()  # Configure the Controller

        if get_config_key(
            key_name="Config.dcv.high_scale",
            expected_type=bool,
            default=False,
            required=False,
        ):
            logger.debug(
                f"Configuring DCV High-Scale Deployment due to Config.dcv.high_scale==True"
            )
            # Configure HA / high-scale DCV infrastructure
            self.dcv_infrastructure()

        self.viewer()  # Configure the DCV Load Balancer
        self.login_nodes()  # Configure the Login Nodes

        # Determine AGA configuration status
        _alb_public_bool: bool = (
            True
            if get_config_key(
                key_name="Config.entry_points_subnets",
                expected_type=str,
                default="public",
                required=False,
            ).lower()
            == "public"
            else False
        )

        if _alb_public_bool and get_config_key(
            key_name="Config.network.aws_aga.enabled",
            expected_type=bool,
            default=False,
            required=False,
        ):
            logger.debug(f"AGA is enabled, configuring it")
            self.configure_aws_aga()
        else:
            logger.debug(f"AGA is not enabled, skipping it")

        if get_config_key(
            key_name="Config.services.aws_pcs.enabled",
            expected_type=bool,
            required=False,
            default=False,
        ):
            self.aws_pcs()

        self.configuration()  # Store SOCA config

        if get_config_key(
            key_name="Config.services.aws_backup.enabled",
            expected_type=bool,
            required=False,
            default=True,
        ):
            self.backups()  # Configure AWS Backup & Restore
        else:
            logger.warning("AWS Backup integration is disabled per configuration")

        # User customization (Post Configuration)
        cdk_construct_user_customization.main(self, self.soca_resources)

        CfnOutput(
            self,
            "StackName",
            value=f"{Aws.STACK_NAME}",
        )

    def generic_resources(self):
        # Tag EC2 resources that don't support tagging in cloudformation
        self.tag_ec2_resource_lambda = aws_lambda.Function(
            self,
            f"{user_specified_variables.cluster_id}-TagEC2ResourceLambda",
            function_name=f"{user_specified_variables.cluster_id}-TagEC2Resource",
            description="Tag EC2 resource that doesn't support tagging in CloudFormation",
            memory_size=128,
            runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
            timeout=Duration.minutes(1),
            log_retention=logs.RetentionDays.INFINITE,
            handler="TagEC2ResourceLambda.lambda_handler",
            code=aws_lambda.Code.from_asset("../functions/TagEC2ResourceLambda"),
        )

        self.tag_ec2_resource_lambda.add_to_role_policy(
            statement=iam.PolicyStatement(
                effect=iam.Effect.ALLOW, actions=["ec2:CreateTags"], resources=["*"]
            )
        )

    def network(self):
        """
        Create a VPC with 3 public and 3 private subnets.
        To save IP space, public subnets have a smaller range compared to private subnets (where we deploy compute node)

        Example: vpc_cidr: 10.0.0.0/17 --> vpc_cidr_prefix_bits = 17
        public_subnet_mask_prefix_bits = 4
        private_subnet_mask_prefix_bits = 2
        public_subnet_mask = 17 + 4 = 21
        Added condition to reduce size of public_subnet_mask to a maximum of /26
        private_SubnetMask = 17 + 2 = 19
        """
        if not user_specified_variables.vpc_id:
            vpc_cidr_prefix_bits = user_specified_variables.vpc_cidr.split("/")[1]
            public_subnet_mask_prefix_bits = 4
            private_subnet_mask_prefix_bits = 2
            public_subnet_mask = int(vpc_cidr_prefix_bits) + int(
                public_subnet_mask_prefix_bits
            )
            if public_subnet_mask < 26:
                public_subnet_mask = 26
            private_subnet_mask = int(vpc_cidr_prefix_bits) + int(
                private_subnet_mask_prefix_bits
            )

            vpc_params = {
                "ip_addresses": ec2.IpAddresses.cidr(user_specified_variables.vpc_cidr),
                "nat_gateways": get_config_key(
                    key_name="Config.network.nat_gateways", expected_type=int
                ),
                "enable_dns_support": True,
                "enable_dns_hostnames": True,
                "max_azs": get_config_key(
                    key_name="Config.network.max_azs", expected_type=int
                ),
                "subnet_configuration": [
                    ec2.SubnetConfiguration(
                        cidr_mask=public_subnet_mask,
                        name="Public",
                        subnet_type=ec2.SubnetType.PUBLIC,
                    ),
                    ec2.SubnetConfiguration(
                        cidr_mask=private_subnet_mask,
                        name="Private",
                        subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS,
                    ),
                ],
            }
            self.soca_resources["vpc"] = ec2.Vpc(self, "SOCAVpc", **vpc_params)
            Tags.of(self.soca_resources["vpc"]).add(
                "Name", f"{user_specified_variables.cluster_id}-VPC"
            )

            # Retrieve all NAT Gateways associated to the public subnets.
            for subnet_info in self.soca_resources["vpc"].public_subnets:
                logger.debug(
                    f"NAT PROCESSING - processing {subnet_info=} / {type(subnet_info)}"
                )
                nat_eip_for_subnet = subnet_info.node.try_find_child("EIP")
                if nat_eip_for_subnet:
                    logger.debug(
                        f"NAT PROCESSING - FOUND EIP - {nat_eip_for_subnet=} / Appending"
                    )
                    self.soca_resources["nat_gateway_ips"].append(
                        nat_eip_for_subnet.attr_public_ip
                    )

        else:
            logger.debug(f"Using existing VPC and subnets for connectivity")
            # Use existing VPC
            public_subnet_ids = []
            private_subnet_ids = []
            # Note: syntax is ["subnet1,az1","subnet2,az2" ....]
            for pub_subnet in user_specified_variables.public_subnets:
                logger.debug(f"Adding Public subnet: {pub_subnet}")
                public_subnet_ids.append(pub_subnet.split(",")[0])
            for priv_subnet in user_specified_variables.private_subnets:
                logger.debug(f"Adding Private subnet: {priv_subnet}")
                private_subnet_ids.append(priv_subnet.split(",")[0])

            logger.debug(
                f"Complete subnet listings:  Public: {public_subnet_ids} / Private: {private_subnet_ids}"
            )
            # self.soca_resources["vpc"] = ec2.Vpc.from_vpc_attributes(
            self.soca_resources["vpc"] = ec2.Vpc.from_lookup(
                self,
                "SOCAVpc",
                vpc_id=user_specified_variables.vpc_id,
            )

            # # Check the VPC for DNS support
            # logger.debug(f"VPC DNS Support: {self.soca_resources['vpc'].dns_support_enabled}")
            # logger.debug(f"VPC DNS Hostname Support: {self.soca_resources['vpc'].dns_hostnames_enabled}")
            #
            # if not self.soca_resources["vpc"].dns_support_enabled or not self.soca_resources["vpc"].dns_hostnames_enabled:
            #     logger.error(f"SOCA requires VPCs to have DNS and DNS hostname supported enabled. Update VPC ({user_specified_variables.vpc_id}) and try again. Unable to continue.")
            #     sys.exit(1)

            #
            # Retrieve all NAT Gateways associated to the public subnets of our existing VPC
            #
            ec2_client = boto3_helper.get_boto(
                service_name="ec2",
                profile_name=user_specified_variables.profile,
                region_name=user_specified_variables.region,
            )
            logger.debug(f"Probing NAT / EIP for egress ACL allowances ...")
            logger.debug(
                f"Processing Public subnet for NAT lookup: {public_subnet_ids}"
            )

            _nat_gw_pager = ec2_client.get_paginator("describe_nat_gateways")
            _nat_gw_iter = _nat_gw_pager.paginate(
                Filters=[
                    {
                        "Name": "vpc-id",
                        "Values": [user_specified_variables.vpc_id],
                    },
                    {
                        "Name": "subnet-id",
                        "Values": [
                            _sn
                            for _subnet_list in [public_subnet_ids, private_subnet_ids]
                            for _sn in _subnet_list
                        ],
                    },
                ]
            )

            # Are we looking for public or private NATs?
            _nat_is_public: bool = (
                True
                if get_config_key(
                    key_name="Config.entry_points_subnets",
                    expected_type=str,
                    default="public",
                    required=False,
                ).lower()
                == "public"
                else False
            )
            logger.debug(f"Looking for public NATs: {_nat_is_public}")

            for _page in _nat_gw_iter:
                for _nat_gw_info in _page.get("NatGateways", []):
                    logger.debug(f"Existing NAT GW Info: {_nat_gw_info}")

                    _nat_gw_id: str = _nat_gw_info.get("NatGatewayId", "")
                    _nat_gw_state: str = _nat_gw_info.get("State", "")
                    _nat_gw_type: str = _nat_gw_info.get("ConnectivityType", "")

                    # Shouldn't need to check the VPC/subnet IDs since we use a filter for the query

                    if not _nat_gw_id or not _nat_gw_state or not _nat_gw_type:
                        logger.debug(
                            f"Skipping NAT GW: {_nat_gw_info} due to missing ID, state, or type from API call"
                        )
                        continue

                    if _nat_gw_state not in {"available"}:
                        logger.debug(
                            f"Skipping NAT GW: {_nat_gw_info} due to undesired state: {_nat_gw_state}"
                        )
                        continue

                    for _addresses in _nat_gw_info.get("NatGatewayAddresses", ""):
                        logger.debug(f"Processing Address spec: {_addresses}")
                        _public_ip: str = _addresses.get("PublicIp", "")
                        _private_ip: str = _addresses.get("PrivateIp", "")
                        _ip_status: str = _addresses.get("Status", "")

                        # Only stable NATs are allowed
                        if _ip_status not in {"succeeded"}:
                            logger.debug(
                                f"Skipping NAT IP: {_addresses} due to undesired status: {_ip_status}"
                            )
                            continue

                        # Check the IPs
                        if not _private_ip:
                            logger.debug(
                                f"Found EIP: {_public_ip} and Private IP: {_private_ip} for NAT GW: {_nat_gw_info}"
                            )
                            continue

                        if _nat_is_public:
                            if _public_ip:
                                logger.debug(
                                    f"Found Public NAT: {_public_ip} for NAT GW: {_nat_gw_info}"
                                )
                                if (
                                    _public_ip
                                    not in self.soca_resources["nat_gateway_ips"]
                                ):
                                    logger.debug(
                                        f"Adding Public EIP: {_public_ip} to list of NAT GW IPs"
                                    )
                                    self.soca_resources["nat_gateway_ips"].append(
                                        _public_ip
                                    )
                        else:
                            if _private_ip:
                                logger.debug(
                                    f"Found Private NAT: {_private_ip} for NAT GW: {_nat_gw_info}"
                                )
                                if (
                                    _private_ip
                                    not in self.soca_resources["nat_gateway_ips"]
                                ):
                                    logger.debug(
                                        f"Adding Private IP: {_private_ip} to list of NAT GW IPs"
                                    )
                                    self.soca_resources["nat_gateway_ips"].append(
                                        _private_ip
                                    )

            logger.debug(
                f"Final list of NAT GW EIP/IPs: {self.soca_resources['nat_gateway_ips']} / {_nat_is_public=}"
            )

    def elasticache(self):
        """
        Deploy AWS ElastiCache for SOCA Controller.
        """

        _supported_cache_engines: set[str] = {"valkey", "redis"}
        if not user_specified_variables.vpc_id:
            _launch_subnets = [
                self.soca_resources["vpc"].private_subnets[0].subnet_id,
                self.soca_resources["vpc"].private_subnets[1].subnet_id,
            ]
        else:
            _launch_subnets = [
                user_specified_variables.private_subnets[0].split(",")[0],
                user_specified_variables.private_subnets[1].split(",")[0],
            ]

        _cache_engine = get_config_key(
            key_name="Config.services.aws_elasticache.engine",
            required=False,
            default="valkey",
        )
        if _cache_engine not in _supported_cache_engines:
            logger.fatal(
                f"Unsupported option for Config.services.aws_elasticache.engine. Specify one of {', '.join(_supported_cache_engines)} ."
            )

        if _cache_engine in {"redis", "valkey"}:
            self.soca_resources["cache_admin_user_secret"] = (
                secretsmanager_helper.create_secret(
                    scope=self,
                    construct_id="CacheAdminUserSecret",
                    secret_name=f"/soca/{user_specified_variables.cluster_id}/CacheAdminUser",
                    secret_string_template='{"username": "default"}',  # soca-adminuser is the default user
                    kms_key_id=(
                        self.soca_resources["secretsmanager_kms_key_id"]
                        if self.soca_resources["secretsmanager_kms_key_id"]
                        else None
                    ),
                )
            )

            # soca-adminuser is known as default user per https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/Clusters.RBAC.html
            self.soca_resources["cache_readonly_user_secret"] = (
                secretsmanager_helper.create_secret(
                    scope=self,
                    construct_id="CacheReadOnlySecret",
                    secret_name=f"/soca/{user_specified_variables.cluster_id}/CacheReadOnlyUser",
                    secret_string_template='{"username": "soca-readonlyuser"}',
                    kms_key_id=(
                        self.soca_resources["secretsmanager_kms_key_id"]
                        if self.soca_resources["secretsmanager_kms_key_id"]
                        else None
                    ),
                )
            )

            _cache_readonly_user = elasticache.CfnUser(
                self,
                "SOCACacheReadOnlyUser",
                user_id=f"soca-{user_specified_variables.cluster_id.lower()}-readonlyuser",
                user_name="soca-readonlyuser",
                engine="redis",
                passwords=[
                    self.soca_resources["cache_readonly_user_secret"]
                    .secret_value_from_json("password")
                    .to_string()
                ],
                access_string="on ~* +@read",
                no_password_required=False,
            )

            # Username must be default. https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/Clusters.RBAC.html
            _cache_admin_user = elasticache.CfnUser(
                self,
                "SOCACacheAdminUser",
                user_id=f"soca-{user_specified_variables.cluster_id.lower()}-adminuser",
                user_name="default",
                engine="redis",
                passwords=[
                    self.soca_resources["cache_admin_user_secret"]
                    .secret_value_from_json("password")
                    .to_string()
                ],
                access_string="on ~* +@all",
                no_password_required=False,
            )

            # Associate users with the Redis cluster
            # Node: default user will automatically be removed via user-data.
            # `default` user must be part of CfnUserGroup
            _redis_user_group = elasticache.CfnUserGroup(
                self,
                "SOCACacheUser",
                engine="redis",
                user_group_id=f"socausers-{user_specified_variables.cluster_id.lower()}",
                user_ids=[
                    _cache_admin_user.user_id,
                    _cache_readonly_user.user_id,
                ],
            )
            _redis_user_group.node.add_dependency(_cache_admin_user)
            _redis_user_group.node.add_dependency(_cache_readonly_user)

            _kms_key_id = get_kms_key_id(
                config_key_names=[
                    "Config.services.aws_elasticache.kms_key_id",  # Current config key
                ],
                allow_global_default=True,
            )

            if _kms_key_id is not None:
                _redis_user_group.kms_key_id = _kms_key_id

            # Not support in all regions/partitions so we guard with self._partition
            _cache_usage_limits = elasticache.CfnServerlessCache.CacheUsageLimitsProperty(
                data_storage=elasticache.CfnServerlessCache.DataStorageProperty(
                    unit="GB",
                    minimum=get_config_key(
                        key_name="Config.services.aws_elasticache.limits.memory.min",
                        required=False,
                        expected_type=int,
                        default=2,
                    ),
                    maximum=get_config_key(
                        key_name="Config.services.aws_elasticache.limits.memory.max",
                        required=False,
                        expected_type=int,
                        default=24,
                    ),
                ),
                ecpu_per_second=elasticache.CfnServerlessCache.ECPUPerSecondProperty(
                    minimum=get_config_key(
                        key_name="Config.services.aws_elasticache.limits.ecpu.min",
                        required=False,
                        expected_type=int,
                        default=1000,
                    ),
                    maximum=get_config_key(
                        key_name="Config.services.aws_elasticache.limits.ecpu.max",
                        required=False,
                        expected_type=int,
                        default=1000,
                    ),
                ),
            )

            self.soca_resources["elasticache"] = elasticache.CfnServerlessCache(
                self,
                "ElastiCache",
                engine=_cache_engine,
                kms_key_id=_kms_key_id if _kms_key_id else None,
                major_engine_version="7",  #  TODO Engine version from Config
                serverless_cache_name=f"{user_specified_variables.cluster_id.lower()}-cache",  # FIXME TODO - sanitize/check
                description=f"{user_specified_variables.cluster_id.lower()}-cache",
                security_group_ids=[
                    self.soca_resources["elasticache_sg"].security_group_id
                ],
                subnet_ids=_launch_subnets,
                user_group_id=_redis_user_group.user_group_id,
                cache_usage_limits=(
                    _cache_usage_limits if self._partition in {"aws"} else None
                ),
            )

            self.soca_resources["elasticache"].node.add_dependency(_redis_user_group)
            self.soca_resources["elasticache"].node.add_dependency(
                self.soca_resources["vpc"]
            )

            # Flatten Cache
            self.cache_info["port"] = self.soca_resources[
                "elasticache"
            ].attr_endpoint_port
            self.cache_info["endpoint"] = self.soca_resources[
                "elasticache"
            ].attr_endpoint_address

    def dcv_infra_security_groups(self):
        """
        Create DCV Infrastructure security groups when Config.dcv.high_scale == True
        """
        logger.debug(
            f"in dcv_infra_security_groups() - Creating SGs for DCV High Scale ..."
        )

        for _dcv_node_type in {"broker", "gateway", "manager"}:
            # FIXME TODO - Narrow down to specific ports for each app
            print(f"Adding NLB all traffic rule for {_dcv_node_type}")
            security_groups_helper.create_ingress_rule(
                security_group=self.soca_resources[f"dcv_{_dcv_node_type}_sg"],
                peer=self.soca_resources["nlb_sg"],
                connection=ec2.Port.all_traffic(),
                description=f"Allow ELB to DCV {_dcv_node_type}",
            )

            logger.debug(f"Adding all traffic rule for intra-{_dcv_node_type}")
            # FIXME TODO - Narrow down to specific ports for each app
            security_groups_helper.create_ingress_rule(
                security_group=self.soca_resources[f"dcv_{_dcv_node_type}_sg"],
                peer=self.soca_resources[f"dcv_{_dcv_node_type}_sg"],
                connection=ec2.Port.all_traffic(),
                description=f"Allow intra-{_dcv_node_type} communications",
            )

        # Now our specific role rules
        # Broker
        # Gateway-to-Broker
        # FIXME TODO - Narrow down to specific ports for each app
        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources[f"dcv_broker_sg"],
            peer=self.soca_resources[f"dcv_gateway_sg"],
            connection=ec2.Port.all_traffic(),
            description=f"Allow DCV gateway to broker",
        )
        # Gateway

        # Manager

    def security_groups(self):
        """
        Create security groups (or re-use existing ones).
        """
        _security_groups = {
            "compute_node_sg": {
                "name": f"{user_specified_variables.cluster_id}-ComputeNodeSG",
                "description": "Security Group used for all compute nodes",
                "existing_security_group_id": (
                    user_specified_variables.compute_node_sg
                    if user_specified_variables.compute_node_sg
                    else None
                ),
                "allow_all_outbound": False,
            },
            "alb_sg": {
                "name": f"{user_specified_variables.cluster_id}-ALBFrontendSG",
                "description": "Security Group used by ALB frontend",
                "existing_security_group_id": (
                    user_specified_variables.alb_sg
                    if user_specified_variables.alb_sg
                    else None
                ),
                "allow_all_outbound": True,
            },
            "nlb_sg": {
                "name": f"{user_specified_variables.cluster_id}-NLBSG",
                "description": "Security Group used by NLB",
                "existing_security_group_id": (
                    user_specified_variables.nlb_sg
                    if user_specified_variables.nlb_sg
                    else None
                ),
                "allow_all_outbound": True,
            },
            "controller_sg": {
                "name": f"{user_specified_variables.cluster_id}-ControllerSG",
                "description": "Security Group used by Controller node",
                "existing_security_group_id": (
                    user_specified_variables.controller_sg
                    if user_specified_variables.controller_sg
                    else None
                ),
                "allow_all_outbound": True,
            },
            "login_node_sg": {
                "name": f"{user_specified_variables.cluster_id}-LoginNodeSG",
                "description": "Security Group used by Login node",
                "existing_security_group_id": (
                    user_specified_variables.login_node_sg
                    if user_specified_variables.login_node_sg
                    else None
                ),
                "allow_all_outbound": True,
            },
            "vpc_endpoint_sg": {
                "name": f"{user_specified_variables.cluster_id}-VPCEndpointSG",
                "description": "Security Group used by VPC Endpoints",
                "existing_security_group_id": (
                    user_specified_variables.vpc_endpoint_sg
                    if user_specified_variables.vpc_endpoint_sg
                    else None
                ),
                "allow_all_outbound": True,
            },
            "elasticache_sg": {
                "name": f"{user_specified_variables.cluster_id}-ElastiCacheSG",
                "description": "Security Group used by ElastiCache",
                "existing_security_group_id": (
                    user_specified_variables.elasticache_sg
                    if user_specified_variables.elasticache_sg
                    else None
                ),
                "allow_all_outbound": True,
            },
        }

        logger.debug(f"User spec vars: {user_specified_variables}")
        if get_config_key(
            key_name="Config.dcv.high_scale",
            expected_type=bool,
            required=False,
            default=False,
        ):
            logger.debug(f"DCV High Scale SG skeleton creation ..")
            for _dcv_host_type in ("broker", "gateway", "manager"):
                logger.debug(f"DCV High Scale SG skeleton for {_dcv_host_type}..")
                _security_groups[f"dcv_{_dcv_host_type}_sg"] = {
                    "name": f"{user_specified_variables.cluster_id}-{_dcv_host_type}_sg",
                    "description": f"Security Group for DCV-{_dcv_host_type}",
                    "existing_security_group_id": get_config_key(
                        key_name=f"Config.dcv.{_dcv_host_type}.security_group_id",
                        required=False,
                        expected_type=str,
                        default=None,
                    ),
                    "allow_all_outbound": True,
                }

        for sg_name, sg_data in _security_groups.items():
            logger.debug(f"SG - processing: {sg_name}: Data: {sg_data}")
            if sg_data["existing_security_group_id"]:
                self.soca_resources[sg_name] = (
                    security_groups_helper.use_existing_security_group(
                        scope=self,
                        construct_id=sg_data["name"],
                        security_group_id=sg_data["existing_security_group_id"],
                    )
                )
            else:
                self.soca_resources[sg_name] = (
                    security_groups_helper.create_security_groups(
                        scope=self,
                        construct_id=sg_data.get("name", "NoName"),
                        vpc=self.soca_resources["vpc"],
                        allow_all_outbound=sg_data.get("allow_all_outbound", True),
                        description=sg_data.get("description", "NoDescr"),
                    )
                )
            # Set Friendly Name tag and don't use the one generated by CDK
            Tags.of(self.soca_resources[sg_name]).add("Name", sg_data["name"])

        # CREATE SECURITY GROUP RULES

        #
        ## LOGIN from the customer IP
        #
        _login_node_ssh_front_port: int = get_config_key(
            key_name="Config.login_node.security.ssh_frontend_port",
            expected_type=int,
            default=22,
            required=False,
        )

        _login_node_ssh_back_port: int = get_config_key(
            key_name="Config.login_node.security.ssh_backend_port",
            expected_type=int,
            default=22,
            required=False,
        )

        logger.debug(
            f"Configuring LoginNode SG with SSH ports:  FrontEnd: {_login_node_ssh_front_port} / BackEnd: {_login_node_ssh_back_port}"
        )

        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["login_node_sg"],
            peer=ec2.Peer.ipv4(user_specified_variables.client_ip),
            connection=ec2.Port.tcp(_login_node_ssh_front_port),
            description="Allow SSH access from customer IP",
        )
        #
        # NLB Healthchecks on the SSH port
        #
        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["login_node_sg"],
            peer=self.soca_resources["nlb_sg"],
            connection=ec2.Port.tcp(_login_node_ssh_back_port),
            description="Allow NLB health checks",
        )
        #
        # The customer prefix-list
        #
        if user_specified_variables.prefix_list_id:
            logger.debug("Configuring LoginNode SG with customer prefix-list")
            logger.debug(f"Prefix list ID: {user_specified_variables.prefix_list_id}")
            for _sg in {"login_node_sg", "nlb_sg"}:
                logger.debug(f"Adding prefix list rule to {_sg}")
                security_groups_helper.create_ingress_rule(
                    security_group=self.soca_resources[_sg],
                    peer=ec2.Peer.prefix_list(user_specified_variables.prefix_list_id),
                    connection=ec2.Port.tcp(_login_node_ssh_front_port),
                    description="Allow SSH access from customer prefix list",
                )

        if get_config_key("Config.directoryservice.provider") in {
            "aws_ds_managed_activedirectory",
            "aws_ds_simple_activedirectory",
            "existing_active_directory",
        }:
            security_groups_helper.create_ingress_rule(
                security_group=self.soca_resources["login_node_sg"],
                peer=ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block),
                connection=ec2.Port.udp_range(0, 1024),
                description="Allow all UDP traffic from VPC to login node. Required for Directory Service",
            )

            security_groups_helper.create_egress_rule(
                security_group=self.soca_resources["login_node_sg"],
                peer=ec2.Peer.ipv4("0.0.0.0/0"),
                connection=ec2.Port.udp_range(0, 1024),
                description="Allow all Egress UDP traffic for login node SG. Required for Directory Service",
            )

        # COMPUTE/DCV
        # Ingress
        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["compute_node_sg"],
            peer=self.soca_resources["compute_node_sg"],
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic between compute node SG members (required for EFA)",
        )

        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["compute_node_sg"],
            peer=ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block),
            connection=ec2.Port.tcp_range(0, 65535),
            description="VPC - allow all TCP traffic from VPC to compute nodes",
        )

        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["compute_node_sg"],
            peer=self.soca_resources["controller_sg"],
            connection=ec2.Port.tcp_range(0, 65535),
            description="Allow all traffic from Controller host",
        )

        # FIXME - TODO - ComputeNode custom SSH port via config
        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["compute_node_sg"],
            peer=self.soca_resources["login_node_sg"],
            connection=ec2.Port.tcp(22),
            description="Allow SSH from login node",
        )

        # Egress is explicitly done so that we can activate EFA for this SG
        logger.debug(f"Creating EFA traffic egress rule")
        security_groups_helper.create_egress_rule(
            security_group=self.soca_resources["compute_node_sg"],
            peer=self.soca_resources["compute_node_sg"],
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic between compute node SG members (required for EFA)",
        )
        # Rest of Egress
        # This cannot be done as CDK complains that allowAllOutbound should be set for true
        # But this does not allow us to create egress rule entry - which prevents EFA from working correctly.
        # Instead - we must use a CDK escape hatch to manually create the rule
        # 20 Oct 2024

        logger.debug(
            f"Creating remaining traffic egress rule via CDK Escape Hatch method"
        )

        _sg_egress_rule = self.soca_resources["compute_node_sg"].node.default_child
        _sg_egress_rule.add_property_override(
            "SecurityGroupEgress",
            [
                {
                    "CidrIp": "0.0.0.0/0",
                    "IpProtocol": "-1",
                    "Description": "Allow All remaining egress for IPv4",
                },
                {
                    "CidrIpv6": "::/0",
                    "IpProtocol": "-1",
                    "Description": "Allow All remaining egress for IPv6",
                },
            ],
        )

        logger.debug(f"Done with Escape Hatch!")
        # security_groups_helper.create_egress_rule(
        #     security_group=self.soca_resources["compute_node_sg"],
        #     peer=ec2.Peer.ipv4("0.0.0.0/0"),
        #     connection=ec2.Port.all_traffic(),
        #     description="Allow all egress traffic from ComputeNodes",
        # )

        if get_config_key("Config.directoryservice.provider") in (
            "aws_ds_managed_activedirectory",
            "aws_ds_simple_activedirectory",
            "existing_active_directory",
        ):
            security_groups_helper.create_ingress_rule(
                security_group=self.soca_resources["compute_node_sg"],
                peer=ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block),
                connection=ec2.Port.udp_range(0, 1024),
                description="Allow all UDP traffic from VPC to compute. Required for Directory Service",
            )

            security_groups_helper.create_egress_rule(
                security_group=self.soca_resources["compute_node_sg"],
                peer=ec2.Peer.ipv4("0.0.0.0/0"),
                connection=ec2.Port.udp_range(0, 1024),
                description="Allow all Egress UDP traffic for ComputeNode SG. Required for Directory Service",
            )

        # ElastiCache SG
        _cache_port_list: list = []
        _cache_provider = get_config_key(
            key_name="Config.services.aws_elasticache.engine", default="redis"
        ).lower()

        if _cache_provider in {"redis", "valkey"}:
            _cache_port_list = [6379]
        elif _cache_provider == "memcached":
            _cache_port_list = [11211, 11212]
        else:
            logger.error(
                f"Unknown cache provider specified: {_cache_provider}  . Must be one of redis, valkey, or memcached."
            )
            exit(1)

        for _port in _cache_port_list:
            for _sg_peer_name in {"controller_sg", "compute_node_sg", "login_node_sg"}:
                security_groups_helper.create_ingress_rule(
                    security_group=self.soca_resources["elasticache_sg"],
                    peer=self.soca_resources[_sg_peer_name],
                    connection=ec2.Port.tcp(_port),
                    description=f"Allow ElastiCache traffic from the {_sg_peer_name}",
                )

        # CONTROLLER
        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["controller_sg"],
            peer=self.soca_resources["compute_node_sg"],
            connection=ec2.Port.tcp_range(0, 65535),
            description="Allow all TCP traffic from the compute nodes",
        )

        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["controller_sg"],
            peer=self.soca_resources["alb_sg"],
            connection=ec2.Port.tcp(8443),
            description="Allow ELB healthcheck to communicate with the UI",
        )

        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["controller_sg"],
            peer=ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block),
            connection=ec2.Port.tcp_range(0, 65535),
            description="VPC - allow all TCP traffic from VPC to controller",
        )

        if get_config_key("Config.directoryservice.provider") in (
            "aws_ds_managed_activedirectory",
            "aws_ds_simple_activedirectory",
            "existing_active_directory",
        ):
            security_groups_helper.create_ingress_rule(
                security_group=self.soca_resources["controller_sg"],
                peer=ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block),
                connection=ec2.Port.udp_range(0, 1024),
                description="Allow UDP traffic from VPC to controller. Required for Directory Service",
            )

            security_groups_helper.create_egress_rule(
                security_group=self.soca_resources["controller_sg"],
                peer=ec2.Peer.ipv4("0.0.0.0/0"),
                connection=ec2.Port.udp_range(0, 1024),
                description="Allow Egress UDP traffic for controller SG. Required for Directory Service",
            )

        # ALB FRONTEND
        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["alb_sg"],
            peer=ec2.Peer.ipv4(user_specified_variables.client_ip),
            connection=ec2.Port.tcp(80),
            description="Allow HTTP from client IP",
        )

        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["alb_sg"],
            peer=ec2.Peer.ipv4(user_specified_variables.client_ip),
            connection=ec2.Port.tcp(443),
            description="Allow HTTPS from client IP",
        )
        # TODO - need?
        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["alb_sg"],
            peer=ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block),
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic from VPC",
        )

        # TODO - merge this / unify the behavior of the NAT IPs
        if user_specified_variables.vpc_id:
            # Existing VPC/IPs
            for nat_eip in self.soca_resources["nat_gateway_ips"]:
                logger.debug(f"Allowing {nat_eip} to access ALB")
                self.soca_resources["alb_sg"].add_ingress_rule(
                    ec2.Peer.ipv4(f"{nat_eip}/32"),
                    ec2.Port.tcp(443),
                    description=f"Allow NAT EIP to communicate to ALB",
                )
                self.soca_resources["nlb_sg"].add_ingress_rule(
                    ec2.Peer.ipv4(f"{nat_eip}/32"),
                    ec2.Port.tcp(_login_node_ssh_front_port),
                    description=f"Allow NAT EIP to communicate to NLB",
                )
        else:
            # Newly created
            logger.debug(
                f"Using NAT EIPs for newly created NAT gateways - {self.soca_resources['nat_gateway_ips']} / {type(self.soca_resources['nat_gateway_ips'])}"
            )
            for nat_eip in self.soca_resources["nat_gateway_ips"]:
                logger.debug(f"Allowing {nat_eip} to access ELBs")
                self.soca_resources["alb_sg"].add_ingress_rule(
                    ec2.Peer.ipv4(f"{nat_eip}/32"),
                    ec2.Port.tcp(443),
                    description=f"Allow NAT EIP to communicate to ALB",
                )
                self.soca_resources["nlb_sg"].add_ingress_rule(
                    ec2.Peer.ipv4(f"{nat_eip}/32"),
                    ec2.Port.tcp(_login_node_ssh_front_port),
                    description=f"Allow NAT EIP to communicate to NLB",
                )

        if user_specified_variables.prefix_list_id:
            security_groups_helper.create_ingress_rule(
                security_group=self.soca_resources["alb_sg"],
                peer=ec2.Peer.prefix_list(user_specified_variables.prefix_list_id),
                connection=ec2.Port.tcp(443),
                description="Allow HTTPS from customer prefix list",
            )

            security_groups_helper.create_ingress_rule(
                security_group=self.soca_resources["alb_sg"],
                peer=ec2.Peer.prefix_list(user_specified_variables.prefix_list_id),
                connection=ec2.Port.tcp(80),
                description="Allow HTTP from customer prefix list",
            )

            security_groups_helper.create_ingress_rule(
                security_group=self.soca_resources["nlb_sg"],
                peer=ec2.Peer.prefix_list(user_specified_variables.prefix_list_id),
                connection=ec2.Port.tcp(_login_node_ssh_front_port),
                description="Allow SSH from customer prefix list",
            )

        for _sg_peer_name in {"controller_sg", "compute_node_sg", "login_node_sg"}:
            logger.debug(f"Allowing {_sg_peer_name} to access NLB on SSH")
            security_groups_helper.create_ingress_rule(
                security_group=self.soca_resources["nlb_sg"],
                peer=self.soca_resources[_sg_peer_name],
                connection=ec2.Port.tcp(_login_node_ssh_front_port),
                description=f"Allow SSH from {_sg_peer_name}",
            )

        # Allow NLB access from customer location
        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["nlb_sg"],
            peer=ec2.Peer.ipv4(user_specified_variables.client_ip),
            connection=ec2.Port.tcp(_login_node_ssh_front_port),
            description="Allow SSH from client IP",
        )

        # Additional LoginNode traffic
        _login_node_additional_ports: dict = get_config_key(
            key_name="Config.login_node.security.additional_ports",
            default={},
            required=False,
            expected_type=dict,
        )

        logger.debug(f"Additional LoginNode traffic: {_login_node_additional_ports}")

        for _proto in _login_node_additional_ports:
            logger.debug(f"Allowing additional traffic for {_proto}")
            for _port in _login_node_additional_ports.get(_proto, []):
                logger.debug(
                    f"Allowing additional traffic {_proto}:{_port} to NLB / LoginNodes"
                )
                for _sg in {"login_node_sg", "nlb_sg"}:
                    logger.debug(f"Updating {_sg} to access {_proto}:{_port}")
                    security_groups_helper.create_ingress_rule(
                        security_group=self.soca_resources[_sg],
                        peer=ec2.Peer.ipv4(user_specified_variables.client_ip),
                        connection=(
                            ec2.Port.udp(_port)
                            if _proto.lower() == "udp"
                            else ec2.Port.tcp(_port)
                        ),
                        description=f"Allow {_proto}:{_port}",
                    )

        # TODO - Needed?
        security_groups_helper.create_ingress_rule(
            security_group=self.soca_resources["login_node_sg"],
            peer=ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block),
            connection=ec2.Port.all_traffic(),
            description="Allow all traffic from VPC",
        )

        # if get_config_key(
        #    key_name="Config.dcv.high_scale",
        #    required=False,
        #    expected_type=bool,
        #    default=False,
        # ):
        #    logger.debug(f"Creating SGs for DCV High Scale ...")
        #    self.dcv_infra_security_groups()

    def create_vpc_endpoints(self):
        """
        Create VPC Endpoints for accessing AWS services.
        """

        # If using an existing VPC first import any existing vpc endpoints
        if user_specified_variables.vpc_id:
            ec2_client = boto3_helper.get_boto(
                service_name="ec2",
                profile_name=user_specified_variables.profile,
                region_name=user_specified_variables.region,
            )
            filters = [{"Name": "vpc-id", "Values": [user_specified_variables.vpc_id]}]
            existing_security_groups = {}
            for page in ec2_client.get_paginator("describe_vpc_endpoints").paginate(
                Filters=filters
            ):
                for vpc_endpoint in page["VpcEndpoints"]:
                    service_name = vpc_endpoint["ServiceName"]
                    short_service_name = service_name.split(".")[-1]
                    resource_name = short_service_name + "VpcEndpoint"
                    security_groups = []
                    for group in vpc_endpoint["Groups"]:
                        group_id = group["GroupId"]
                        security_group = existing_security_groups.get(group_id, None)
                        if not security_group:
                            group_name = group["GroupName"]
                            security_group = ec2.SecurityGroup.from_security_group_id(
                                self, group_name, group_id
                            )
                            existing_security_groups[group_id] = security_group
                        security_groups.append(security_group)
                    print(
                        f"Importing resource {resource_name} for {service_name} {short_service_name}"
                    )
                    if vpc_endpoint["VpcEndpointType"] == "Gateway":
                        self.vpc_gateway_endpoints[short_service_name] = (
                            ec2.GatewayVpcEndpoint.from_gateway_vpc_endpoint_id(
                                self,
                                resource_name,
                                gateway_vpc_endpoint_id=vpc_endpoint["VpcEndpointId"],
                            )
                        )
                    elif vpc_endpoint["VpcEndpointType"] == "Interface":
                        self.vpc_interface_endpoints[short_service_name] = (
                            ec2.InterfaceVpcEndpoint.from_interface_vpc_endpoint_attributes(
                                self,
                                resource_name,
                                vpc_endpoint_id=vpc_endpoint["VpcEndpointId"],
                                security_groups=security_groups,
                                port=443,
                            )
                        )

        for short_service_name in get_config_key(
            key_name="Config.network.vpc_gateway_endpoints", expected_type=list
        ):
            endpoint_service = ec2.GatewayVpcEndpointAwsService(short_service_name)
            if short_service_name in self.vpc_gateway_endpoints:
                continue
            resource_name = f"{short_service_name}VpcEndpoint"
            print(f"Creating resource {resource_name} for {short_service_name}")
            self.vpc_gateway_endpoints[short_service_name] = self.soca_resources[
                "vpc"
            ].add_gateway_endpoint(resource_name, service=endpoint_service)
            CustomResource(
                self,
                f"{short_service_name}VPCEndpointTags",
                service_token=self.tag_ec2_resource_lambda.function_arn,
                properties={
                    "ResourceId": self.vpc_gateway_endpoints[
                        short_service_name
                    ].vpc_endpoint_id,
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": f"{user_specified_variables.cluster_id}-{short_service_name}-VpcEndpoint",
                        },
                        {
                            "Key": "soca:ClusterId",
                            "Value": user_specified_variables.cluster_id,
                        },
                    ],
                },
            )

        for short_service_name in get_config_key(
            key_name="Config.network.vpc_interface_endpoints", expected_type=list
        ):
            if short_service_name == "iam":
                endpoint_service = ec2.InterfaceVpcEndpointAwsService.IAM
            else:
                endpoint_service = ec2.InterfaceVpcEndpointAwsService(
                    short_service_name
                )

            if short_service_name in self.vpc_interface_endpoints:
                continue
            resource_name = f"{short_service_name}VpcEndpoint"
            print(f"Creating resource {resource_name} for {short_service_name}")
            self.vpc_interface_endpoints[short_service_name] = ec2.InterfaceVpcEndpoint(
                self,
                resource_name,
                vpc=self.soca_resources["vpc"],
                service=endpoint_service,
                private_dns_enabled=True,
                security_groups=[self.soca_resources["vpc_endpoint_sg"]],
            )

            CustomResource(
                self,
                f"{short_service_name}VPCEndpointTags",
                service_token=self.tag_ec2_resource_lambda.function_arn,
                properties={
                    "ResourceId": self.vpc_interface_endpoints[
                        short_service_name
                    ].vpc_endpoint_id,
                    "Tags": [
                        {
                            "Key": "Name",
                            "Value": f"{user_specified_variables.cluster_id}-{short_service_name}-VpcEndpoint",
                        },
                        {
                            "Key": "soca:ClusterId",
                            "Value": user_specified_variables.cluster_id,
                        },
                    ],
                },
            )

        for short_service_name, vpc_endpoint in self.vpc_interface_endpoints.items():
            # Ingress
            for _sg_peer_name in {"compute_node_sg", "controller_sg", "login_node_sg"}:
                vpc_endpoint.connections.allow_from(
                    self.soca_resources[_sg_peer_name],
                    ec2.Port.tcp(443),
                    f"Allow HTTPS traffic to {short_service_name} endpoint from {_sg_peer_name}",
                )

    def iam_roles(self):
        """
        Configure IAM roles & policies for the various resources
        """
        # Specify if customers want to re-use existing IAM role for controller/compute nodes/spotfleet
        if user_specified_variables.controller_role_name:
            use_existing_roles = True
        else:
            use_existing_roles = False

        # Create IAM roles
        self.soca_resources["backup_role"] = iam.Role(
            self,
            "BackupRole",
            description="IAM role to manage AWS Backup & Restore jobs",
            assumed_by=iam.ServicePrincipal(principals_suffix["backup"]),
        )
        self.soca_resources["acm_certificate_lambda_role"] = iam.Role(
            self,
            "ACMCertificateLambdaRole",
            description="IAM role assigned to the ACMCertificate Lambda function",
            assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
        )
        self.soca_resources["solution_metrics_lambda_role"] = iam.Role(
            self,
            "SolutionMetricsLambdaRole",
            description="IAM role assigned to the SolutionMetrics Lambda function",
            assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
        )

        # Create Role for EFS Throughput Lambda function only when deploying a new EFS for /apps
        # Moved to EFS fs creation
        # if (
        #     not user_specified_variables.fs_apps_provider
        #     or user_specified_variables.fs_apps_provider == "efs"
        # ):
        self.soca_resources["efs_lambda_role"] = iam.Role(
            self,
            "EFSLambdaRole",
            description="IAM role assigned to the EFS Lambda function",
            assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
        )

        # AOSS Serverless Data Policy creator Lambda role
        # self.soca_resources["aoss_data_policy_lambda_role"] = iam.Role(
        #     self,
        #     "AOSSDataPolicyLambdaRole",
        #     description="IAM role assigned to the AOSS Data Policy Lambda function",
        #     assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
        # )

        if use_existing_roles is False:
            # Create Controller/ComputeNode/SpotFleet roles if not specified by the user
            self.soca_resources["controller_role"] = iam.Role(
                self,
                "ControllerRole",
                description="IAM role assigned to the controller host",
                assumed_by=iam.CompositePrincipal(
                    iam.ServicePrincipal(principals_suffix["ssm"]),
                    iam.ServicePrincipal(principals_suffix["ec2"]),
                ),
            )
            self.soca_resources["compute_node_role"] = iam.Role(
                self,
                "ComputeNodeRole",
                description="IAM role assigned to the compute nodes",
                assumed_by=iam.CompositePrincipal(
                    iam.ServicePrincipal(principals_suffix["ssm"]),
                    iam.ServicePrincipal(principals_suffix["ec2"]),
                ),
            )
            self.soca_resources["spot_fleet_role"] = iam.Role(
                self,
                "SpotFleetRole",
                description="IAM role to manage SpotFleet requests",
                assumed_by=iam.ServicePrincipal(principals_suffix["spotfleet"]),
            )
            self.soca_resources["spot_fleet_role"].add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AmazonEC2SpotFleetTaggingRole"
                )
            )
            #
            # LoginNode Role
            #
            self.soca_resources["login_node_role"] = iam.Role(
                self,
                "LoginNodeRole",
                description="IAM role assigned to the login nodes",
                assumed_by=iam.CompositePrincipal(
                    iam.ServicePrincipal(principals_suffix["ssm"]),
                    iam.ServicePrincipal(principals_suffix["ec2"]),
                ),
            )

            # Do we need our DCV high-scale IAM roles?
            if get_config_key(
                key_name="Config.dcv.high_scale",
                required=False,
                expected_type=bool,
                default=False,
            ):
                logger.debug(f"Creating DCV High Scale roles...")
                for _dcv_host_type in ("broker", "gateway", "manager"):
                    logger.debug(
                        f"Creating IAM role for DCV host type: {_dcv_host_type}"
                    )
                    self.soca_resources[f"dcv_{_dcv_host_type}_role"] = iam.Role(
                        self,
                        f"Dcv{_dcv_host_type.capitalize()}Role",
                        description=f"IAM role assigned to DCV {_dcv_host_type} hosts",
                        assumed_by=iam.CompositePrincipal(
                            iam.ServicePrincipal(principals_suffix["ssm"]),
                            iam.ServicePrincipal(principals_suffix["ec2"]),
                        ),
                    )
                    # Make sure the Admin can SSM to the DCV Infrastructure
                    self.soca_resources[
                        f"dcv_{_dcv_host_type}_role"
                    ].add_managed_policy(
                        iam.ManagedPolicy.from_aws_managed_policy_name(
                            "AmazonSSMManagedInstanceCore"
                        )
                    )
                    # DCV High-scale instance profiles
                    logger.debug(
                        f"Creating Instance profile for DCV host {_dcv_host_type}"
                    )
                    self.soca_resources[f"dcv_{_dcv_host_type}_instance_profile"] = (
                        iam.CfnInstanceProfile(
                            self,
                            f"Dcv{_dcv_host_type.capitalize()}InstanceProfile",
                            roles=[
                                self.soca_resources[
                                    f"dcv_{_dcv_host_type}_role"
                                ].role_name
                            ],
                        )
                    )

            # Instance Profiles
            self.soca_resources["compute_node_instance_profile"] = (
                iam.CfnInstanceProfile(
                    self,
                    "ComputeNodeInstanceProfile",
                    roles=[self.soca_resources["compute_node_role"].role_name],
                )
            )

        else:
            # Reference existing Controller/ComputeNode/SpotFleet roles
            self.soca_resources["controller_role"] = iam.Role.from_role_arn(
                self,
                "ControllerRole",
                role_arn=user_specified_variables.controller_role_arn,
            )
            self.soca_resources["compute_node_role"] = iam.Role.from_role_arn(
                self,
                "ComputeNodeRole",
                role_arn=user_specified_variables.compute_node_role_arn,
            )
            self.soca_resources["spot_fleet_role"] = iam.Role.from_role_arn(
                self,
                "SpotFleetRole",
                role_arn=user_specified_variables.spotfleet_role_arn,
            )
            self.soca_resources["compute_node_instance_profile"] = (
                iam.CfnInstanceProfile(
                    self,
                    "ComputeNodeInstanceProfile",
                    roles=[user_specified_variables.compute_node_role_name],
                )
            )

        # Add SSM Managed Policy
        for _role in {
            "controller_role",
            "compute_node_role",
            "login_node_role",
            "spot_fleet_role",
        }:
            logger.debug(f"Adding SSM Managed Policy to {_role}")
            self.soca_resources[_role].add_managed_policy(
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "AmazonSSMManagedInstanceCore"
                )
            )

        # Generate IAM inline policies
        policy_substitutes = {
            "%%AWS_ACCOUNT_ID%%": Aws.ACCOUNT_ID,
            "%%AWS_PARTITION%%": Aws.PARTITION,
            "%%AWS_URL_SUFFIX%%": Aws.URL_SUFFIX,
            "%%AWS_REGION%%": Aws.REGION,
            "%%BUCKET%%": user_specified_variables.bucket,
            "%%COMPUTE_NODE_ROLE_ARN%%": (
                self.soca_resources["compute_node_role"].role_arn
                if not user_specified_variables.compute_node_role_arn
                else user_specified_variables.compute_node_role_arn
            ),
            "%%SCHEDULER_ROLE_ARN%%": (
                self.soca_resources["controller_role"].role_arn
                if not user_specified_variables.controller_role_arn
                else user_specified_variables.controller_role_arn
            ),
            "%%SPOTFLEET_ROLE_ARN%%": (
                self.soca_resources["spot_fleet_role"].role_arn
                if not user_specified_variables.spotfleet_role_arn
                else user_specified_variables.spotfleet_role_arn
            ),
            "%%VPC_ID%%": self.soca_resources["vpc"].vpc_id,
            "%%CLUSTER_ID%%": user_specified_variables.cluster_id,
        }

        policy_templates = {
            "ACMCertificateLambdaPolicy": {
                "template": "../policies/ACMCertificateLambda.json",
                "attach_to_role": "acm_certificate_lambda_role",
            },
            "BackupPolicy": {
                "template": "../policies/Backup.json",
                "attach_to_role": "backup_role",
            },
            "SolutionMetricsLambdaPolicy": {
                "template": "../policies/SolutionMetricsLambda.json",
                "attach_to_role": "solution_metrics_lambda_role",
            },
            # "AOSSDataPolicyLambdaPolicy": {
            #     "template": "../policies/AOSSDataPolicyLambda.json",
            #     "attach_to_role": "aoss_data_policy_lambda_role",
            # },
        }

        if use_existing_roles is False:
            policy_templates["ComputeNodePolicy"] = {
                "template": "../policies/ComputeNode.json",
                "attach_to_role": "compute_node_role",
            }
            policy_templates["ControllerPolicy"] = {
                "template": "../policies/Controller.json",
                "attach_to_role": "controller_role",
            }
            policy_templates["SpotFleetPolicy"] = {
                "template": "../policies/SpotFleet.json",
                "attach_to_role": "spot_fleet_role",
            }
            policy_templates["LoginNodePolicy"] = {
                "template": "../policies/LoginNode.json",
                "attach_to_role": "login_node_role",
            }

            if get_config_key(
                key_name="Config.dcv.high_scale",
                required=False,
                expected_type=bool,
                default=False,
            ):
                logger.debug(f"Attaching IAM Policies for DCV hosts ...")
                for _dcv_host_type in {"broker", "gateway", "manager"}:
                    policy_templates[f"Dcv{_dcv_host_type.capitalize()}Policy"] = {
                        "template": f"../policies/Dcv{_dcv_host_type.capitalize()}.json",
                        "attach_to_role": f"dcv_{_dcv_host_type}_role",
                    }
                    logger.debug(
                        f"Attaching IAM Policies for DCV host type {_dcv_host_type}: {policy_templates[f'Dcv{_dcv_host_type.capitalize()}Policy']}"
                    )

        else:
            # Append required policies if IAM specified by user have not been generated by SOCA
            if user_specified_variables.controller_role_from_previous_soca_deployment:
                policy_templates["ControllerPolicyNewCluster"] = {
                    "template": "../policies/ControllerAppendToExistingRole.json",
                    "attach_to_role": "controller_role",
                }
            else:
                policy_templates["ControllerPolicyNewCluster"] = {
                    "template": "../policies/Controller.json",
                    "attach_to_role": "controller_role",
                }

            if (
                not user_specified_variables.compute_node_role_from_previous_soca_deployment
            ):
                policy_templates["ComputeNodePolicy"] = {
                    "template": "../policies/ComputeNode.json",
                    "attach_to_role": "compute_node_role",
                }

            if (
                not user_specified_variables.spotfleet_role_from_previous_soca_deployment
            ):
                policy_templates["SpotFleetPolicy"] = {
                    "template": "../policies/SpotFleet.json",
                    "attach_to_role": "spot_fleet_role",
                }

        if not user_specified_variables.fs_apps:
            policy_templates["EFSAppsLambdaPolicy"] = {
                "template": "../policies/EFSAppsLambda.json",
                "attach_to_role": "efs_lambda_role",
            }

        # Create all policies and attach them to their respective role
        for policy_name, policy_data in policy_templates.items():
            with open(policy_data["template"]) as json_file:
                policy_content = json_file.read()

            for k, v in policy_substitutes.items():
                policy_content = policy_content.replace(k, v)

            self.soca_resources[policy_data["attach_to_role"]].attach_inline_policy(
                iam.Policy(
                    self,
                    f"{user_specified_variables.cluster_id}-{policy_name}",
                    document=iam.PolicyDocument.from_json(json.loads(policy_content)),
                )
            )

    def directory_service(self):
        """ "
        Determine our desired directory service and create it.
        """

        logger.debug(
            f"Determining required directory service for {self.directory_service_resource_setup.get('provider')}"
        )

        if self.directory_service_resource_setup.get("provider") in {
            "aws_ds_simple_activedirectory"
        }:
            logger.error(
                f"AWS SimpleAD is no longer supported. Please update your configuration to use a supported Directory Service"
            )
            exit(1)
            # return self.directory_service_aws_simplead()

        elif self.directory_service_resource_setup.get("provider") in {
            "aws_ds_managed_activedirectory"
        }:
            logger.debug(f"Creating AWS Manage AD Directory Service")
            return self.directory_service_aws_mad()

        elif (
            self.directory_service_resource_setup.get("provider")
            == "existing_active_directory"
        ):
            logger.info(
                f"Using existing Active Directory. Retrieving specified configuration"
            )
            self.directory_service_resource_setup["domain_controller_ips"] = (
                get_config_key(
                    key_name=f"Config.directoryservice.existing_active_directory.dc_ips",
                    required=True,
                    expected_type=list,
                )
            )

            logger.info("Retrieving specific AD Service Account User/Password")
            _ad_service_account_secret = get_config_key(
                key_name=f"Config.directoryservice.existing_active_directory.service_account_secret_name_arn",
                required=True,
                expected_type=str,
            )
            _ad_service_account_credentials = (
                secretsmanager_helper.retrieve_secret_value(
                    secret_id=_ad_service_account_secret,
                    region_name=user_specified_variables.region,
                )
            )
            self.directory_service_resource_setup["ds_admin_username"] = (
                _ad_service_account_credentials.get("username", None)
            )
            self.directory_service_resource_setup["ds_admin_password"] = (
                _ad_service_account_credentials.get("password", None)
            )

            if (
                self.directory_service_resource_setup["ds_admin_username"] is None
                or self.directory_service_resource_setup["ds_admin_password"] is None
            ):
                logger.fatal(
                    f"Unable to retrieve username/password for the service account. Please check the secret provided on {_ad_service_account_secret}"
                )

        elif (
            self.directory_service_resource_setup.get("provider") == "existing_openldap"
        ):
            logger.debug(f"Using existing OpenLDAP. SOCA won't create it.")

        elif self.directory_service_resource_setup.get("provider") == "openldap":
            logger.debug(
                f"Self-hosted OpenLDAP will be initialized with the controller instance."
            )
        else:
            logger.fatal(
                f"Unknown Directory Service provider: {self.directory_service_resource_setup.get('provider')}"
            )

    # SimpleAD deprecated - codepath to be removed at a later date
    def directory_service_aws_simplead(self):
        """
        Deploy an AWS SimpleAD Directory Service
        """
        # FIXME TODO - dupe with AWS MAD
        if not user_specified_variables.vpc_id:
            launch_subnets = [
                self.soca_resources["vpc"].private_subnets[0].subnet_id,
                self.soca_resources["vpc"].private_subnets[1].subnet_id,
            ]
        else:
            launch_subnets = [
                user_specified_variables.private_subnets[0].split(",")[0],
                user_specified_variables.private_subnets[1].split(",")[0],
            ]

        _secret_name: str = (
            f"/soca/{user_specified_variables.cluster_id}/UserDirectoryServiceAccount"
        )
        self.directory_service_resource_setup[
            "ds_admin_username"
        ]: str = "Administrator"  # Cannot be changed
        logger.debug(
            f"SimpleAD - generating Admin Username/pw to Secret: {_secret_name}"
        )
        self.directory_service_resource_setup["ds_admin_password"] = (
            secretsmanager_helper.create_secret(
                scope=self,
                construct_id="UserDirectoryServiceAccount",
                secret_name=_secret_name,
                secret_string_template=f'{{"username":"{self.directory_service_resource_setup['ds_admin_username']}@{self.directory_service_resource_setup.get("domain_name")}"}}',
                kms_key_id=(
                    self.soca_resources["secretsmanager_kms_key_id"]
                    if self.soca_resources["secretsmanager_kms_key_id"]
                    else None
                ),
            )
        )
        self.directory_service_resource_setup["service_account_secret_arn"] = (
            self.directory_service_resource_setup["ds_admin_password"].secret_full_arn
        )
        logger.debug(
            f"Creating AWS SimpleAD Directory Service in aws_simplead_directory_service"
        )
        logger.debug(
            f"SimpleAD Username: {self.directory_service_resource_setup['ds_admin_username']}"
        )
        self.directory_service_resource_setup["ds"] = ds.CfnSimpleAD(
            self,
            "DSSimpleAD",
            name=self.directory_service_resource_setup.get("domain_name"),
            short_name=self.directory_service_resource_setup.get("short_name"),
            password=secretsmanager_helper.resolve_secret_as_str(
                secret_construct=self.directory_service_resource_setup[
                    "ds_admin_password"
                ]
            ),
            size=get_config_key(
                key_name="Config.directoryservice.aws_ds_simple_activedirectory.size",
                expected_type=str,
                required=False,
                default="Small",
            ).capitalize(),  # must be Small vs. small
            vpc_settings=ds.CfnSimpleAD.VpcSettingsProperty(
                subnet_ids=launch_subnets,
                vpc_id=self.soca_resources["vpc"].vpc_id,
            ),
        )

        self.directory_service_resource_setup["ad_aws_directory_service_id"] = (
            self.directory_service_resource_setup["ds"].ref
        )
        self.directory_service_resource_setup["domain_controller_ips"] = [
            f"{Fn.select(0, self.directory_service_resource_setup["ds"].attr_dns_ip_addresses)}",
            f"{Fn.select(1, self.directory_service_resource_setup["ds"].attr_dns_ip_addresses)}",
        ]
        self.directory_service_resource_setup["endpoint"] = (
            f"ldap://{self.directory_service_resource_setup["ds"].name}"
        )

        # Finally , fixup our DNS
        if get_config_key(
            key_name="Config.directoryservice.create_route53_resolver",
            expected_type=bool,
            required=False,
            default=True,
        ):
            self.aws_route53_resolver(
                launch_subnets=launch_subnets,
                dns_ip_addresses=self.directory_service_resource_setup[
                    "ds"
                ].attr_dns_ip_addresses,
            )
        else:
            logger.info(
                f"Bypassing Route53 Resolver Creation due to Config.directoryservice.create_route53_resolver_rule == False"
            )

    def directory_service_aws_mad(self):
        """
        Deploy an AWS Manage AD Directory Service
        """
        logger.debug(f"Creating AWS MAD Directory Service in aws_mad_directory_service")

        if not user_specified_variables.vpc_id:
            launch_subnets = [
                self.soca_resources["vpc"].private_subnets[0].subnet_id,
                self.soca_resources["vpc"].private_subnets[1].subnet_id,
            ]
        else:
            launch_subnets = [
                user_specified_variables.private_subnets[0].split(",")[0],
                user_specified_variables.private_subnets[1].split(",")[0],
            ]

        # Create a new AWS Directory Service Managed AD
        _secret_name: str = (
            f"/soca/{user_specified_variables.cluster_id}/UserDirectoryServiceAccount"
        )
        self.directory_service_resource_setup[
            "ds_admin_username"
        ]: str = "Admin"  # Cannot be changed
        self.directory_service_resource_setup["ds_admin_password"] = (
            secretsmanager_helper.create_secret(
                scope=self,
                construct_id="UserDirectoryDomainAdmin",
                secret_name=_secret_name,
                secret_string_template=f'{{"username":"{self.directory_service_resource_setup['ds_admin_username']}@{self.directory_service_resource_setup.get("domain_name")}"}}',
                require_each_included_type=True,
                kms_key_id=(
                    self.soca_resources["secretsmanager_kms_key_id"]
                    if self.soca_resources["secretsmanager_kms_key_id"]
                    else None
                ),
            )
        )
        self.directory_service_resource_setup["service_account_secret_arn"] = (
            self.directory_service_resource_setup["ds_admin_password"].secret_full_arn
        )
        self.directory_service_resource_setup["ds"] = ds.CfnMicrosoftAD(
            self,
            "DSManagedAD",
            name=self.directory_service_resource_setup.get("domain_name"),
            edition=get_config_key(
                key_name="Config.directoryservice.activedirectory.edition",
                expected_type=str,
                required=False,
                default="Standard",
            ),
            short_name=self.directory_service_resource_setup.get("short_name"),
            password=secretsmanager_helper.resolve_secret_as_str(
                secret_construct=self.directory_service_resource_setup[
                    "ds_admin_password"
                ]
            ),
            vpc_settings=ds.CfnMicrosoftAD.VpcSettingsProperty(
                subnet_ids=launch_subnets, vpc_id=self.soca_resources["vpc"].vpc_id
            ),
        )

        self.directory_service_resource_setup["ad_aws_directory_service_id"] = (
            self.directory_service_resource_setup["ds"].ref
        )
        self.directory_service_resource_setup["endpoint"] = (
            f"ldap://{self.directory_service_resource_setup["ds"].name}"
        )

        self.directory_service_resource_setup["domain_controller_ips"] = [
            Fn.select(
                0, self.directory_service_resource_setup["ds"].attr_dns_ip_addresses
            ),
            Fn.select(
                1, self.directory_service_resource_setup["ds"].attr_dns_ip_addresses
            ),
        ]

        # Finally, fixup our DNS unless instructed not to
        # Some Shared VPC environments do not allow the downstream account to create R53 resolvers.
        if get_config_key(
            key_name="Config.directoryservice.create_route53_resolver",
            expected_type=bool,
            required=False,
            default=True,
        ):
            self.aws_route53_resolver(
                launch_subnets=launch_subnets,
                dns_ip_addresses=self.directory_service_resource_setup[
                    "ds"
                ].attr_dns_ip_addresses,
            )
        else:
            logger.info(
                f"Bypassing Route53 Resolver Creation due to Config.directoryservice.create_route53_resolver_rule == False"
            )

    def aws_route53_resolver(self, launch_subnets: list, dns_ip_addresses: list):
        """
        Create AWS Route53 resolver configurations for domain forwarding.
        """

        # Prepare a security group for the Route53 Resolver(outbound)
        _r53_security_group = security_groups_helper.create_security_groups(
            scope=self,
            construct_id=f"{user_specified_variables.cluster_id}-route53-resolver",
            vpc=self.soca_resources["vpc"],
            allow_all_outbound=False,
            allow_all_ipv6_outbound=False,
            description=f"{user_specified_variables.cluster_id} Route53 Resolver SG",
        )

        # Ingress to the Route53 SG
        for _sg_id in ["controller_sg", "compute_node_sg", "login_node_sg"]:
            logger.debug(
                f"Adding ingress traffic for {_sg_id} to Route53 Outbound resolver SG"
            )

            for _proto in ("TCP", "UDP"):
                logger.debug(f"Adding {_proto} DNS {_sg_id} -> {_r53_security_group}")
                security_groups_helper.create_ingress_rule(
                    security_group=_r53_security_group,
                    peer=self.soca_resources[_sg_id],
                    connection=ec2.Port(
                        protocol=ec2.Protocol(_proto),
                        string_representation=f"{_proto} DNS",
                        from_port=53,
                        to_port=53,
                    ),
                    description=f"Allow {_sg_id} {_proto} DNS",
                )

        # After explicitly listing the cluster SGs, we also include the VPC CIDR range.
        # This allows for the cluster to work properly with the per-cluster SGs and this rule
        # to match any missed items. This rule could then be removed if it is considered
        # too broad by local security policy.
        for _proto in ("TCP", "UDP"):
            security_groups_helper.create_ingress_rule(
                security_group=_r53_security_group,
                peer=ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block),
                connection=ec2.Port(
                    protocol=ec2.Protocol(_proto),
                    string_representation=f"VPC {_proto} DNS",
                    from_port=53,
                    to_port=53,
                ),
                description=f"Allow VPC CIDR {_proto} DNS",
            )

        # Egress from the Route53 SG - restricted to DNS traffic only
        for _address_family in ("ipv4", "ipv6"):
            logger.debug(f"Adding egress rule for address family: {_address_family}")
            for _proto in ("TCP", "UDP"):
                logger.debug(f"Adding egress rule - {_proto} DNS {_r53_security_group}")
                security_groups_helper.create_egress_rule(
                    security_group=_r53_security_group,
                    peer=(
                        ec2.Peer.any_ipv4()
                        if _address_family == "ipv4"
                        else ec2.Peer.any_ipv6()
                    ),
                    connection=ec2.Port(
                        protocol=ec2.Protocol(_proto),
                        string_representation=f"{_address_family}/{_proto} DNS",
                        from_port=53,
                        to_port=53,
                    ),
                    description=f"Allow {_address_family}/{_proto} DNS",
                )

        # Create DNS Forwarder. Requests sent to AD will be forwarded to AD DNS
        # Other requests will remain the same. Do not create custom DHCP Option Set otherwise resources such as FSx or EFS won't resolve
        resolver = route53resolver.CfnResolverEndpoint(
            self,
            "ADRoute53OutboundResolver",
            direction="OUTBOUND",
            name=user_specified_variables.cluster_id,
            ip_addresses=[
                route53resolver.CfnResolverEndpoint.IpAddressRequestProperty(
                    subnet_id=launch_subnets[0]
                ),
                route53resolver.CfnResolverEndpoint.IpAddressRequestProperty(
                    subnet_id=launch_subnets[1]
                ),
            ],
            security_group_ids=[_r53_security_group.security_group_id],
        )

        resolver_rule = route53resolver.CfnResolverRule(
            self,
            "ADRoute53OutboundResolverRule",
            name=user_specified_variables.cluster_id,
            domain_name=self.directory_service_resource_setup.get("domain_name"),
            rule_type="FORWARD",
            resolver_endpoint_id=resolver.attr_resolver_endpoint_id,
            target_ips=[
                route53resolver.CfnResolverRule.TargetAddressProperty(
                    ip=Fn.select(
                        0,
                        dns_ip_addresses,
                    ),
                    port="53",
                ),
                route53resolver.CfnResolverRule.TargetAddressProperty(
                    ip=Fn.select(
                        1,
                        dns_ip_addresses,
                    ),
                    port="53",
                ),
            ],
        )

        route53resolver.CfnResolverRuleAssociation(
            self,
            "ADRoute53ResolverRuleAssociation",
            resolver_rule_id=resolver_rule.attr_resolver_rule_id,
            vpc_id=self.soca_resources["vpc"].vpc_id,
        )

    def _storage_build_efs_filesystem(self, fs_key: str):
        """
        Build an EFS filesystem.
        """
        logger.debug(f"_storage_build_efs_filesystem called for {fs_key}")
        _kms_key_id: str = get_kms_key_id(
            config_key_names=[f"Config.storage.{fs_key}.kms_key_id"],
            allow_global_default=True,
        )
        if _kms_key_id:
            logger.debug(f"EFS KMS for {fs_key}: {_kms_key_id}")

        self.soca_resources[f"fs_{fs_key}"] = efs.CfnFileSystem(
            self,
            id=f"EFS{fs_key.capitalize()}",
            encrypted=True,
            kms_key_id=_kms_key_id if _kms_key_id else "alias/aws/elasticfilesystem",
            throughput_mode=get_config_key(
                key_name=f"Config.storage.{fs_key}.efs.throughput_mode",
                required=False,
                expected_type=str,
                default="bursting",
            ),
            file_system_tags=[
                efs.CfnFileSystem.ElasticFileSystemTagProperty(
                    key="soca:BackupPlan", value=user_specified_variables.cluster_id
                ),
                efs.CfnFileSystem.ElasticFileSystemTagProperty(
                    key="Name",
                    value=f"{user_specified_variables.cluster_id}-{fs_key.capitalize()}",
                ),
            ],
            lifecycle_policies=[
                efs.CfnFileSystem.LifecyclePolicyProperty(
                    transition_to_ia=get_config_key(
                        key_name=f"Config.storage.{fs_key}.efs.transition_to_ia",
                        required=False,
                        expected_type=str,
                        default="AFTER_30_DAYS",
                    )
                )
            ],
            performance_mode=get_config_key(
                key_name=f"Config.storage.{fs_key}.efs.performance_mode",
                required=False,
                expected_type=str,
                default="generalPurpose",
            ),
        )

        if (
            get_config_key(f"Config.storage.{fs_key}.efs.deletion_policy").upper()
            == "RETAIN"
        ):
            self.soca_resources[f"fs_{fs_key}"].cfn_options.deletion_policy = (
                CfnDeletionPolicy.RETAIN
            )

        # Create the Security group for the filesystem
        self.soca_resources[f"fs_{fs_key}_sg"] = ec2.SecurityGroup(
            self,
            id=f"EFS{fs_key.capitalize()}SecurityGroup",
            vpc=self.soca_resources["vpc"],
            description=f"EFS {fs_key.capitalize()} Security Group",
        )
        Tags.of(self.soca_resources[f"fs_{fs_key}_sg"]).add(
            "Name", f"{user_specified_variables.cluster_id}-EFS{fs_key.capitalize()}SG"
        )

        # Create our rules for each SG expected to consume the filesystem
        for _sg_peer in {"compute_node_sg", "controller_sg", "login_node_sg"}:
            for _tcp_port in {2049}:
                security_groups_helper.create_ingress_rule(
                    security_group=self.soca_resources[f"fs_{fs_key}_sg"],
                    peer=self.soca_resources[_sg_peer],
                    connection=ec2.Port.tcp(_tcp_port),
                    description=f"Allow NFS from {_sg_peer}",
                )

        # Where do we need EFS mount points created?
        _efs_mount_subnets: list = []
        if not user_specified_variables.vpc_id:
            for _sn_id in [
                *self.soca_resources["vpc"].isolated_subnets,
                *self.soca_resources["vpc"].private_subnets,
            ]:
                if _sn_id not in _efs_mount_subnets:
                    logger.debug(
                        f"Adding subnet for EFS mountpoint: {_sn_id.subnet_id}"
                    )
                    _efs_mount_subnets.append(_sn_id.subnet_id)

        else:
            # Existing subnets selected
            # Note - cannot include multiple subnets in a single AZ
            # TODO FIXME - deconflict the subnet/AZs
            # _subnets_for_efs_mounts: list = [*user_specified_variables.private_subnets, *user_specified_variables.public_subnets]
            _subnets_for_efs_mounts: list = [*user_specified_variables.private_subnets]

            logger.debug(
                f"Using existing subnets for EFS mountpoint: {_subnets_for_efs_mounts}"
            )
            for _sn_id in _subnets_for_efs_mounts:
                _exact_subnet_id = _sn_id.split(",")[0]
                if _exact_subnet_id not in _efs_mount_subnets:
                    logger.debug(
                        f"Adding subnet for EFS mountpoint: {_exact_subnet_id}"
                    )
                    _efs_mount_subnets.append(_exact_subnet_id)

        # Complete list of subnets needing EFS mount points

        logger.debug(f"Creating EFS mount targets for {fs_key} - {_efs_mount_subnets}")

        for _i in range(len(_efs_mount_subnets)):
            logger.debug(
                f"Creating EFS mount target for {fs_key} - {_efs_mount_subnets[_i]}"
            )
            _efs_mt = efs.CfnMountTarget(
                self,
                id=f"EFS{fs_key.capitalize()}MountTarget{_i + 1}",
                file_system_id=self.soca_resources[f"fs_{fs_key}"].ref,
                security_groups=[
                    self.soca_resources[f"fs_{fs_key}_sg"].security_group_id,
                ],
                subnet_id=_efs_mount_subnets[_i],
            )
            # _efs_mt.node.add_dependency(
            #     self.soca_resources[f"fs_{fs_key}"],
            #     self.soca_resources[f"fs_{fs_key}_sg"],
            # )

        _efs_alarms: dict = {}
        for _alarm in {"Low", "High"}:
            logger.debug(f"Creating EFS {_alarm} alarm for {fs_key}")
            match _alarm:
                case "Low":
                    _compare_op = (
                        cloudwatch.ComparisonOperator.LESS_THAN_OR_EQUAL_TO_THRESHOLD
                    )
                    _threshold = 10_000_000
                    _evaluation_periods = 10
                case "High":
                    _compare_op = (
                        cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD
                    )
                    _threshold = 2_000_000_000_000
                    _evaluation_periods = 1
                case _:
                    raise ValueError(f"Invalid alarm type: {_alarm}")

            _efs_alarms[_alarm] = cloudwatch.Alarm(
                self,
                id=f"EFS{fs_key.capitalize()}CWAlarm{_alarm}Threshold",
                metric=cloudwatch.Metric(
                    metric_name="BurstCreditBalance",
                    namespace="AWS/EFS",
                    period=Duration.minutes(1),
                    statistic="Average",
                    dimensions_map=dict(
                        FileSystemId=self.soca_resources[f"fs_{fs_key}"].ref
                    ),
                ),
                comparison_operator=_compare_op,
                evaluation_periods=_evaluation_periods,
                threshold=_threshold,
            )
            _efs_alarms[_alarm].add_alarm_action(
                cw_actions.SnsAction(self.soca_resources["sns_efs_topic"])
            )

            _efs_alarms[_alarm].node.add_dependency(
                self.soca_resources[f"fs_{fs_key}"],
                self.soca_resources["sns_efs_topic"],
            )

        # self.soca_resources[f"fs_{fs_key}_lambda_role"] = iam.Role(
        #     self,
        #     id=f"EFS{_fs.capitalize()}LambdaRole",
        #     description=f"IAM role assigned to the EFS{fs_key.capitalize()}Lambda function",
        #     assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]),
        # )

        # efs_throughput_lambda = aws_lambda.Function(
        #     self,
        #     f"{user_specified_variables.cluster_id}-EFS{fs_key.capitalize()}Lambda",
        #     function_name=f"{user_specified_variables.cluster_id}-EFSThroughput",
        #     description="Check EFS BurstCreditBalance and update ThroughputMode when needed",
        #     memory_size=128,
        #     role=self.soca_resources[f"fs_{fs_key}_lambda_role"],
        #     timeout=Duration.minutes(3),
        #     runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
        #     log_retention=logs.RetentionDays.INFINITE,
        #     handler="EFSThroughputLambda.lambda_handler",
        #     code=aws_lambda.Code.from_asset("../functions/EFSThroughputLambda"),
        # )
        # efs_throughput_lambda.node.add_dependency(
        #     self.soca_resources["efs_lambda_role"]
        # )

        # TODO - FIXME - These should be in sync with the above values
        # efs_throughput_lambda.add_environment(
        #     "EFSBurstCreditLowThreshold", "10000000"
        # )
        # efs_throughput_lambda.add_environment(
        #     "EFSBurstCreditHighThreshold", "2000000000000"
        # )
        # efs_throughput_lambda.add_permission(
        #     "InvokePermission",
        #     principal=iam.ServicePrincipal(principals_suffix["sns"]),
        #     action="lambda:InvokeFunction",
        # )

        # sns.Subscription(
        #     self,
        #     f"{user_specified_variables.cluster_id}-SNSEFSSubscription",
        #     protocol=sns.SubscriptionProtocol.LAMBDA,
        #     endpoint=efs_throughput_lambda.function_arn,
        #     topic=self.soca_resources["sns_efs_topic"],
        # )

        self.soca_filesystems[f"{fs_key}"] = {
            "provider": "efs",
            "mount_path": f"/{fs_key}",
            "mount_options": "nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport",
            "mount_target": self.soca_resources[f"fs_{fs_key}"].ref,
            "on_mount_failure": "exit",
            "enabled": "true",
        }

    def _storage_build_fsx_lustre_filesystem(self, fs_key: str):
        """
        Build an FSx filesystem.
        """

        logger.debug(f"_storage_build_fsx_filesystem called for {fs_key}")

        _storage_type: str = get_config_key(
            key_name=f"Config.storage.{fs_key}.fsx_lustre.storage_type",
            required=False,
            expected_type=str,
            default="SSD",
        ).upper()

        _deployment_type: str = get_config_key(
            key_name=f"Config.storage.{fs_key}.fsx_lustre.deployment_type",
            expected_type=str,
            required=False,
            default="PERSISTENT_2",
        ).upper()

        _per_unit_storage_throughput: int = get_config_key(
            key_name=f"Config.storage.{fs_key}.fsx_lustre.per_unit_storage_throughput",
            expected_type=int,
            required=False,
            default=125 if _deployment_type == "PERSISTENT_2" else 100,
        )

        _drive_cache_type: str = get_config_key(
            key_name=f"Config.storage.{fs_key}.fsx_lustre.drive_cache_type",
            required=False,
            expected_type=str,
            default="READ",
        ).upper()

        _storage_capacity: int = get_config_key(
            key_name=f"Config.storage.{fs_key}.fsx_lustre.storage_capacity",
            expected_type=int,
            required=False,
            default=1200 if _deployment_type == "PERSISTENT_2" else 300,
        )

        match _storage_type:
            case "SSD":
                if _deployment_type in {"PERSISTENT_1", "PERSISTENT_2"}:
                    lustre_configuration = (
                        fsx.CfnFileSystem.LustreConfigurationProperty(
                            per_unit_storage_throughput=_per_unit_storage_throughput,
                            deployment_type=_deployment_type,
                        )
                    )
                else:
                    lustre_configuration = (
                        fsx.CfnFileSystem.LustreConfigurationProperty(
                            deployment_type=_deployment_type
                        )
                    )
            case "HDD":
                lustre_configuration = (
                    fsx.CfnFileSystem.LustreConfigurationProperty(
                        deployment_type=_deployment_type,
                        per_unit_storage_throughput=_per_unit_storage_throughput,
                        drive_cache_type=_drive_cache_type,
                    ),
                )
            case _:
                raise ValueError(f"Invalid storage type: {_storage_type} for {fs_key}")

        # Determine KMS config
        _kms_key_id = get_kms_key_id(
            config_key_names=[
                f"Config.storage.{fs_key}.kms_key_id",  # The proper location providing per-fs keys
                "Config.storage.kms_key_id",  # Fallback to a global storage kms_key_id
            ],
            allow_global_default=True,
        )
        logger.debug(f"FSx KMS for {fs_key}: {_kms_key_id}")

        # Create the Security group for the filesystem
        self.soca_resources[f"fs_{fs_key}_sg"] = ec2.SecurityGroup(
            self,
            id=f"FSxLustre{fs_key.capitalize()}SecurityGroup",
            vpc=self.soca_resources["vpc"],
            description=f"FSx/Lustre {fs_key.capitalize()} Security Group",
        )

        # Create our rules for each peer expected to consume the filesystem
        for _sg_peer in [
            f"fs_{fs_key}_sg",
            "compute_node_sg",
            "controller_sg",
            "login_node_sg",
        ]:
            for _tcp_port_spec in {"988", "1018-1023"}:
                logger.debug(f"Adding TCP {_tcp_port_spec} for {_sg_peer}")

                if "-" in _tcp_port_spec:
                    _tcp_from_port: int = int(_tcp_port_spec.split("-")[0])
                    _tcp_to_port: int = int(_tcp_port_spec.split("-")[1])
                    _conn_spec: ec2.Port = ec2.Port.tcp_range(
                        start_port=_tcp_from_port, end_port=_tcp_to_port
                    )
                else:
                    _conn_spec: ec2.Port = ec2.Port.tcp(int(_tcp_port_spec))

                logger.debug(f"Adding ingress rule for {_conn_spec}")
                security_groups_helper.create_ingress_rule(
                    security_group=self.soca_resources[f"fs_{fs_key}_sg"],
                    peer=self.soca_resources[_sg_peer],
                    connection=_conn_spec,
                    description=f"Allow FSx/Lustre from {_sg_peer}",
                )

        self.soca_resources[f"fs_{fs_key}"] = fsx.CfnFileSystem(
            self,
            f"FSxLustre{fs_key.capitalize()}",
            file_system_type="LUSTRE",
            subnet_ids=[
                self.soca_resources["vpc"]
                .select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                .subnets[0]
                .subnet_id
            ],
            lustre_configuration=lustre_configuration,
            security_group_ids=[
                self.soca_resources[f"fs_{fs_key}_sg"].security_group_id
            ],
            storage_capacity=_storage_capacity,
            storage_type=_storage_type,
            kms_key_id=_kms_key_id if _kms_key_id else None,
        )

        self.soca_resources[f"fs_{fs_key}"].node.add_dependency(
            self.soca_resources[f"fs_{fs_key}_sg"]
        )

        Tags.of(self.soca_resources[f"fs_{fs_key}"]).add(
            "Name", f"{user_specified_variables.cluster_id}-{fs_key.capitalize()}"
        )
        Tags.of(self.soca_resources[f"fs_{fs_key}"]).add(
            "soca:BackupPlan", user_specified_variables.cluster_id
        )

        self.soca_filesystems[f"{fs_key}"] = {
            "provider": "fsx_lustre",
            "mount_path": f"/{fs_key}",
            "mount_options": "defaults,noatime,flock,_netdev",
            "mount_target": self.soca_resources[f"fs_{fs_key}"].ref,
            "on_mount_failure": "exit",
            "enabled": "true",
        }

    @staticmethod
    def get_fsx_pricing_data(region: Optional[str]) -> list:
        """
        Get pricing data for AmazonFSx
        """

        _pricing_data: list = []

        # Where we connect to for pricing API endpoint
        _pricing_region: str = ""

        if region:
            if region.startswith("ap"):
                _pricing_region = "ap-south-1"
            elif region.startswith("eu"):
                _pricing_region = "eu-central-1"
            else:
                # default to us-east-1
                _pricing_region = "us-east-1"
        else:
            # default to us-east-1
            _pricing_region = "us-east-1"

        logger.debug(f"Using Pricing region endpoint from: {_pricing_region}")

        _pricing_client = boto3_helper.get_boto(
            service_name="pricing",
            profile_name=user_specified_variables.profile,
            region_name=_pricing_region,
        )

        _pricing_paginator = _pricing_client.get_paginator("get_products")

        _filters: list = []

        if not region:
            logger.debug(f"Retrieving pricing data for ALL AWS Regions")
        else:
            # Add our specific region to the filter to have a smaller API req/response
            logger.debug(f"Retrieving pricing data for specific region: {region}")
            _filters.append(
                {"Field": "regionCode", "Value": region, "Type": "TERM_MATCH"}
            )

        _pricing_iterator = _pricing_paginator.paginate(
            ServiceCode="AmazonFSx",
            Filters=_filters,
            PaginationConfig={"MaxResults": 100},
        )

        _pricing_pages: int = 0
        _pricing_entries: int = 0

        for _page in _pricing_iterator:
            _pricing_pages += 1
            for _entry in _page.get("PriceList", {}):
                _pricing_entries += 1
                _pricing_data.append(_entry)

        if not _pricing_data:
            logger.fatal(
                f"No FSx pricing data retrieved. Check auth for pricing API at region {_pricing_region}."
            )

        logger.info(
            f"Pricing data retrieved: {_pricing_pages} pages, {_pricing_entries} entries"
        )
        return _pricing_data

    def get_fsx_deployment_options(self, region: Optional[str] = None) -> dict:
        """
        Get the deployment options for FSx
        """

        _reply_data: dict = {}
        _pricing_data = self.get_fsx_pricing_data(region=region if region else None)

        logger.debug(f"Pricing data retrieved len: {len(_pricing_data)} ")

        for _entry in _pricing_data:
            _pricing = ast.literal_eval(_entry)
            _attribs = _pricing.get("product", {}).get("attributes", {})
            if not _attribs:
                # something didn't work for this region - just skip it
                continue

            _region = _attribs.get("regionCode", "")
            _dep_type = _attribs.get("deploymentOption", "")
            _fs_type = _attribs.get("fileSystemType", "")
            _usage_type = _attribs.get("usagetype", "")

            # SnapLock is "" , Backup is "N/A". Skip em.
            if "N/A" in _dep_type or _dep_type == "":
                continue

            if _region not in _reply_data:
                _reply_data[_region] = {}

            if _fs_type not in _reply_data[_region]:
                _reply_data[_region][_fs_type] = []

            if _dep_type not in _reply_data[_region][_fs_type]:
                _reply_data[_region][_fs_type].append(_dep_type)
        logger.debug(f"Reply Data len: {len(_reply_data)}")
        return _reply_data

    def get_fsx_deployment_options_by_region(self, region: str) -> dict:
        """
        Get the deployment options for FSx in a specific region
        """

        logger.debug(f"Getting FSx deployment options for region {region}")

        _fsx_deployment_options: dict = self.get_fsx_deployment_options(region=region)

        if not _fsx_deployment_options:
            logger.fatal(f"No FSx deployment options retrieved. Check auth.")

        if not _fsx_deployment_options.get(region, {}):
            logger.fatal(
                f"No FSx deployment options retrieved for region {region}. Check auth."
            )

        logger.debug(
            f"FSx Deployment Options for region {region}: {len(_fsx_deployment_options.get(region, {}))}"
        )
        return {region: _fsx_deployment_options.get(region, {})}

    def _storage_build_fsx_ontap_filesystem(self, fs_key: str):
        """
        Build an FSx/ONTAP filesystem.
        """
        logger.debug(f"_storage_build_fsx_ontap_filesystem called for {fs_key}")

        _deployment_type: str = get_config_key(
            key_name=f"Config.storage.{fs_key}.fsx_ontap.deployment_type",
            expected_type=str,
            required=False,
            default="MULTI_AZ_2",
        ).upper()

        # Determine the regions that various FSx types are supported
        _fsx_regional_capability: dict = self.get_fsx_deployment_options_by_region(
            region=user_specified_variables.region
        )

        _throughput_capacity: int = get_config_key(
            key_name=f"Config.storage.{fs_key}.fsx_ontap.throughput_capacity",
            expected_type=int,
            required=False,
            default=256,
        )

        _allowed_throughput_capacity = {
            "MULTI_AZ_1": [128, 256, 512, 1024, 2048, 4096],
            "MULTI_AZ_2": [384, 768, 1536, 3072, 6144],
            "SINGLE_AZ_1": [128, 256, 512, 1024, 2048, 4096],
            # "SINGLE_AZ_2": Too many options, will let CLoudFormation returns the error based on HA pair
        }

        if _deployment_type in _allowed_throughput_capacity:
            if (
                _throughput_capacity
                not in _allowed_throughput_capacity[_deployment_type]
            ):
                logger.fatal(
                    f"Invalid throughput_capacity {_throughput_capacity} for {_deployment_type}. Accepted value: {_allowed_throughput_capacity[_deployment_type]}"
                )

        _storage_capacity: int = get_config_key(
            key_name=f"Config.storage.{fs_key}.fsx_ontap.storage_capacity",
            expected_type=int,
            required=False,
            default=1024,
        )

        # Is the desired deployment type supported in the region?
        # Note that the Pricing API uses underscore (_) while the CFN string uses dashes (-)
        # So we need to convert the CFN string to underscore
        # There is also a case difference between the service names to accomodate
        # So we make an extra copy of the string that we plan to mutate
        _dep_type_lookup: str = _deployment_type.replace("_", "-").upper()

        if _deployment_type == "MULTI_AZ_1":
            _dep_type_lookup = "Multi-AZ"
        elif _deployment_type == "MULTI_AZ_2":
            _dep_type_lookup = "Multi-AZ-2"
        elif _deployment_type == "SINGLE_AZ_1":
            _dep_type_lookup = "Single-AZ_2N"
        elif _deployment_type == "SINGLE_AZ_2":
            _dep_type_lookup = "Single-AZ_2N-2"

        logger.debug(
            f"Checking if deployment type {_deployment_type} ({_dep_type_lookup=}) is supported in region {user_specified_variables.region}"
        )

        if _dep_type_lookup not in _fsx_regional_capability.get(
            user_specified_variables.region, {}
        ).get("ONTAP", []):
            logger.fatal(
                f"Config.storage.{fs_key}.fsx_ontap.deployment_type {_deployment_type} ({_dep_type_lookup=}) is not supported in region {user_specified_variables.region}"
            )

        _automatic_backup_retention_days: int = get_config_key(
            key_name=f"Config.storage.{fs_key}.fsx_ontap.automatic_backup_retention_days",
            expected_type=int,
            required=False,
            default=7,
        )

        _daily_automatic_backup_start_time: str = get_config_key(
            key_name=f"Config.storage.{fs_key}.fsx_ontap.daily_automatic_backup_start_time",
            expected_type=str,
            required=False,
            default="00:00",
        )

        _junction_path: str = get_config_key(
            key_name=f"Config.storage.{fs_key}.fsx_ontap.junction_path",
            expected_type=str,
            required=True,
        )

        _netbios_name: str = get_config_key(
            key_name=f"Config.storage.{fs_key}.fsx_ontap.netbios_name",
            expected_type=str,
            required=True,
        ).upper()

        if len(_netbios_name) > 15:
            logger.fatal(
                f"Config.storage.{fs_key}.fsx_ontap.netbios_name must be 15 characters or less"
            )

        _file_system_administrators_group: str = get_config_key(
            key_name=f"Config.storage.{fs_key}.fsx_ontap.file_system_administrators_group",
            expected_type=str,
            default="AWS Delegated FSx Administrators",
            required=False,
        ).upper()

        _organizational_unit_distinguished_name: str = get_config_key(
            key_name=f"Config.storage.{fs_key}.fsx_ontap.organizational_unit_distinguished_name",
            expected_type=str,
            default=f"OU=Computers, OU={self.directory_service_resource_setup.get('short_name')},{self.directory_service_resource_setup.get('domain_base')}",
            required=False,
        ).upper()

        _secret_name = (
            f"/soca/{user_specified_variables.cluster_id}/FSxOntapAdminPassword{fs_key}"
        )
        _fsx_admin_password = secretsmanager_helper.create_secret(
            scope=self,
            construct_id=f"FSxOntapAdminPassword{fs_key}",
            secret_name=_secret_name,
            secret_string_template='{"username": "fsxadmin"}',
            kms_key_id=(
                self.soca_resources["secretsmanager_kms_key_id"]
                if self.soca_resources["secretsmanager_kms_key_id"]
                else None
            ),
        )

        # Find all private subnets VPC to deploy FSxONTAP. Note Only 2 can be configured
        # Associate FSxN with all Private Route Tables of your VPC

        _vpc_subnets_id: list = []
        _route_table_ids: list = []

        logger.debug(
            f"FSx/ONTAP - User selected the following private subnets: {user_specified_variables.private_subnets=}"
        )

        # Determine our subnet usage
        # did we select private subnets / existing resources during installation?
        _fsx_ontap_source_subnets: dict = {}

        if user_specified_variables.private_subnets is not None:
            logger.debug(
                f"FSx/ONTAP - User selected subnets - probable Existing Resources installation"
            )
            for _sn in user_specified_variables.private_subnets:
                # ['subnet-123,us-east-1b', ...]
                _sn_id: str = _sn.split(",")[0]
                if _sn_id not in _fsx_ontap_source_subnets:
                    # route_table_id comes later
                    _fsx_ontap_source_subnets[_sn_id] = {
                        "subnet_id": _sn_id,
                    }
                    logger.debug(
                        f"FSx/ONTAP - User selected the following private subnet: {_sn_id=} / AZ: {_sn.split(',')[1]}"
                    )
                else:
                    logger.fatal(
                        f"FSx/ONTAP - Duplicate subnet {_sn_id} selected. Subnets now {_fsx_ontap_source_subnets=}. Probable defect?"
                    )

            # Now that we have built up _fsx_ontap_source_subnets, we need to populate the route table info
            _rt_dict: dict = get_subnet_route_table_by_subnet_id(
                subnet_ids=list(_fsx_ontap_source_subnets.keys())
            )

            if not _rt_dict:
                logger.fatal(
                    f"FSx/ONTAP - Unable to lookup route tables for {_fsx_ontap_source_subnets=}"
                )

            for _sn_id in _rt_dict:
                _rt_id: str = _rt_dict.get(_sn_id, "")
                if not _rt_id:
                    logger.fatal(
                        f"FSx/ONTAP - Unable to lookup route table for subnet {_sn_id}"
                    )
                logger.debug(
                    f"FSx/ONTAP - Using Route Table {_rt_id} for subnet {_sn_id}"
                )
                _fsx_ontap_source_subnets[_sn_id].update({"route_table_id": _rt_id})

        else:
            # New VPC
            logger.debug(
                f"FSx/ONTAP - No User selected subnets - probable New VPC installation"
            )
            for _sn in (
                self.soca_resources["vpc"]
                .select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_EGRESS)
                .subnets
            ):
                if _sn not in _fsx_ontap_source_subnets:
                    _fsx_ontap_source_subnets[_sn.subnet_id] = {
                        "subnet_id": _sn.subnet_id,
                        "route_table_id": _sn.route_table.route_table_id,
                    }
                    logger.debug(
                        f"FSx/ONTAP - Using VPC subnet {_sn.subnet_id} / RTB: {_sn.route_table.route_table_id} . Subnets now {_fsx_ontap_source_subnets=}"
                    )
                else:
                    logger.fatal(
                        f"FSx/ONTAP - Duplicate subnet {_sn.subnet_id} selected. Subnets now {_fsx_ontap_source_subnets=}. Probable defect?"
                    )

        logger.debug(
            f"FSx/ONTAP - Final FSx/Source Subnets/RTB for consideration: {_fsx_ontap_source_subnets=}"
        )

        for _subnet in list(_fsx_ontap_source_subnets.keys()):
            if _subnet not in _vpc_subnets_id:

                logger.debug(f"FSx/ONTAP - Adding VPC subnet {_subnet}")
                _vpc_subnets_id.append(_subnet)

                _route_id = _fsx_ontap_source_subnets.get(_subnet, {}).get(
                    "route_table_id", ""
                )
                if not _route_id:
                    logger.fatal(
                        f"FSx/ONTAP - Unable to lookup route table for subnet {_subnet}"
                    )

                if _route_id not in _route_table_ids:
                    _route_table_ids.append(_route_id)
                    logger.debug(
                        f"FSx/ONTAP - Adding Route Table {_route_id} . Route Tables now {_route_table_ids=}"
                    )
                else:
                    # This is just when multiple subnets share the same route table, which is fine
                    logger.info(
                        f"FSx/ONTAP - Route Table {_route_id} already exists for filesystem consideration. Route Tables now {_route_table_ids=} (not an indication of a problem)"
                    )
            else:
                # This gets a warning as it shouldn't happen
                logger.warning(
                    f"FSx/ONTAP - Subnet {_subnet.subnet_id} already exists. Subnets now {_vpc_subnets_id=}.  Defect?"
                )

        # Determine KMS config
        _kms_key_id = get_kms_key_id(
            config_key_names=[
                f"Config.storage.{fs_key}.kms_key_id",  # The proper location providing per-fs keys
                "Config.storage.kms_key_id",  # Fallback to a global storage kms_key_id
            ],
            allow_global_default=True,
        )
        logger.debug(f"FSx KMS for {fs_key}: {_kms_key_id}")

        # Create the Security group for the filesystem
        self.soca_resources[f"fs_{fs_key}_sg"] = ec2.SecurityGroup(
            self,
            id=f"FSxOntap{fs_key.capitalize()}SecurityGroup",
            vpc=self.soca_resources["vpc"],
            description=f"FSx/ONTAP {fs_key.capitalize()} Security Group",
        )

        # Create our rules (TCP and UDP) for each peer expected to consume the filesystem
        # https://docs.aws.amazon.com/fsx/latest/ONTAPGuide/limit-access-security-groups.html
        for _sg_peer in [
            f"fs_{fs_key}_sg",
            "compute_node_sg",
            "controller_sg",
            "login_node_sg",
        ]:
            for _port, _desc in {
                "22-11105": f"Allow FSx/ONTAP from {_sg_peer}"
            }.items():
                logger.debug(f"Adding TCP {_port} for {_sg_peer}")
                _rules: list[ec2.Port] = []
                if "-" in _port:
                    _from_port: int = int(_port.split("-")[0])
                    _to_port: int = int(_port.split("-")[1])
                    _rules.append(
                        ec2.Port.tcp_range(start_port=_from_port, end_port=_to_port)
                    )
                    _rules.append(
                        ec2.Port.udp_range(start_port=_from_port, end_port=_to_port)
                    )
                else:
                    _rules.append(ec2.Port.tcp(int(_port)))
                    _rules.append(ec2.Port.udp(int(_port)))

                for _rule in _rules:
                    logger.debug(f"Adding ingress rule for {_rule}")
                    security_groups_helper.create_ingress_rule(
                        security_group=self.soca_resources[f"fs_{fs_key}_sg"],
                        peer=self.soca_resources[_sg_peer],
                        connection=_rule,
                        description=f"{_sg_peer} {_port}",
                    )
        Tags.of(self.soca_resources[f"fs_{fs_key}_sg"]).add(
            "Name",
            f"{user_specified_variables.cluster_id}-ONTAP{fs_key.capitalize()}SG",
        )

        if _deployment_type in ["MULTI_AZ_1", "MULTI_AZ_2"]:
            _ontap_configuration_property = fsx.CfnFileSystem.OntapConfigurationProperty(
                preferred_subnet_id=_vpc_subnets_id[0],
                route_table_ids=_route_table_ids,
                deployment_type=_deployment_type,
                throughput_capacity=_throughput_capacity,
                automatic_backup_retention_days=_automatic_backup_retention_days,
                daily_automatic_backup_start_time=_daily_automatic_backup_start_time,
                fsx_admin_password=secretsmanager_helper.resolve_secret_as_str(
                    secret_construct=_fsx_admin_password, password_key="password"
                ),
            )
        elif _deployment_type in ["SINGLE_AZ_1", "SINGLE_AZ_2"]:
            # todo: add this
            pass
        else:
            logger.error(
                f"Ontap {_deployment_type=} must be SINGLE_AZ_1, SINGLE_AZ_2, MULTI_AZ_1 or MULTI_AZ_2 "
            )

        # Define the FSx for ONTAP filesystem
        _ontap_filesystem = fsx.CfnFileSystem(
            self,
            f"FSxOntap{fs_key.capitalize()}",
            subnet_ids=_vpc_subnets_id[:2],  # 2 subnets max
            file_system_type="ONTAP",
            kms_key_id=_kms_key_id if _kms_key_id else "alias/aws/fsx",
            storage_capacity=_storage_capacity,
            ontap_configuration=_ontap_configuration_property,
            security_group_ids=[
                self.soca_resources[f"fs_{fs_key}_sg"].security_group_id
            ],
            tags=[
                {
                    "key": "Name",
                    "value": f"{user_specified_variables.cluster_id}-{fs_key.capitalize()}",
                },
                {
                    "key": "soca:BackupPlan",
                    "value": user_specified_variables.cluster_id,
                },
                {"key": "soca:FsxAdminSecretName", "value": _secret_name},
            ],
        )

        # Create the SVM
        if not self.directory_service_resource_setup.get("domain_controller_ips", []):
            logger.fatal(
                "Unable to retrieve Domain Controller IPs. If using existing AD, you must specific dc_ips"
            )

        logger.debug(
            f"Using AD/DC IP addresses: {self.directory_service_resource_setup.get('domain_controller_ips')}"
        )

        _fsx_active_directory_configuration = fsx.CfnStorageVirtualMachine.ActiveDirectoryConfigurationProperty(
            net_bios_name=_netbios_name,
            self_managed_active_directory_configuration=fsx.CfnStorageVirtualMachine.SelfManagedActiveDirectoryConfigurationProperty(
                dns_ips=self.directory_service_resource_setup["domain_controller_ips"],
                domain_name=self.directory_service_resource_setup.get("domain_name"),
                file_system_administrators_group=_file_system_administrators_group,
                organizational_unit_distinguished_name=_organizational_unit_distinguished_name,
                password=(
                    self.directory_service_resource_setup["ds_admin_password"]
                    .secret_value_from_json("password")
                    .to_string()
                    if self.directory_service_resource_setup["use_existing_directory"]
                    is False
                    else self.directory_service_resource_setup["ds_admin_password"]
                ),
                user_name=self.directory_service_resource_setup["ds_admin_username"],
            ),
        )

        self.soca_resources[f"fs_{fs_key}"] = fsx.CfnStorageVirtualMachine(
            self,
            f"SVMFSxOntap{fs_key.capitalize()}",
            file_system_id=_ontap_filesystem.ref,
            name=f"SVMFSxOntap{fs_key.capitalize()}",
            active_directory_configuration=_fsx_active_directory_configuration,
            root_volume_security_style="UNIX",
        )

        if self.directory_service_resource_setup.get("use_existing_directory") is False:
            self.soca_resources[f"fs_{fs_key}"].node.add_dependency(
                self.directory_service_resource_setup.get("ds")
            )

        _volume = fsx.CfnVolume(
            self,
            f"VolumeFSxOntap{fs_key.capitalize()}",
            name=f"VolumeFSxOntap{fs_key.capitalize()}",
            volume_type="ONTAP",
            ontap_configuration=fsx.CfnVolume.OntapConfigurationProperty(
                storage_virtual_machine_id=self.soca_resources[
                    f"fs_{fs_key}"
                ].attr_storage_virtual_machine_id,
                ontap_volume_type="RW",
                storage_efficiency_enabled="true",
                volume_style="FLEXVOL",
                junction_path=_junction_path,
                size_in_bytes=str(_storage_capacity * 1024**3),
                security_style="UNIX",
            ),
            tags=[CfnTag(key="soca:OntapFirstSetup", value="true")],
        )

        self.soca_filesystems[f"{fs_key}"] = {
            "provider": "fsx_ontap",
            "mount_path": f"/{fs_key}",
            "mount_options": "defaults,noatime,_netdev",
            "mount_target": _volume.attr_volume_id,
            "on_mount_failure": "exit",
            "enabled": "true",
        }

    def _storage_build_fsx_openzfs_filesystem(self, fs_key: str):
        """
        Build an FSx/OpenZFS filesystem.
        """
        pass

    def storage(self):
        """
        Create filesystems that will be mounted. This reads Config.storage to create all filesystems.
        An entry for apps and data are required. Others are optional.
        """

        _fs_list: dict = get_config_key(
            key_name="Config.storage", required=True, expected_type=dict
        )

        logger.debug(f"Storage Configuration tree: {_fs_list}")

        # First - make sure we have our required apps and data
        # , and they are mounted on /apps and /data
        for _req_fs in {"apps", "data"}:
            if not _fs_list.get(_req_fs):
                raise ValueError(f"Missing required {_req_fs} filesystem configuration")
            if not isinstance(_fs_list.get(_req_fs), dict):
                raise ValueError(f"Invalid {_req_fs} filesystem configuration")

            # Allow for mount_point or mountpoint in the YML
            _configured_mountpoint_str: str = _fs_list.get(_req_fs).get(
                "mount_point", _fs_list.get(_req_fs).get("mountpoint", "")
            )

            if not _configured_mountpoint_str:
                raise ValueError(f"Missing required {_req_fs} filesystem mountpoint")

            if _configured_mountpoint_str != f"/{_req_fs}":
                raise ValueError(
                    f"Mountpoint for {_req_fs} must be /{_req_fs}. Found {_configured_mountpoint_str}"
                )

            logger.debug(f"Validated {_req_fs} filesystem configuration")

        # Do a quick sanity check on the names to make sure they are alnum
        for _fs in _fs_list:
            if _fs == "kms_key_id":
                logger.debug(
                    f"Skipping Storage-wide KMS key ID specification as a filesystem (Config.kms_key_id) - (this is perfectly OK)"
                )
                continue

            if not _fs.isalnum():
                raise ValueError(
                    f"Invalid filesystem key name: {_fs} . Use only alphanumeric key names and try again"
                )

        # Do a quick scan to see if we need EFS/SNS alarms
        # We have to do this prior to the filesystem create loop since the downstream resources will need this to be created
        for _fs in _fs_list:
            if _fs == "kms_key_id":
                logger.debug(
                    f"Skipping Storage-wide KMS key ID specification as a filesystem (Config.kms_key_id) - (this is perfectly OK)"
                )
                continue

            _fs_provider: str = get_config_key(
                key_name=f"Config.storage.{_fs}.provider",
                required=False,
                expected_type=str,
                default="efs",
            ).lower()

            logger.debug(f"Provider for {_fs}: {_fs_provider}")
            if _fs_provider == "efs":
                # Only one per cluster is needed
                if not self.soca_resources.get("sns_efs_topic"):
                    _sns_kms_key_id: str = get_kms_key_id(
                        config_key_names=[
                            "Config.storage.kms_key_id",  # Should there be an alternate for the SNS Key?
                        ],
                        allow_global_default=True,
                    )
                    logger.debug(f"SNS KMS for EFS-SNS Topic: {_sns_kms_key_id=}")

                    if _sns_kms_key_id:
                        _sns_kms_ikey = kms.Key.from_key_arn(
                            self,
                            id="SNSKeyID",
                            key_arn=_sns_kms_key_id,
                        )
                    else:
                        # Import the service default alias
                        _sns_kms_ikey = kms.Key.from_lookup(
                            self,
                            id="SNSKeyID",
                            alias_name="alias/aws/sns",
                        )
                        # logger.debug(f"SNS Topic using service-default KMS key alias/aws/sns")

                    logger.debug(
                        f"SNS KMS for EFS-SNS Topic: {_sns_kms_key_id=} / {_sns_kms_ikey=}"
                    )

                    # Create CloudWatch/SNS alarm for SNS EFS. This will check BurstCreditBalance and increase allocated throughput to support temporary burst activity if needed
                    self.soca_resources["sns_efs_topic"] = sns.Topic(
                        self,
                        id="SNSEFSTopic",
                        display_name=f"{user_specified_variables.cluster_id}-EFSAlarm-SNS",
                        topic_name=f"{user_specified_variables.cluster_id}-EFSAlarm-SNS",
                        master_key=_sns_kms_ikey if _sns_kms_ikey else None,
                    )
                    self.soca_resources["sns_efs_topic"].add_to_resource_policy(
                        iam.PolicyStatement(
                            effect=iam.Effect.ALLOW,
                            actions=["sns:Publish"],
                            resources=[self.soca_resources["sns_efs_topic"].topic_arn],
                            principals=[
                                iam.ServicePrincipal(principals_suffix["cloudwatch"])
                            ],
                            conditions={
                                "ArnLike": {
                                    "aws:SourceArn": f"arn:{Aws.PARTITION}:*:*:{Aws.ACCOUNT_ID}:*"
                                }
                            },
                        )
                    )

                    efs_throughput_lambda = aws_lambda.Function(
                        self,
                        f"{user_specified_variables.cluster_id}-EFSLambda",
                        function_name=f"{user_specified_variables.cluster_id}-EFSThroughput",
                        description="Check EFS BurstCreditBalance and update ThroughputMode when needed",
                        memory_size=128,
                        role=self.soca_resources["efs_lambda_role"],
                        timeout=Duration.minutes(3),
                        runtime=typing.cast(
                            aws_lambda.Runtime, get_lambda_runtime_version()
                        ),
                        log_retention=logs.RetentionDays.INFINITE,
                        handler="EFSThroughputLambda.lambda_handler",
                        code=aws_lambda.Code.from_asset(
                            "../functions/EFSThroughputLambda"
                        ),
                    )
                    efs_throughput_lambda.node.add_dependency(
                        self.soca_resources["efs_lambda_role"]
                    )

                    # TODO - FIXME - These should be in sync with the above values
                    efs_throughput_lambda.add_environment(
                        "EFSBurstCreditLowThreshold", "10000000"
                    )
                    efs_throughput_lambda.add_environment(
                        "EFSBurstCreditHighThreshold", "2000000000000"
                    )
                    efs_throughput_lambda.add_permission(
                        "InvokePermission",
                        principal=iam.ServicePrincipal(principals_suffix["sns"]),
                        action="lambda:InvokeFunction",
                    )

                    sns.Subscription(
                        self,
                        f"{user_specified_variables.cluster_id}-SNSEFSSubscription",
                        protocol=sns.SubscriptionProtocol.LAMBDA,
                        endpoint=efs_throughput_lambda.function_arn,
                        topic=self.soca_resources["sns_efs_topic"],
                    )
                else:
                    logger.debug(
                        f"EFS filesystems detected - SNS/Alarming infrastructure previously created"
                    )
            else:
                logger.debug(f"EFS filesystems not detected for {_fs}")

        # Continue with creating filesystems
        for _fs in _fs_list:
            if _fs == "kms_key_id":
                logger.debug(
                    f"Skipping Storage-wide KMS key ID specification as a filesystem (Config.kms_key_id) - (this is perfectly OK)"
                )
                continue
            _fs_provider = getattr(user_specified_variables, f"fs_{_fs}_provider", None)

            logger.debug(f"Provider for {_fs}: {_fs_provider}")
            match _fs_provider:
                case "efs":
                    self._storage_build_efs_filesystem(fs_key=_fs)
                case "fsx_lustre":
                    self._storage_build_fsx_lustre_filesystem(fs_key=_fs)
                case "fsx_ontap":
                    self._storage_build_fsx_ontap_filesystem(fs_key=_fs)
                case "fsx_openzfs":
                    self._storage_build_fsx_openzfs_filesystem(fs_key=_fs)
                case _:
                    raise ValueError(
                        f"Invalid provider: {_fs_provider} for {_fs} - unable to continue"
                    )

        logger.debug(f"Storage Configuration completed")

    def controller(self):
        """
        Create the Controller EC2 instance, configure user data and assign EIP
        """

        logger.debug(f"DEBUG: UserSpecVars: {user_specified_variables}")

        # Make sure our filesystems are fully qualified
        _fs_apps_provider: str = user_specified_variables.fs_apps_provider
        if user_specified_variables.fs_apps_provider:
            _fs_apps_dns: str = f"{user_specified_variables.fs_apps}"
        else:
            _fs_apps_dns: str = storage_helper.get_filesystem_dns(
                storage_construct=self.soca_resources["fs_apps"],
                storage_provider=_fs_apps_provider,
                endpoints_suffix=endpoints_suffix,
                fsx_ontap_junction_path=(
                    None
                    if _fs_apps_provider != "fsx_ontap"
                    else get_config_key(
                        key_name=f"Config.storage.apps.fsx_ontap.junction_path",
                        expected_type=str,
                    )
                ),
            )
        _fs_data_provider: str = user_specified_variables.fs_data_provider
        if user_specified_variables.fs_data_provider:
            _fs_data_dns: str = f"{user_specified_variables.fs_data}"
        else:
            _fs_data_dns: str = storage_helper.get_filesystem_dns(
                storage_construct=self.soca_resources["fs_data"],
                storage_provider=_fs_data_provider,
                endpoints_suffix=endpoints_suffix,
                fsx_ontap_junction_path=(
                    None
                    if _fs_data_provider != "fsx_ontap"
                    else get_config_key(
                        key_name=f"Config.storage.data.fsx_ontap.junction_path",
                        expected_type=str,
                    )
                ),
            )

        # We manually replace  the variable with the relevant ParameterStore as all ParamStore hierarchy is created at the very end of this CDK
        _user_data_variables = {
            "/configuration/BaseOS": user_specified_variables.base_os,
            "/configuration/ClusterId": user_specified_variables.cluster_id,
            "/configuration/UserDirectory/provider": get_config_key(
                key_name="Config.directoryservice.provider"
            ),
            "/configuration/Region": user_specified_variables.region,
            "/configuration/Version": "25.5.0",
            "/configuration/CustomAMI": self.soca_resources["ami_id"],
            "/configuration/S3Bucket": user_specified_variables.bucket,
            "/configuration/HPC/SchedulerEngine": get_config_key(
                key_name="Config.scheduler.scheduler_engine",
                required=False,
                default="openpbs",
            ),
            "/configuration/Cache/enabled": self.cache_info.get("enabled"),
            "/configuration/Cache/port": self.cache_info.get("port"),
            "/configuration/Cache/endpoint": self.cache_info.get("endpoint"),
            "/job/NodeType": "controller",
        }

        # add all System hierarchy
        _parameter_store_keys = flatten_parameterstore_config(
            get_config_key(key_name="Parameters", expected_type=dict),
        )
        for _ssm_parameter_key, _ssm_parameter_value in _parameter_store_keys.items():
            _user_data_variables[f"/{_ssm_parameter_key}"] = _ssm_parameter_value

        # Generate EC2 User Data and clean all copyright header to save some space
        _user_data = user_data_helper.remove_text(
            text_to_remove=[
                "# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.",
                "# SPDX-License-Identifier: Apache-2.0",
            ],
            data=self.jinja2_env.get_template(
                "user_data/controller/01_user_data.sh.j2"
            ).render(
                context=_user_data_variables,
                ns=SimpleNamespace(template_already_included=[]),
            ),
        )

        os.makedirs(
            f"{pathlib.Path.cwd().parent}/upload_to_s3/bootstrap/controller/",
            exist_ok=True,
        )

        # Because of size limitation, scripts needed during bootstrap are stored on s3
        _templates_to_render = [
            "user_data/controller/02_prerequisites",
            "templates/linux/system_packages/install_required_packages",
            "templates/linux/filesystems_automount",
        ]

        for template in _templates_to_render:

            _t = self.jinja2_env.get_template(f"{template}.sh.j2").render(
                context=_user_data_variables,
                ns=SimpleNamespace(template_already_included=[]),
            )
            with open(
                f"{pathlib.Path.cwd().parent}/upload_to_s3/bootstrap/controller/{template.split('/')[-1]}.sh",
                "w",
            ) as f:
                f.write(_t)

        shutil.copy(
            f"{pathlib.Path.cwd().parent}/user_data/controller/03_setup.sh.j2",
            f"{pathlib.Path.cwd().parent}/upload_to_s3/bootstrap/controller",
        )

        # Choose subnet where to deploy the controller
        if not user_specified_variables.vpc_id:
            # We created the VPC
            vpc_subnets = ec2.SubnetSelection(
                subnets=[self.soca_resources["vpc"].private_subnets[0]]
            )
        else:
            # Existing VPC was used
            # format is subnet-123,us-east-1a
            subnet_info = user_specified_variables.private_subnets[0].split(",")

            logger.debug(
                f"Using existing VPC subnet for Controller subnet: {subnet_info}"
            )

            launch_subnet = ec2.Subnet.from_subnet_attributes(
                self,
                "ControllerSubnet",
                availability_zone=subnet_info[1],
                subnet_id=subnet_info[0],
            )
            vpc_subnets = ec2.SubnetSelection(subnets=[launch_subnet])
            logger.debug(f"Controller Subnet: {vpc_subnets}")
        # Create the Controller Instance

        _volume_type_str: str = get_config_key(
            key_name="Config.controller.volume_type",
            required=False,
            default="gp3",
            expected_type=str,
        ).lower()

        _volume_type = return_ebs_volume_type(volume_string=_volume_type_str)

        _ebs_volume_key_id: str = get_kms_key_id(
            config_key_names=[
                "Config.controller.volume_kms_key_id",  # Current key name
                "Config.controller.kms_key_id",  # Alternative
                "Config.scheduler.volume_kms_key_id",  # legacy key name
                "Config.scheduler.kms_key_id",  # Alternative
            ],
            allow_global_default=True,
        )
        logger.debug(f"Controller EBS encryption: KeyID: {_ebs_volume_key_id}")

        _volume_iops = get_config_key(
            key_name="Config.controller.volume_iops",
            required=False,
            default=0,
            expected_type=int,
        )

        _volume_throughput = get_config_key(
            key_name="Config.controller.volume_throughput",
            required=False,
            default=0,
            expected_type=int,
        )

        # Fixup some configs for specific volume types
        logger.debug(f"Performing EBS fixups for volume_type - {_volume_type}")

        match _volume_type_str:
            case "gp3":
                logger.debug(f"Performing EBS fixups for gp3")
                if not _volume_iops:
                    _volume_iops = 3000
                if not _volume_throughput:
                    _volume_throughput = 125
            case "io1":
                logger.debug(f"Performing EBS fixups for io1")
                if _volume_throughput:
                    _volume_throughput = None

        logger.debug(f"Controller EBS volume IOPS: {_volume_iops}")
        logger.debug(f"Controller EBS volume throughput: {_volume_throughput}")

        self.soca_resources["controller_instance"] = ec2.Instance(
            self,
            f"{user_specified_variables.cluster_id}-ControllerInstance",
            availability_zone=vpc_subnets.availability_zones,
            machine_image=ec2.MachineImage.generic_linux(
                {user_specified_variables.region: self.soca_resources["ami_id"]}
            ),
            instance_type=ec2.InstanceType(self._instance_type),
            key_pair=ec2.KeyPair.from_key_pair_attributes(
                self,
                "SchedulerKeyPair",
                key_pair_name=user_specified_variables.ssh_keypair,
            ),
            vpc=self.soca_resources["vpc"],
            propagate_tags_to_volume_on_creation=True,
            block_devices=[
                ec2.BlockDevice(
                    device_name=self.return_ebs_volume_name(
                        base_os=user_specified_variables.base_os
                    ),
                    volume=ec2.BlockDeviceVolume(
                        ebs_device=ec2.EbsDeviceProps(
                            encrypted=True if _ebs_volume_key_id else False,
                            kms_key=(
                                kms.Key.from_key_arn(
                                    self,
                                    id="ControllerEBSKMSKey",
                                    key_arn=_ebs_volume_key_id,
                                )
                                if _ebs_volume_key_id
                                else None
                            ),
                            volume_size=get_config_key(
                                key_name="Config.controller.volume_size",
                                expected_type=int,
                            ),
                            volume_type=_volume_type,
                            iops=_volume_iops if _volume_iops else None,
                            throughput=(
                                _volume_throughput if _volume_throughput else None
                            ),
                        )
                    ),
                )
            ],
            role=self.soca_resources["controller_role"],
            security_group=self.soca_resources["controller_sg"],
            vpc_subnets=vpc_subnets,
            user_data=ec2.UserData.custom(_user_data),
            require_imdsv2=(
                True
                if get_config_key(
                    key_name="Config.metadata_http_tokens",
                    default="required",
                    required=False,
                ).lower()
                == "required"
                else False
            ),
        )

        Tags.of(self.soca_resources["controller_instance"]).add(
            key="Name", value=f"{user_specified_variables.cluster_id}-Controller"
        )

        Tags.of(self.soca_resources["controller_instance"]).add(
            key="soca:NodeType", value=f"controller"
        )

        # XXX FIXME TODO - Should this take place when there isn't active backup plan?
        Tags.of(self.soca_resources["controller_instance"]).add(
            key="soca:BackupPlan", value=f"{user_specified_variables.cluster_id}"
        )

        # Ensure Filesystem are already up and running before creating the controller instance
        if not user_specified_variables.fs_apps:
            self.soca_resources["controller_instance"].node.add_dependency(
                self.soca_resources["fs_apps"]
            )
        if not user_specified_variables.fs_data:
            self.soca_resources["controller_instance"].node.add_dependency(
                self.soca_resources["fs_data"]
            )

        # OpenLDAP is installed by default on the controller machine
        if self.directory_service_resource_setup.get("provider") == "openldap":
            _secret_name = f"/soca/{user_specified_variables.cluster_id}/UserDirectoryServiceAccount"
            _openldap_secret = secretsmanager_helper.create_secret(
                scope=self,
                construct_id="UserDirectoryServiceAccount",
                secret_name=_secret_name,
                secret_string_template=f'{{"username":"CN=admin,{self.directory_service_resource_setup.get("domain_base")}"}}',
                kms_key_id=(
                    self.soca_resources["secretsmanager_kms_key_id"]
                    if self.soca_resources["secretsmanager_kms_key_id"]
                    else None
                ),
            )
            _openldap_secret.node.add_dependency(
                self.soca_resources["controller_instance"]
            )

            self.directory_service_resource_setup["service_account_secret_arn"] = (
                _openldap_secret.secret_full_arn
            )
            self.directory_service_resource_setup["endpoint"] = (
                f"ldaps://{self.soca_resources['controller_instance'].instance_private_dns_name}"
            )

        # FIXME TODO -
        # Other controller deps
        # VPC-Endpoints, Directory services, ElastiCache, VPC, Subnets, etc?
        # Some should be automatic - but always good to list them
        if self.soca_resources["elasticache"]:
            self.soca_resources["controller_instance"].node.add_dependency(
                self.soca_resources["elasticache"]
            )

    def configuration(self):
        """
        Store SOCA configuration in a Secret Manager's Secret.
        Controller/Compute Nodes have the permission to read the secret
        """
        solution_metrics_lambda = aws_lambda.Function(
            self,
            f"{user_specified_variables.cluster_id}-SolutionMetricsLambda",
            function_name=f"{user_specified_variables.cluster_id}-Metrics",
            description="Send SOCA anonymous Metrics to AWS",
            memory_size=128,
            role=self.soca_resources["solution_metrics_lambda_role"],
            timeout=Duration.minutes(3),
            runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
            log_retention=logs.RetentionDays.INFINITE,
            handler="SolutionMetricsLambda.lambda_handler",
            code=aws_lambda.Code.from_asset("../functions/SolutionMetricsLambda"),
        )

        # TODO FIXME - This can be cleaned up
        _subnet_listings: dict = {
            "public": [],
            "private": [],
        }

        if (
            user_specified_variables.public_subnets
            and user_specified_variables.private_subnets
        ):
            logger.debug(
                f"Using supplied public and private subnets for Param configuration"
            )

            # format for user_specified is subnet-123,us-east-1a
            for _sn in user_specified_variables.public_subnets:
                _sn_id: str = _sn.split(",")[0]
                logger.debug(f"Adding public subnet - {_sn_id}")
                _subnet_listings["public"].append(_sn_id)
            for _sn in user_specified_variables.private_subnets:
                _sn_id: str = _sn.split(",")[0]
                logger.debug(f"Adding private subnet - {_sn_id}")
                _subnet_listings["private"].append(_sn_id)

        else:
            # SOCA created the VPC - so it should be clean, and we can use the CDK methods
            logger.debug(f"Using SOCA created VPC subnets for Param configuration")

            for pub_sub in self.soca_resources["vpc"].public_subnets:
                logger.debug(f"Public subnet: {pub_sub.subnet_id}")
                _subnet_listings["public"].append(pub_sub.subnet_id)

            for priv_sub in self.soca_resources["vpc"].private_subnets:
                logger.debug(f"Private subnet: {priv_sub.subnet_id}")
                _subnet_listings["private"].append(priv_sub.subnet_id)

        # Determine our mounting for /apps and /data
        # /apps
        _fs_apps_provider: str = user_specified_variables.fs_apps_provider
        if user_specified_variables.fs_apps:
            _fs_apps_mount: str = f"{user_specified_variables.fs_apps}"
        else:
            _fs_apps_mount: str = storage_helper.get_filesystem_dns(
                storage_construct=self.soca_resources["fs_apps"],
                storage_provider=_fs_apps_provider,
                endpoints_suffix=endpoints_suffix,
                fsx_ontap_junction_path=(
                    None
                    if _fs_apps_provider != "fsx_ontap"
                    else get_config_key(
                        key_name=f"Config.storage.apps.fsx_ontap.junction_path",
                        expected_type=str,
                    )
                ),
            )

        # /data
        _fs_data_provider: str = user_specified_variables.fs_data_provider

        if user_specified_variables.fs_data:
            _fs_data_mount: str = f"{user_specified_variables.fs_data}"
        else:
            _fs_data_mount: str = storage_helper.get_filesystem_dns(
                storage_construct=self.soca_resources["fs_data"],
                storage_provider=_fs_data_provider,
                endpoints_suffix=endpoints_suffix,
                fsx_ontap_junction_path=(
                    None
                    if _fs_data_provider != "fsx_ontap"
                    else get_config_key(
                        key_name=f"Config.storage.data.fsx_ontap.junction_path",
                        expected_type=str,
                    )
                ),
            )

        # Allow config file over-ride of the SOCA admin default username
        if self.directory_service_resource_setup.get("use_existing_directory") is False:
            _def_admin_username: str = get_config_key(
                key_name="Config.admin_user_name",
                required=False,
                default="socaadmin",
                expected_type=str,
            )

            _secret_string: str = '{"username": "' + _def_admin_username + '"}'
            _default_soca_user_secret = secretsmanager_helper.create_secret(
                scope=self,
                construct_id="SocaAdminUserSecret",
                secret_name=f"/soca/{user_specified_variables.cluster_id}/SocaAdminUser",
                secret_string_template=_secret_string,
                kms_key_id=(
                    self.soca_resources["secretsmanager_kms_key_id"]
                    if self.soca_resources["secretsmanager_kms_key_id"]
                    else None
                ),
            )

        self.soca_resources["soca_config"] = {
            "VpcId": self.soca_resources["vpc"].vpc_id,
            "PublicSubnets": _subnet_listings.get("public", []),
            "PrivateSubnets": _subnet_listings.get("private", []),
            "ControllerPrivateIP": self.soca_resources[
                "controller_instance"
            ].instance_private_ip,
            "ControllerPrivateDnsName": self.soca_resources[
                "controller_instance"
            ].instance_private_dns_name,
            "ControllerInstanceId": self.soca_resources[
                "controller_instance"
            ].instance_id,
            "ControllerSecurityGroup": self.soca_resources[
                "controller_sg"
            ].security_group_id,
            "ComputeNodeSecurityGroup": self.soca_resources[
                "compute_node_sg"
            ].security_group_id,
            "ControllerIAMRoleArn": self.soca_resources["controller_role"].role_arn,
            "SpotFleetIAMRoleArn": self.soca_resources["spot_fleet_role"].role_arn,
            "ControllerIAMRole": self.soca_resources["controller_role"].role_name,
            "ComputeNodeIAMRoleArn": self.soca_resources["compute_node_role"].role_arn,
            "ComputeNodeIAMRole": self.soca_resources["compute_node_role"].role_name,
            "ComputeNodeInstanceProfileArn": f"arn:{Aws.PARTITION}:iam::{Aws.ACCOUNT_ID}:instance-profile/{self.soca_resources['compute_node_instance_profile'].ref}",
            "ClusterId": user_specified_variables.cluster_id,
            "Version": get_config_key("Config.version"),
            "Region": user_specified_variables.region,
            "S3Bucket": user_specified_variables.bucket,
            "SSHKeyPair": user_specified_variables.ssh_keypair,
            "CustomAMI": self.soca_resources["ami_id"],
            "CustomAMIMap": self.soca_resources["custom_ami_map"],
            "DCVEntryPointDNSName": self.soca_resources["alb"].load_balancer_dns_name,
            "LoadBalancerDNSName": self.soca_resources["alb"].load_balancer_dns_name,
            "LoadBalancerArn": self.soca_resources["alb"].load_balancer_arn,
            "NLBLoadBalancerDNSName": self.soca_resources["nlb"].load_balancer_dns_name,
            "BaseOS": user_specified_variables.base_os,
            "S3InstallFolder": user_specified_variables.cluster_id,
            "SolutionMetricsLambda": solution_metrics_lambda.function_arn,
            "DefaultMetricCollection": "true",
            "FileSystemDataProvider": _fs_data_provider,
            "FileSystemData": _fs_data_mount,
            "FileSystemAppsProvider": _fs_apps_provider,
            "FileSystemApps": _fs_apps_mount,
            "SkipQuotas": get_config_key(
                key_name="Config.skip_quotas", default=False, required=False
            ),
            "MetadataHttpTokens": get_config_key(
                key_name="Config.metadata_http_tokens"
            ),
            "DefaultVolumeType": get_config_key(
                key_name="Config.controller.volume_type"
            ),
            "HPCJobDeploymentMethod": "fleet",  # asg or fleet
            "HPC": {**get_config_key(key_name="Config.scheduler", expected_type=dict)},
            "AWSPCS": {
                **get_config_key(
                    key_name="Config.services.aws_pcs",
                    required=False,
                    default={},
                    expected_type=dict,
                )
            },
            # Defaults for eVDI/DCV
            "DCVDefaultVersion": get_config_key("Config.dcv.version"),
            "DCVAllowPreviousGenerations": False,  # Allow Previous Generation(older) instances
            "DCVAllowBareMetal": False,  # Allow Bare Metal instances to be shown
            "DCVAllowedInstances": get_config_key(
                key_name="Config.dcv.allowed_instances",
                required=False,
                expected_type=list,
                default=[
                    "m7i-flex.*",
                    "m5.*",
                    "g5.*",
                    "g6.*",
                ],  # List (with wildcard) of instances that are allowed. All rest are denied.
            ),
            "DCVDeniedInstances": [
                "*.48xlarge"
            ],  # Wildcards of instance types that should be denied that otherwise may be permitted in the AllowedInstances
            #
            "SchedulerDeploymentType": get_config_key(
                "Config.scheduler.deployment_type"
            ),
        }

        # Analytics configuration
        _is_analytics_enabled = get_config_key(
            key_name="Config.analytics.enabled",
            expected_type=bool,
            required=False,
            default=True,
        )
        _analytics_config = {
            "engine": get_config_key(
                key_name="Config.analytics.engine",
                expected_type=str,
                required=False,
                default="opensearch",
            ),
            "enabled": _is_analytics_enabled,
        }

        if _is_analytics_enabled:
            if not user_specified_variables.os_endpoint:
                _analytics_engine: str = _analytics_config.get("engine", "")
                logger.debug(f"Analytics engine: {_analytics_engine}")

                if _analytics_engine in {"opensearch"}:
                    _analytics_config["endpoint"] = (
                        f"https://{self.soca_resources['os_domain'].domain_endpoint}"
                    )
                elif _analytics_engine in {"opensearch_serverless", "aoss_serverless"}:
                    logger.debug(f"OS Endpoint: {self.soca_resources['os_domain']=}")
                    _analytics_config["endpoint"] = (
                        f"https://{self.soca_resources['os_domain'].attr_collection_endpoint}"
                    )
                else:
                    logger.fatal(
                        f"Unsupported analytics engine defined: {_analytics_engine}"
                    )
            else:
                logger.debug(
                    f"Analytics Endpoint: {user_specified_variables.os_endpoint=}"
                )
                if not user_specified_variables.os_endpoint.startswith(
                    "https://"
                ) and not user_specified_variables.os_endpoint.startswith("http://"):
                    _analytics_config["endpoint"] = (
                        f"https://{user_specified_variables.os_endpoint}"
                    )
                else:
                    _analytics_config["endpoint"] = user_specified_variables.os_endpoint
        else:
            _analytics_config["endpoint"] = "NO_ENDPOINT_CONFIGURED"

        # Store SOCA config on AWS SSM Parameter Store
        _parameter_store_prefix = f"/soca/{user_specified_variables.cluster_id}"

        # Retrieve all static SOCA parameters defined in default_config.yml (or config specified by user)
        _parameter_store_keys = flatten_parameterstore_config(
            get_config_key(key_name="Parameters", expected_type=dict)
        )
        for _ssm_parameter_key, _ssm_parameter_value in _parameter_store_keys.items():
            ssm.StringParameter(
                self,
                f"Parameter{_ssm_parameter_key}",
                parameter_name=f"{_parameter_store_prefix}/{_ssm_parameter_key}",
                string_value=str(_ssm_parameter_value),
                tier=ssm.ParameterTier.STANDARD,
            )

        # Flatten Config Dict

        # Remove unwanted config keys

        for ds_keys in [
            "ds",  # Optional if using existing_ad/openldap
            "ds_admin_username",  # We do not want to store this on SSM
            "ds_admin_password",  # We do not want to store this on SSM
        ]:
            if ds_keys in self.directory_service_resource_setup:
                del self.directory_service_resource_setup[ds_keys]

        # Make a copy of the list version of the obj
        _ds_resources = self.directory_service_resource_setup.copy()

        # Update directory_service_resource_setup[domain_controller_ips] list to a str for SSM
        _ds_resources["domain_controller_ips"] = str(
            self.directory_service_resource_setup["domain_controller_ips"]
        )

        _dicts_to_flatten = {
            "/configuration/Analytics": _analytics_config,
            "/configuration/UserDirectory": _ds_resources,
            "/configuration/Cache": flatten_parameterstore_config(self.cache_info),
            "/configuration/FileSystems": flatten_parameterstore_config(
                self.soca_filesystems
            ),
        }

        for _parent_prefix, _dict in _dicts_to_flatten.items():
            _dict_flattened = flatten_parameterstore_config(_dict)
            for _k, _v in _dict_flattened.items():

                ssm.StringParameter(
                    self,
                    f"Config{_parent_prefix.replace('/','-')}{_k}",
                    parameter_name=f"{_parameter_store_prefix}{_parent_prefix}/{_k}",
                    string_value=str(_v),
                    tier=ssm.ParameterTier.STANDARD,
                )

        # Retrieve dynamic SOCA parameters created during the CDK
        for _k, _v in self.soca_resources["soca_config"].items():
            ssm.StringParameter(
                self,
                f"Config{_k}",
                parameter_name=f"{_parameter_store_prefix}/configuration/{_k}",
                string_value=str(_v),
                tier=ssm.ParameterTier.STANDARD,
            )

        # Controller host has R/W permissions. Delete permissions are not allowed
        self.soca_resources["controller_role"].attach_inline_policy(
            iam.Policy(
                self,
                "AttachParameterStorePolicyToController",
                statements=[
                    iam.PolicyStatement(
                        actions=["ssm:DescribeParameters"],
                        effect=iam.Effect.ALLOW,
                        resources=["*"],
                    ),
                    iam.PolicyStatement(
                        actions=[
                            "ssm:GetParameters",
                            "ssm:GetParameterHistory",
                            "ssm:GetParametersByPath",
                            "ssm:GetParameter",
                            "ssm:PutParameter",
                        ],
                        effect=iam.Effect.ALLOW,
                        resources=[
                            f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:parameter{_parameter_store_prefix}/*"
                        ],
                    ),
                ],
            )
        )

        # All other nodes only have R permissions
        for _role in {"compute_node_role", "spot_fleet_role", "login_node_role"}:
            self.soca_resources[_role].attach_inline_policy(
                iam.Policy(
                    self,
                    f"AttachParameterStorePolicyTo{_role.split('_')[0].capitalize()}Node",
                    statements=[
                        iam.PolicyStatement(
                            actions=["ssm:DescribeParameters"],
                            effect=iam.Effect.ALLOW,
                            resources=["*"],
                        ),
                        iam.PolicyStatement(
                            actions=[
                                "ssm:GetParameters",
                                "ssm:GetParameterHistory",
                                "ssm:GetParametersByPath",
                                "ssm:GetParameter",
                            ],
                            effect=iam.Effect.ALLOW,
                            resources=[
                                f"arn:{Aws.PARTITION}:ssm:{Aws.REGION}:{Aws.ACCOUNT_ID}:parameter{_parameter_store_prefix}/*"
                            ],
                        ),
                    ],
                )
            )

        # Create IAM policy and attach it to both Controller and Compute Nodes group
        self.soca_resources["controller_role"].attach_inline_policy(
            iam.Policy(
                self,
                "AttachSecretManagerPolicyToController",
                statements=[
                    iam.PolicyStatement(
                        actions=["secretsmanager:GetSecretValue"],
                        effect=iam.Effect.ALLOW,
                        resources=[
                            f"arn:{Aws.PARTITION}:secretsmanager:{Aws.REGION}:{Aws.ACCOUNT_ID}:secret:/soca/{user_specified_variables.cluster_id}/*",
                            f"{self.directory_service_resource_setup.get('service_account_secret_arn')}",
                        ],
                    )
                ],
            )
        )
        # Compute Nodes can only query some secrets
        _compute_node_iam_resources = [
            f"{self.directory_service_resource_setup.get('service_account_secret_arn')}"
        ]

        if get_config_key(
            key_name="Config.services.aws_elasticache.engine",
            expected_type=str,
            default="valkey",
            required=False,
        ) in {"valkey", "redis"} and get_config_key(
            key_name="Config.services.aws_elasticache.enabled",
            expected_type=bool,
            default=True,
            required=False,
        ):
            _compute_node_iam_resources.append(
                self.soca_resources["cache_readonly_user_secret"].secret_arn
            )

        # FIXME TODO - this can be merged with the prior loop as well
        for _role in {"compute_node_role", "spot_fleet_role", "login_node_role"}:
            self.soca_resources[_role].attach_inline_policy(
                iam.Policy(
                    self,
                    f"AttachSecretManagerPolicyTo{_role.split('_')[0].capitalize()}Node",
                    statements=[
                        iam.PolicyStatement(
                            actions=["secretsmanager:GetSecretValue"],
                            effect=iam.Effect.ALLOW,
                            resources=_compute_node_iam_resources,
                        )
                    ],
                )
            )

        _install_scheduler_from_s3_uri = get_config_key(
            key_name="Parameters.system.scheduler.openpbs.s3_tgz.s3_uri",
            expected_type=str,
            required=False,
            default="",
        )
        if _install_scheduler_from_s3_uri:
            try:
                _s3_uri_bucket_name = re.search(
                    r"s3://([^/]+)", _install_scheduler_from_s3_uri
                ).group(1)
            except AttributeError:
                logger.fatal(
                    f"s3_uri {_install_scheduler_from_s3_uri} does not seems to be a valid s3_uri"
                )

            _custom_openpbs_s3_bucket_policy = iam.Policy(
                self,
                "AttachCustomS3BucketSchedulerPolicyToComputeNode",
                statements=[
                    iam.PolicyStatement(
                        actions=["s3:GetObject", "s3:ListBucket", "s3:PutObject"],
                        effect=iam.Effect.ALLOW,
                        resources=[
                            f"arn:{Aws.PARTITION}:s3:::{_s3_uri_bucket_name}/*",
                            f"arn:{Aws.PARTITION}:s3:::{_s3_uri_bucket_name}",
                        ],
                    )
                ],
            )
            for _rn in {
                "compute_node_role",
                "controller_role",
                "login_node_role",
                "spot_node_role",
            }:
                self.soca_resources[_rn].attach_inline_policy(
                    _custom_openpbs_s3_bucket_policy
                )

        # Finally, create one last parameter, this one will be created at the very end.
        _final_ssm_parameter = ssm.StringParameter(
            self,
            f"ParameterCDKCompleted",
            parameter_name=f"{_parameter_store_prefix}/cdk_completed",
            string_value="true",
            tier=ssm.ParameterTier.STANDARD,
        )

        # TODO - This should depend on the longest running items to make sure
        # we don't create it until the very end
        _final_ssm_parameter.node.add_dependency(self.soca_resources["nlb"])

    def analytics(self):
        """
        Create Analytics cluster. This will be used for jobs and hosts analytics.
        """
        _desired_engine: str = get_config_key(
            key_name="Config.analytics.engine",
            expected_type=str,
            required=False,
            default="opensearch",
        ).lower()

        if _desired_engine in {"opensearch"}:
            self.analytics_opensearch()
        elif _desired_engine in {"opensearch_serverless", "aoss_serverless"}:
            self.analytics_opensearch_serverless()
        else:
            logger.fatal(
                f"Config.analytics.engine must be one of opensearch or opensearch_serverless. Detected {_desired_engine}"
            )

    def analytics_create_opensearch_serverless_vpce(self):
        """
        Deploy a VPC Endpoint for AOSS Serverless
        """

        # Create a Security Group for the VPC Endpoint
        self.soca_resources["os_vpce_sg"] = ec2.SecurityGroup(
            self,
            "AOSSVPCEndpointSG",
            vpc=self.soca_resources["vpc"],
            allow_all_outbound=True,
            description="Security Group for AOSS Serverless VPC Endpoint",
        )
        Tags.of(self.soca_resources["os_vpce_sg"]).add(
            "Name", f"{user_specified_variables.cluster_id}-AOSSSG"
        )

        for _peer_sg in {"compute_node_sg", "controller_sg", "login_node_sg"}:
            security_groups_helper.create_ingress_rule(
                security_group=self.soca_resources["os_vpce_sg"],
                peer=self.soca_resources[_peer_sg],
                connection=ec2.Port.tcp(443),
                description=f"Allow {_peer_sg}",
            )

        self.soca_resources["os_vpce_sg"].node.add_dependency(
            self.soca_resources["controller_sg"],
            self.soca_resources["compute_node_sg"],
            self.soca_resources["login_node_sg"],
        )

        self.soca_resources["os_vpce"] = opensearchserverless.CfnVpcEndpoint(
            self,
            "AOSSVPCEndpoint",
            name=f"{user_specified_variables.cluster_id.lower()}-analytics",
            subnet_ids=[
                _s.subnet_id for _s in self.soca_resources["vpc"].private_subnets
            ],
            vpc_id=self.soca_resources["vpc"].vpc_id,
            security_group_ids=[self.soca_resources["os_vpce_sg"].security_group_id],
        )
        # Wait for deps
        self.soca_resources["os_vpce"].node.add_dependency(self.soca_resources["vpc"])
        self.soca_resources["os_vpce"].node.add_dependency(
            self.soca_resources["os_vpce_sg"]
        )
        #
        # What else needs access?
        #
        self.soca_resources["os_vpce"].node.add_dependency(
            self.soca_resources["controller_sg"],
            self.soca_resources["compute_node_sg"],
            self.soca_resources["login_node_sg"],
        )

    def analytics_opensearch_serverless(self):
        """
        Create an OpenSearch Serverless collection for analytics.
        """

        # If we are using an existing VPC - determine if there is an existing VPC-endpoint for OpenSearch serverless

        if user_specified_variables.vpc_id:
            logger.warning(
                f"NOT IMPLEMENTED - analytics_opensearch_serverless for existing VPCs - create VPCE here."
            )
        else:
            logger.debug(f"Creating VPC-Endpoint for AOSS Serverless")
            self.analytics_create_opensearch_serverless_vpce()

        # Create a serverless collection
        # TODO - this may need more sanitizing based on the AOSS rules
        sanitized_domain: str = user_specified_variables.cluster_id.lower()

        _standby_replicas: str = get_config_key(
            key_name="Config.analytics.aoss.standby_replicas",
            expected_type=str,
            required=False,
            default="DISABLED",
        ).upper()

        _serverless_public_access: bool = get_config_key(
            key_name="Config.analytics.aoss.public_access",
            expected_type=bool,
            required=False,
            default=False,
        )

        if _standby_replicas not in {"ENABLED", "DISABLED"}:
            logger.warning(
                f"Config.analytics.aoss.standby_replicas must be either ENABLED or DISABLED. Detected {_standby_replicas}. Falling back to DISABLED..."
            )
            _standby_replicas = "DISABLED"

        if _serverless_public_access not in {True, False}:
            logger.warning(
                f"Config.analytics.aoss.public_access must be True/False. Detected {_serverless_public_access}. Reverting to False"
            )
            _serverless_public_access = False

        logger.debug(
            f"AOSS Serverless - {_standby_replicas=} / {_serverless_public_access=}"
        )

        # First we create the security policy
        self.soca_resources["os_encryption_policy"] = (
            opensearchserverless.CfnSecurityPolicy(
                self,
                "AOSSEncryptionPolicy",
                type="encryption",
                name=f"{sanitized_domain}-encryption-policy",
                description=f"{sanitized_domain} encryption policy",
                policy=json.dumps(
                    {
                        "Rules": [
                            {
                                "Resource": [
                                    f"collection/{sanitized_domain}-analytics"
                                ],
                                "ResourceType": "collection",
                            }
                        ],
                        "AWSOwnedKey": True,
                    }
                ),
            )
        )
        logger.debug(
            f"Created AOSS encryption policy: {self.soca_resources['os_encryption_policy']}"
        )

        # Second, our Network Access policy
        self.soca_resources["os_network_policy"] = (
            opensearchserverless.CfnSecurityPolicy(
                self,
                "AOSSNetworkPolicy",
                type="network",
                name=f"{sanitized_domain}-network-policy",
                description=f"{sanitized_domain} network policy",
                policy=json.dumps(
                    [
                        {
                            "Rules": [
                                {
                                    "Resource": [
                                        f"collection/{sanitized_domain}-analytics"
                                    ],
                                    "ResourceType": "collection",
                                },
                                {
                                    "Resource": [
                                        f"collection/{sanitized_domain}-analytics"
                                    ],
                                    "ResourceType": "dashboard",
                                },
                            ],
                            "AllowFromPublic": _serverless_public_access,
                            "SourceVPCEs": [self.soca_resources["os_vpce"].attr_id],
                        }
                    ]
                ),
            )
        )

        # Third - Our Data access policy
        # This is created by a CustomResource Lambda since we do not know the Principal
        # ARNs (IAM Roles for the instances)

        self.soca_resources["aoss_data_policy_lambda"] = aws_lambda.Function(
            self,
            f"{user_specified_variables.cluster_id}-AOSSDataPolicyLambda",
            function_name=f"{user_specified_variables.cluster_id}-AOSSDataPolicyLambda",
            description=f"Create AOSS Data Policy for {user_specified_variables.cluster_id}",
            memory_size=128,
            role=self.soca_resources["aoss_data_policy_lambda_role"],
            runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
            timeout=Duration.minutes(1),
            log_retention=logs.RetentionDays.INFINITE,
            handler="AOSSDataPolicyLambda.lambda_handler",
            code=aws_lambda.Code.from_asset("../functions/AOSSDataPolicyLambda"),
        )

        # Finally, the actual Serverless collection
        self.soca_resources["os_domain"] = opensearchserverless.CfnCollection(
            self,
            "AOSSCollection",
            name=f"{sanitized_domain}-analytics",
            description=f"{sanitized_domain} analytics collection",
            type="SEARCH",
            standby_replicas=_standby_replicas,
            # FIXME TODO - Tags
            # tags=
        )

        # Make sure our required items are created prior to the collection attempt
        self.soca_resources["os_domain"].node.add_dependency(
            self.soca_resources["os_encryption_policy"]
        )
        self.soca_resources["os_domain"].node.add_dependency(
            self.soca_resources["os_network_policy"]
        )
        self.soca_resources["os_domain"].node.add_dependency(
            self.soca_resources["os_vpce"]
        )

        self.soca_resources["aoss_custom_resource"] = CustomResource(
            self,
            "AOSSCustomResource",
            service_token=self.soca_resources["aoss_data_policy_lambda"].function_arn,
            properties={"ClusterId": user_specified_variables.cluster_id},
        )

        self.soca_resources["aoss_custom_resource"].node.add_dependency(
            self.soca_resources["os_domain"],
            self.soca_resources["os_network_policy"],
            self.soca_resources["aoss_data_policy_lambda_role"],
        )

    def analytics_opensearch(self):
        """
        Create OpenSearch cluster.
        """

        sanitized_domain: str = user_specified_variables.cluster_id.lower()
        _data_node_instance_type: str = get_config_key(
            key_name="Config.analytics.data_node_instance_type",
            expected_type=str,
        )
        _data_nodes: int = get_config_key(
            key_name="Config.analytics.data_nodes",
            expected_type=int,
        )
        _volume_size: int = get_config_key(
            key_name="Config.analytics.ebs_volume_size",
            expected_type=int,
        )
        _deletion_policy: str = get_config_key(
            key_name="Config.analytics.deletion_policy",
            expected_type=str,
        ).upper()
        _desired_engine: str = get_config_key(
            key_name="Config.analytics.engine",
            expected_type=str,
        ).lower()

        if _desired_engine == "opensearch":
            _engine_version = opensearch.EngineVersion.OPENSEARCH_2_17
        else:
            logger.fatal(
                f"Config.analytics.engine must be one of opensearch, or opensearch_serverless. Detected {_desired_engine}"
            )

        if not user_specified_variables.os_endpoint:
            # Determine serverless or classic
            if _data_nodes == 1:
                es_subnets = [
                    ec2.SubnetSelection(
                        subnets=[self.soca_resources["vpc"].private_subnets[0]]
                    )
                ]
                es_zone_awareness = opensearch.ZoneAwarenessConfig(enabled=False)
            elif _data_nodes == 2:
                es_subnets = [
                    ec2.SubnetSelection(
                        subnets=[
                            self.soca_resources["vpc"].private_subnets[0],
                            self.soca_resources["vpc"].private_subnets[1],
                        ]
                    )
                ]
                es_zone_awareness = opensearch.ZoneAwarenessConfig(
                    availability_zone_count=2, enabled=True
                )
            else:
                es_subnets = [
                    ec2.SubnetSelection(
                        subnets=[
                            self.soca_resources["vpc"].private_subnets[0],
                            self.soca_resources["vpc"].private_subnets[1],
                            self.soca_resources["vpc"].private_subnets[2],
                        ]
                    )
                ]
                es_zone_awareness = opensearch.ZoneAwarenessConfig(
                    availability_zone_count=3, enabled=True
                )

            # Create the SG for the Analytics cluster
            self.soca_resources["os_sg"] = ec2.SecurityGroup(
                self,
                "OpenSearchSecurityGroup",
                vpc=self.soca_resources["vpc"],
                description="OpenSearch Analytics Security Group",
                allow_all_outbound=True,
            )
            Tags.of(self.soca_resources["os_sg"]).add(
                "Name", f"{user_specified_variables.cluster_id}-OpenSearchSG"
            )

            # Allow nodes to analytics SG

            for _sg_peer_name in {"controller_sg", "compute_node_sg", "login_node_sg"}:
                logger.debug(f"Allowing {_sg_peer_name} to access OpenSearch Analytics")
                security_groups_helper.create_ingress_rule(
                    security_group=self.soca_resources["os_sg"],
                    peer=self.soca_resources[_sg_peer_name],
                    connection=ec2.Port.tcp(443),
                    description=f"Allow OpenSearch from {_sg_peer_name}",
                )

            _kms_key_id: str = get_kms_key_id(
                config_key_names=[
                    "Config.analytics.kms_key_id",  # Current configuration parameter
                ],
                allow_global_default=True,
            )

            # FIXME TODO - Not all volume types may work with OpenSearch
            # They should be sanity checked
            _volume_type = return_ebs_volume_type(
                volume_string=get_config_key(
                    key_name="Config.analytics.volume_type",
                    required=False,
                    default="gp3",
                    expected_type=str,
                ).lower()
            )

            self.soca_resources["os_domain"] = opensearch.Domain(
                self,
                "OpenSearch",
                domain_name=sanitized_domain,
                enforce_https=True,
                node_to_node_encryption=True,
                tls_security_policy=opensearch.TLSSecurityPolicy.TLS_1_2,
                version=typing.cast(opensearch.EngineVersion, _engine_version),
                encryption_at_rest=opensearch.EncryptionAtRestOptions(
                    enabled=True,
                    kms_key=(
                        kms.Key.from_key_arn(
                            self, id="OpenSearchKMS", key_arn=_kms_key_id
                        )
                        if _kms_key_id
                        else None
                    ),
                ),
                ebs=opensearch.EbsOptions(
                    volume_size=_volume_size,
                    volume_type=_volume_type,
                ),
                capacity=opensearch.CapacityConfig(
                    data_node_instance_type=_data_node_instance_type,
                    data_nodes=_data_nodes,
                ),
                automated_snapshot_start_hour=0,
                removal_policy=(
                    RemovalPolicy.RETAIN
                    if _deletion_policy == "RETAIN"
                    else RemovalPolicy.DESTROY
                ),
                access_policies=[
                    iam.PolicyStatement(
                        principals=[iam.AnyPrincipal()],
                        actions=["es:ESHttp*"],
                        resources=[
                            f"arn:{Aws.PARTITION}:es:{Aws.REGION}:{Aws.ACCOUNT_ID}:domain/{sanitized_domain}/*"
                        ],
                    )
                ],
                advanced_options={"rest.action.multi.allow_explicit_index": "true"},
                security_groups=[self.soca_resources["os_sg"]],
                zone_awareness=es_zone_awareness,
                vpc=self.soca_resources["vpc"],
                vpc_subnets=es_subnets,
            )

            if user_specified_variables.create_es_service_role:
                service_linked_role = iam.CfnServiceLinkedRole(
                    self,
                    "AOSSServiceLinkedRole",
                    aws_service_name=f"opensearchservice.{Aws.URL_SUFFIX}",
                    description="Role for AOSS to access resources in the VPC",
                )

                # When creating the SLR - it should be set to RETAIN to decouple it from the Stack
                service_linked_role.apply_removal_policy(RemovalPolicy.RETAIN)

                self.soca_resources["os_domain"].node.add_dependency(
                    service_linked_role,
                    self.soca_resources["os_sg"],
                )

    def backups(self):
        """
        Deploy AWS Backup vault. Controller EC2 instance and both EFS will be backup on a daily basis
        """
        logger.debug(f"Creating AWS Backup vault")
        _kms_key_id = get_kms_key_id(
            config_key_names=[
                "Config.services.aws_backup.kms_key_id",  # Current configuration parameter
            ],
            allow_global_default=True,
        )

        vault = backup.BackupVault(
            self,
            "SOCABackupVault",
            backup_vault_name=f"{user_specified_variables.cluster_id}-BackupVault",
            removal_policy=RemovalPolicy.DESTROY,
            encryption_key=(
                kms.Key.from_key_arn(self, id="BackupVaultKMSKey", key_arn=_kms_key_id)
                if _kms_key_id
                else None
            ),
        )  # removal policy won't apply if backup vault is not empty

        # Any additional copy destinations needed?
        _backup_copy_destinations: list = get_config_key(
            key_name="Config.backups.additional_copy_destinations",
            expected_type=list,
            required=False,
            default=[],
        )

        _backup_copy_actions: list = []

        if _backup_copy_destinations:

            for _bu_destination in _backup_copy_destinations:
                if not is_valid_backup_vault_arn(arn=_bu_destination):
                    logger.warning(
                        f"Invalid ARN for backup destination: {_bu_destination} (SKIPPING)"
                    )
                    continue

                # It looks like a proper ARN - resolve it
                logger.debug(f"Adding a new discrete backup dest: {_bu_destination}")
                _bu_vault = backup.BackupVault.from_backup_vault_arn(
                    self, f"BackupVault{_bu_destination}", _bu_destination
                )

                if _bu_vault:
                    logger.debug(f"Vault copy being added - {_bu_destination}")
                    if _bu_destination in _backup_copy_destinations:
                        logger.error(
                            f"Duplicate backup destination: {_bu_destination} . SKIPPING"
                        )
                        continue

                    # Looks unique - add it
                    _backup_copy_actions.append(
                        backup.BackupPlanCopyActionProps(
                            destination_backup_vault=_bu_vault,
                        )
                    )

                else:
                    logger.error(
                        f"Unable to find backup vault for {_bu_destination} . SKIPPING"
                    )
                    continue

        plan = backup.BackupPlan(
            self,
            "SOCABackupPlan",
            backup_plan_name=f"{user_specified_variables.cluster_id}-BackupPlan",
            backup_plan_rules=[
                backup.BackupPlanRule(
                    backup_vault=vault,
                    start_window=Duration.minutes(60),
                    delete_after=Duration.days(
                        get_config_key(
                            key_name="Config.backups.delete_after",
                            expected_type=int,
                            required=False,
                            default=7,
                        )
                    ),
                    schedule_expression=events.Schedule.expression("cron(0 5 * * ? *)"),
                    copy_actions=_backup_copy_actions if _backup_copy_actions else None,
                )
            ],
        )
        # Backup EFS/EC2 resources with special tag: soca:BackupPlan, value: Current Cluster ID
        backup.BackupSelection(
            self,
            "SOCABackupSelection",
            backup_plan=plan,
            role=self.soca_resources["backup_role"],
            backup_selection_name=f"{user_specified_variables.cluster_id}-BackupSelection",
            resources=[
                backup.BackupResource(
                    tag_condition=backup.TagCondition(
                        key="soca:BackupPlan",
                        value=user_specified_variables.cluster_id,
                        operation=backup.TagOperation.STRING_EQUALS,
                    )
                )
            ],
        )

    @staticmethod
    def aws_pcs():
        """
        Create AWS PCS cluster integration
        """
        logger.debug(f"Creating AWS PCS integration")
        _pcs_cluster_name = f"{user_specified_variables.cluster_id}-PCS"

    def login_nodes(self):
        """
        Create ASG for Login Node
        """

        # Make sure our filesystems are fully qualified
        # duplicate from controller(),
        if user_specified_variables.fs_apps_provider:
            _fs_apps_provider: str = user_specified_variables.fs_apps_provider
            _fs_apps_dns: str = f"{user_specified_variables.fs_apps}"
        else:
            _fs_apps_provider: str = install_props.fs_apps_provider
            _fs_apps_dns: str = storage_helper.get_filesystem_dns(
                storage_construct=self.soca_resources["fs_apps"],
                storage_provider=_fs_apps_provider,
                endpoints_suffix=endpoints_suffix,
                fsx_ontap_junction_path=(
                    None
                    if _fs_apps_provider != "fsx_ontap"
                    else get_config_key(
                        key_name=f"Config.storage.apps.fsx_ontap.junction_path",
                        expected_type=str,
                    )
                ),
            )

        if user_specified_variables.fs_data_provider:
            _fs_data_provider: str = user_specified_variables.fs_data_provider
            _fs_data_dns: str = f"{user_specified_variables.fs_data}"
        else:
            _fs_data_provider: str = user_specified_variables.fs_data_provider
            _fs_data_dns: str = storage_helper.get_filesystem_dns(
                storage_construct=self.soca_resources["fs_data"],
                storage_provider=_fs_data_provider,
                endpoints_suffix=endpoints_suffix,
                fsx_ontap_junction_path=(
                    None
                    if _fs_data_provider != "fsx_ontap"
                    else get_config_key(
                        key_name=f"Config.storage.data.fsx_ontap.junction_path",
                        expected_type=str,
                    )
                ),
            )

        # Generate EC2 User Data
        # We manually replace  the variable with the relevant ParameterStore as all ParamStore hierarchy is created at the very end of this CDK
        _user_data_variables = {
            "/configuration/BaseOS": user_specified_variables.base_os,
            "/configuration/ClusterId": user_specified_variables.cluster_id,
            "/configuration/UserDirectory/provider": get_config_key(
                "Config.directoryservice.provider"
            ),
            "/configuration/Region": user_specified_variables.region,
            "/configuration/Cache/enabled": self.cache_info.get("enabled"),
            "/configuration/Cache/port": self.cache_info.get("port"),
            "/configuration/Cache/endpoint": self.cache_info.get("endpoint"),
            "/configuration/ControllerPrivateDnsName": self.soca_resources[
                "controller_instance"
            ].instance_private_dns_name,
            "/configuration/S3Bucket": user_specified_variables.bucket,
            "/job/BootstrapPath": f"/apps/soca/{user_specified_variables.cluster_id}/shared/logs/bootstrap/login_node",
            "/job/BootstrapScriptsS3Location": f"s3://{user_specified_variables.bucket}/{user_specified_variables.cluster_id}/config/do_not_delete/bootstrap/login_node",
            "/job/NodeType": "login_node",
        }

        # add all System hierarchy
        _parameter_store_keys = flatten_parameterstore_config(
            get_config_key(key_name="Parameters", expected_type=dict)
        )
        for _ssm_parameter_key, _ssm_parameter_value in _parameter_store_keys.items():
            _user_data_variables[f"/{_ssm_parameter_key}"] = _ssm_parameter_value

        # Generate EC2 User Data
        os.makedirs(
            f"{pathlib.Path.cwd().parent}/upload_to_s3/bootstrap/login_node/",
            exist_ok=True,
        )

        # Because of size limitation, the main setup script is stored on S3 as it's only called once.
        _user_data = user_data_helper.remove_text(
            text_to_remove=[
                "# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.",
                "# SPDX-License-Identifier: Apache-2.0",
            ],
            data=self.jinja2_env.get_template(
                "user_data/login_node/01_user_data.sh.j2"
            ).render(
                context=_user_data_variables,
                ns=SimpleNamespace(template_already_included=[]),
            ),
        )

        # Because of size limitation, scripts needed during bootstrap are stored on s3
        _templates_to_render = [
            "templates/linux/system_packages/install_required_packages",
            "templates/linux/filesystems_automount",
        ]

        for template in _templates_to_render:
            _t = self.jinja2_env.get_template(f"{template}.sh.j2").render(
                context=_user_data_variables,
                ns=SimpleNamespace(template_already_included=[]),
            )
            with open(
                f"{pathlib.Path.cwd().parent}/upload_to_s3/bootstrap/login_node/{template.split('/')[-1]}.sh",
                "w",
            ) as f:
                f.write(_t)

        # final 03_setup.sh.j2 will be generated by controller original setup and uploaded to login_node s3 location
        # as we have to wait until CDK is fully deployed

        _configured_instance_type: list = get_config_key(
            key_name="Config.login_node.instance_type",
            expected_type=list,
            required=False,
            default=["m7i-flex.large", "m5.large"],
        )
        logger.debug(
            f"LoginNode - Configured instance type: {_configured_instance_type}"
        )

        _selected_instance, _instance_arch, _default_instance_ami_for_instance = (
            self.select_best_instance(
                instance_list=_configured_instance_type,
                region=user_specified_variables.region,
                fallback_instance="m5.large",
            )
        )

        logger.debug(
            f"LoginNode - Selected instance type: {_selected_instance} / Arch: {_instance_arch}"
        )

        # Do we have any configuration over-rides in the login_node.ami.<arch> configuration?
        _desired_ami: str = get_config_key(
            key_name=f"Config.login_node.ami.{_instance_arch}",
            expected_type=str,
            required=False,  # Fallback to default if needed
            default=_default_instance_ami_for_instance,
        )

        # show what we landed on
        logger.debug(
            f"LoginNode - Instance / AMI / Arch determination - InstanceType: {_selected_instance} / AMI: {_desired_ami} / Arch: {_instance_arch}"
        )

        _ebs_volume_key_id: str = get_kms_key_id(
            config_key_names=["Config.login_node.volume_kms_key_id"],
            allow_global_default=True,
        )

        logger.debug(f"login_node EBS encryption: KeyID: {_ebs_volume_key_id}")

        _volume_type_str: str = get_config_key(
            key_name="Config.controller.volume_type",
            required=False,
            default="gp3",
            expected_type=str,
        ).lower()

        _volume_type = return_ebs_volume_type(volume_string=_volume_type_str)

        _volume_iops = get_config_key(
            key_name="Config.login_node.volume_iops",
            required=False,
            default=0,
            expected_type=int,
        )

        _volume_throughput = get_config_key(
            key_name="Config.login_node.volume_throughput",
            required=False,
            default=0,
            expected_type=int,
        )
        logger.debug(f"login_node EBS volume IOPS: {_volume_iops}")
        logger.debug(f"login_node EBS volume throughput: {_volume_throughput}")

        # Fixup some configs for specific volume types
        logger.debug(f"Performing EBS fixups for volume_type - {_volume_type}")

        match _volume_type_str:
            case "gp3":
                logger.debug(f"Performing EBS fixups for gp3")
                if not _volume_iops:
                    _volume_iops = 3000
                if not _volume_throughput:
                    _volume_throughput = 125
            case "io1":
                logger.debug(f"Performing EBS fixups for io1")
                if _volume_throughput:
                    _volume_throughput = None

        _login_node_launch_template = ec2.LaunchTemplate(
            self,
            f"LoginNodeLT",
            machine_image=ec2.MachineImage.generic_linux(
                {user_specified_variables.region: _desired_ami}
            ),
            instance_type=ec2.InstanceType(_selected_instance),
            key_pair=ec2.KeyPair.from_key_pair_attributes(
                self,
                "LoginNodeKeyPair",
                key_pair_name=user_specified_variables.ssh_keypair,
            ),
            require_imdsv2=True,
            role=self.soca_resources["login_node_role"],
            block_devices=[
                ec2.BlockDevice(
                    device_name=self.return_ebs_volume_name(
                        base_os=user_specified_variables.base_os
                    ),
                    volume=ec2.BlockDeviceVolume(
                        ebs_device=ec2.EbsDeviceProps(
                            encrypted=True if _ebs_volume_key_id else False,
                            kms_key=(
                                kms.Key.from_key_arn(
                                    self,
                                    id="LoginEBSKMSKey",
                                    key_arn=_ebs_volume_key_id,
                                )
                                if _ebs_volume_key_id
                                else None
                            ),
                            volume_size=get_config_key(
                                key_name="Config.login_node.volume_size",
                                expected_type=int,
                                required=False,
                                default=50,
                            ),
                            volume_type=_volume_type,
                            iops=_volume_iops if _volume_iops else None,
                            throughput=(
                                _volume_throughput if _volume_throughput else None
                            ),
                        ),
                    ),
                )
            ],
            security_group=self.soca_resources["login_node_sg"],
            user_data=ec2.UserData.custom(_user_data),
        )
        # _login_node_subnets == subnetIds
        # _login_node_isubnets == ISubnets (CDK)
        _login_node_subnets: list = []
        _login_node_isubnets: list = []
        _subnets_for_login_nodes: list = []
        logger.debug(f"Determining the LoginNode placement subnets for the ASG")

        # If we are using an existing VPC - we use our specific marked private subnets
        if user_specified_variables.vpc_id:
            logger.debug(f"Using pre-existing VPC: {user_specified_variables.vpc_id}")
            for _sn_info in user_specified_variables.private_subnets:
                # subnet-123,az1
                _exact_subnet_id = _sn_info.split(",")[0]
                logger.debug(f"Adding subnet for LoginNodes ASG: {_exact_subnet_id}")
                _subnets_for_login_nodes.append(_exact_subnet_id)

        else:
            # SOCA Created subnets
            logger.debug(f"Using SOCA-created VPC subnets for LoginNode ASG")
            for _sn_info in self.soca_resources["vpc"].private_subnets:
                logger.debug(
                    f"Adding SOCA-created subnet for LoginNodes ASG: {_sn_info.subnet_id}"
                )
                _subnets_for_login_nodes.append(_sn_info.subnet_id)

        logger.debug(
            f"Final List of SubnetIDs for Login Nodes ASG: {_subnets_for_login_nodes}"
        )
        _subnet_i: int = 1
        for _sn_id in _subnets_for_login_nodes:
            if _sn_id not in _login_node_subnets:
                logger.debug(f"Adding subnet #{_subnet_i} for LoginNodes ASG: {_sn_id}")
                _login_node_subnets.append(_sn_id)
                _login_node_isubnets.append(
                    ec2.Subnet.from_subnet_id(
                        self,
                        f"LoginNodePrivateSubnet{_subnet_i}",
                        subnet_id=_sn_id,
                    )
                )
            _subnet_i += 1

        # Read our configuration for min/max/desired with defaults to 1
        _login_node_count: dict = {}
        for _node_count in ("min", "max", "desired"):
            _login_node_count[_node_count] = get_config_key(
                key_name=f"Config.login_node.{_node_count}_count",
                expected_type=int,
                required=False,
                default=(
                    _login_node_count.get("min", 1) if _node_count == "desired" else 1
                ),
            )
            logger.debug(
                f"Configuring LoginNode ASG for {_node_count} == {_login_node_count[_node_count]}"
            )

        # Sanity check
        _login_node_count["min"] = min(
            _login_node_count["desired"], _login_node_count["min"]
        )
        _login_node_count["max"] = max(
            _login_node_count["desired"], _login_node_count["max"]
        )
        logger.debug(f"LoginNode ASG sizing post-check/fixups: {_login_node_count}")

        _login_node_asg = autoscaling.AutoScalingGroup(
            self,
            f"LoginNodeASG",
            vpc=self.soca_resources["vpc"],
            launch_template=_login_node_launch_template,
            max_capacity=_login_node_count["max"],
            min_capacity=min(_login_node_count["min"], _login_node_count["desired"]),
            desired_capacity=_login_node_count["desired"],
            vpc_subnets=ec2.SubnetSelection(subnets=_login_node_isubnets),
        )

        #
        _login_node_ssh_back_port: int = get_config_key(
            key_name=f"Config.login_node.security.ssh_backend_port",
            expected_type=int,
            required=False,
            default=22,
        )
        _login_node_ssh_front_port: int = get_config_key(
            key_name=f"Config.login_node.security.ssh_frontend_port",
            expected_type=int,
            required=False,
            default=22,
        )
        logger.debug(
            f"LoginNode SSH port: Front: {_login_node_ssh_back_port} / Back: {_login_node_ssh_front_port}"
        )

        _login_node_target_groups = elbv2.NetworkTargetGroup(
            self,
            f"{user_specified_variables.cluster_id}-LoginNodesTargetGroup",
            port=_login_node_ssh_back_port,
            protocol=elbv2.Protocol.TCP,
            target_type=elbv2.TargetType.INSTANCE,
            vpc=self.soca_resources["vpc"],
            targets=[_login_node_asg],
            target_group_name=f"{user_specified_variables.cluster_id}-LoginNodes",
            health_check=elbv2.HealthCheck(
                port=str(_login_node_ssh_back_port), protocol=elbv2.Protocol.TCP
            ),
            connection_termination=True,
        )

        # Create NLB
        # Plaintext list of subnets to launch the NLB into
        _nlb_public_bool: bool = (
            True
            if get_config_key(
                key_name="Config.entry_points_subnets",
                expected_type=str,
                default="public",
                required=False,
            ).lower()
            == "public"
            else False
        )

        logger.debug(f"NLB / Cluster Entry Point Public?: {_nlb_public_bool}")

        _nlb_subnets_list: list = []
        _source_subnets: list = []

        # Did we use existing resources?
        if user_specified_variables.vpc_id:
            # Existing resources
            logger.debug(
                f"Using imported VPC Subnets for NLB from VPC {user_specified_variables.vpc_id}"
            )
            if _nlb_public_bool:
                _source_subnets = user_specified_variables.public_subnets
            else:
                _source_subnets = user_specified_variables.private_subnets

            for _subnet in _source_subnets:
                _subnet_id: str = _subnet.split(",")[0]
                _subnet_az: str = _subnet.split(",")[1]
                _nlb_subnets_list.append(_subnet_id)
                logger.debug(
                    f"Adding existing subnet for NLB: {_subnet_id} / AZ: {_subnet_az}"
                )

        else:
            # SOCA created the VPC
            logger.debug(f"Using SOCA created VPC Subnets for NLB")
            if _nlb_public_bool:
                logger.debug(f"Adding SOCA created public subnets")
                for _soca_sn in self.soca_resources["vpc"].public_subnets:
                    logger.debug(
                        f"Adding SOCA created public subnet: {_soca_sn.subnet_id}"
                    )
                    _source_subnets.append(_soca_sn.subnet_id)
            else:
                logger.debug(f"Adding SOCA created private subnets")
                for _soca_sn in self.soca_resources["vpc"].private_subnets:
                    logger.debug(
                        f"Adding SOCA created private subnet: {_soca_sn.subnet_id}"
                    )
                    _source_subnets.append(_soca_sn.subnet_id)

            logger.debug(f"Scanning Source subnets: {_source_subnets}")
            # TODO - still needed?
            for _subnet in _source_subnets:
                logger.debug(f"Adding subnet: {_subnet}")
                _nlb_subnets_list.append(_subnet)
                logger.debug(f"Adding existing subnet for NLB: {_subnet}")

        logger.debug(
            f"Final subnets for NLB: {_nlb_subnets_list} / Public: {_nlb_public_bool}"
        )

        # Convert our subnet list to a list of ISubnets
        _nlb_isubnets_list: list = [
            ec2.Subnet.from_subnet_id(
                self,
                f"NLBSubnet{_i}",
                subnet_id=_subnet,
            )
            for _i, _subnet in enumerate(_nlb_subnets_list)
        ]
        logger.debug(f"Final ISubnets for NLB: {_nlb_isubnets_list}")

        self.soca_resources["nlb"] = elbv2.NetworkLoadBalancer(
            self,
            "SOCANLB",
            load_balancer_name=f"{user_specified_variables.cluster_id}-nlb",
            vpc=self.soca_resources["vpc"],
            security_groups=[self.soca_resources["nlb_sg"]],
            internet_facing=_nlb_public_bool,
            vpc_subnets=ec2.SubnetSelection(subnets=_nlb_isubnets_list),
            # deletion_protection=get_config_key(
            #     key_name="Config.termination_protection",
            #     expected_type=bool,
            #     required=False,
            #     default=True,
            # ),
            cross_zone_enabled=get_config_key(
                key_name="Config.network.cross_zone_enabled",
                expected_type=bool,
                required=False,
                default=True,
            ),
        )

        # Create listener
        elbv2.NetworkListener(
            self,
            "SSHListener",
            load_balancer=self.soca_resources["nlb"],
            protocol=elbv2.Protocol.TCP,
            port=_login_node_ssh_front_port,
            default_action=elbv2.NetworkListenerAction.forward(
                target_groups=[_login_node_target_groups]
            ),
        )

        Tags.of(_login_node_asg).add(
            key="Name", value=f"{user_specified_variables.cluster_id}-LoginNode"
        )
        Tags.of(_login_node_asg).add(key="soca:NodeType", value=f"login_node")

        # Login Nodes creation is triggered at the end of the deployment as we have to wait for bootstrap.d folder to be deployed on the filesystem
        if (
            get_config_key(key_name="Config.analytics.enabled", expected_type=bool)
            is True
        ):
            if not user_specified_variables.os_endpoint:
                self.soca_resources["nlb"].node.add_dependency(
                    self.soca_resources["os_domain"]
                )

        # Other LoginNode Deps (ElastiCache)
        if self.soca_resources["elasticache"]:
            self.soca_resources["nlb"].node.add_dependency(
                self.soca_resources["elasticache"]
            )

        # Give the controller a head start in resource creation since the LoginNodes need to do some items that depend on Controller
        _login_node_asg.node.add_dependency(self.soca_resources["controller_instance"])

        self.soca_resources["nlb"].node.add_dependency(
            self.soca_resources["controller_instance"]
        )

        CfnOutput(
            self,
            "SSHEndpoint",
            value=f"{self.soca_resources['nlb'].load_balancer_dns_name}",
        )
        CfnOutput(
            self,
            "SSHPort",
            value=str(_login_node_ssh_front_port),
        )

    def viewer(self):
        # Create the ALB. It's used to forward HTTP/S traffic to DCV hosts, Web UI and Analytics back-end

        # FIXME TODO - duplicate with NLB
        _alb_public_bool: bool = (
            True
            if get_config_key(
                key_name="Config.entry_points_subnets",
                expected_type=str,
                default="public",
                required=False,
            ).lower()
            == "public"
            else False
        )

        logger.debug(f"ALB / Cluster Entry Point Public?: {_alb_public_bool}")

        _alb_subnets_list: list = []
        _source_subnets: list = []

        # Did we use existing resources?
        if user_specified_variables.vpc_id:
            # Existing resources
            logger.debug(
                f"Using imported VPC Subnets for ALB from VPC {user_specified_variables.vpc_id}"
            )
            if _alb_public_bool:
                _source_subnets = user_specified_variables.public_subnets
            else:
                _source_subnets = user_specified_variables.private_subnets

            for _subnet in _source_subnets:
                _subnet_id: str = _subnet.split(",")[0]
                _subnet_az: str = _subnet.split(",")[1]
                _alb_subnets_list.append(_subnet_id)
                logger.debug(
                    f"Adding existing subnet for ALB: {_subnet_id} / AZ: {_subnet_az}"
                )

        else:
            # SOCA created the VPC
            logger.debug(f"Using SOCA created VPC Subnets for ALB")
            if _alb_public_bool:
                logger.debug(f"Adding SOCA created public subnets")
                for _soca_sn in self.soca_resources["vpc"].public_subnets:
                    logger.debug(
                        f"Adding SOCA created public subnet: {_soca_sn.subnet_id}"
                    )
                    _source_subnets.append(_soca_sn.subnet_id)
            else:
                logger.debug(f"Adding SOCA created private subnets")
                for _soca_sn in self.soca_resources["vpc"].private_subnets:
                    logger.debug(
                        f"Adding SOCA created private subnet: {_soca_sn.subnet_id}"
                    )
                    _source_subnets.append(_soca_sn.subnet_id)

            logger.debug(f"Scanning Source subnets: {_source_subnets}")
            # TODO - still needed?
            for _subnet in _source_subnets:
                logger.debug(f"Adding ALB subnet: {_subnet}")
                _alb_subnets_list.append(_subnet)
                logger.debug(f"Adding existing subnet for ALB: {_subnet}")

        logger.debug(
            f"Final subnets for ALB: {_alb_subnets_list} / Public: {_alb_public_bool}"
        )

        # Convert our subnet list to a list of ISubnets
        _alb_isubnets_list: list = [
            ec2.Subnet.from_subnet_id(
                self,
                f"ALBSubnet{_i}",
                subnet_id=_subnet,
            )
            for _i, _subnet in enumerate(_alb_subnets_list)
        ]
        logger.debug(f"Final ISubnets for ALB: {_alb_isubnets_list}")

        self.soca_resources["alb"] = elbv2.ApplicationLoadBalancer(
            self,
            f"{user_specified_variables.cluster_id}-ELBv2Viewer",
            load_balancer_name=f"{user_specified_variables.cluster_id}-viewer",
            security_group=self.soca_resources["alb_sg"],
            http2_enabled=True,
            vpc=self.soca_resources["vpc"],
            drop_invalid_header_fields=True,
            internet_facing=(
                True
                if get_config_key("Config.entry_points_subnets").lower() == "public"
                else False
            ),
            vpc_subnets=ec2.SubnetSelection(subnets=_alb_isubnets_list),
        )

        # Create self-signed certificate (if needed) for HTTPS listener (via AWS Lambda)
        create_acm_certificate_lambda = aws_lambda.Function(
            self,
            f"{user_specified_variables.cluster_id}-ACMCertificateLambda",
            function_name=f"{user_specified_variables.cluster_id}-CreateACMCertificate",
            description="Create first self-signed certificate for ALB",
            memory_size=128,
            role=self.soca_resources["acm_certificate_lambda_role"],
            runtime=typing.cast(aws_lambda.Runtime, get_lambda_runtime_version()),
            timeout=Duration.minutes(1),
            log_retention=logs.RetentionDays.INFINITE,
            handler="CreateELBSSLCertificate.generate_cert",
            code=aws_lambda.Code.from_asset("../functions/CreateELBSSLCertificate"),
        )

        cert_custom_resource = CustomResource(
            self,
            "RetrieveACMCertificate",
            service_token=create_acm_certificate_lambda.function_arn,
            properties={
                "LoadBalancerDNSName": self.soca_resources[
                    "alb"
                ].load_balancer_dns_name,
                "ClusterId": user_specified_variables.cluster_id,
            },
        )

        cert_custom_resource.node.add_dependency(create_acm_certificate_lambda)
        cert_custom_resource.node.add_dependency(
            self.soca_resources["acm_certificate_lambda_role"]
        )

        # TODO - FIXME - customize port via config
        soca_webui_target_group = elbv2.ApplicationTargetGroup(
            self,
            f"{user_specified_variables.cluster_id}-SOCAWebUITargetGroup",
            port=8443,
            target_type=elbv2.TargetType.INSTANCE,
            protocol=elbv2.ApplicationProtocol.HTTPS,
            vpc=self.soca_resources["vpc"],
            target_group_name=f"{user_specified_variables.cluster_id}-SOCAWebUI",
            targets=[
                elbv2_targets.InstanceIdTarget(
                    instance_id=self.soca_resources["controller_instance"].instance_id,
                    port=8443,
                )
            ],
            health_check=elbv2.HealthCheck(
                port="8443", protocol=elbv2.Protocol.HTTPS, path="/ping"
            ),
        )

        self.soca_resources["alb"].add_listener(
            "HTTPListener",
            port=80,
            open=False,
            protocol=elbv2.ApplicationProtocol.HTTP,
            default_action=elbv2.ListenerAction.redirect(
                host="#{host}",
                path="/#{path}",
                permanent=True,
                port="443",
                query="#{query}",
            ),
        )

        _configured_ssl_policy_name: str = get_config_key(
            key_name="Config.network.alb_tls_policy",
            required=False,
            default="ELBSecurityPolicy-TLS13-1-2-2021-06",
            expected_type=str,
        )

        logger.debug(f"Using SSL policy name: {_configured_ssl_policy_name}")

        self.soca_resources["https_listener"] = elbv2.ApplicationListener(
            self,
            "HTTPSListener",
            load_balancer=self.soca_resources["alb"],
            port=443,
            open=False,
            protocol=elbv2.ApplicationProtocol.HTTPS,
            certificates=[
                acm.Certificate.from_certificate_arn(
                    self,
                    "ImportACM",
                    certificate_arn=cert_custom_resource.get_att_string(
                        "ACMCertificateArn"
                    ),
                )
            ],
            default_action=elbv2.ListenerAction.forward(
                target_groups=[soca_webui_target_group]
            ),
        )

        # Use a CDK escape hatch to set the SSL policy
        # per the docs page versus Enum lookup via CDK
        # https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html
        _https_cdk_override = self.soca_resources["https_listener"].node.default_child
        _https_cdk_override.add_property_override(
            "SslPolicy", _configured_ssl_policy_name
        )

        self.soca_resources["https_listener"].node.add_dependency(cert_custom_resource)

        # Determine our Analytics configuration based on the selected engine
        if (
            get_config_key(key_name="Config.analytics.enabled", expected_type=bool)
            is True
        ):
            if get_config_key("Config.analytics.engine") in {"opensearch"}:
                self.viewer_analytics_opensearch()
            elif get_config_key("Config.analytics.engine") in {
                "opensearch_serverless",
                "aoss_serverless",
            }:
                self.viewer_analytics_opensearch_serverless()

        CfnOutput(
            self,
            "WebUserInterface",
            value=f"https://{self.soca_resources['alb'].load_balancer_dns_name}/",
        )

    def configure_aws_aga(self):
        """
        Configure an AWS Global Accelerator (AGA) for the SOCA environment.
        """

        _aga_address_type_str = get_config_key(
            key_name="Config.network.aws_aga.address_type",
            expected_type=str,
            default="IPV4",
            required=False,
        ).upper()

        logger.debug(f"Creating AWS AGA using address-type {_aga_address_type_str}")

        self.soca_resources["aga"] = globalaccelerator.CfnAccelerator(
            self,
            f"{user_specified_variables.cluster_id}-AGA",
            name=f"{user_specified_variables.cluster_id}-AGA",
            enabled=True,
            ip_address_type=_aga_address_type_str,
        )

        # Define our listeners to resource mappings
        # Listeners are arranged in Endpoint groups that go to specific
        # region resources (ALB, NLB, EC2, etc.)

        _aga_listeners_needed = {
            #
            # ALB contains the WebUI
            #
            "ALB": {
                "protocols": {
                    "TCP": {
                        "ports": [80, 443],
                    },
                },
                "client_affinity": "SOURCE_IP",
                "endpoint": self.soca_resources["alb"].load_balancer_arn,
            },
            #
            # NLB contains the VDI/DCV and SSH/login_nodes
            #
            "NLB": {
                "protocols": {
                    "UDP": {
                        "ports": [8443],
                    },
                    "TCP": {
                        # "ports": [22, 8443],
                        "ports": [8443],
                    },
                },
                "client_affinity": "SOURCE_IP",
                "endpoint": self.soca_resources["nlb"].load_balancer_arn,
            },
        }

        # Create our required listeners as configured in the dict
        logger.debug(f"Creating AGA listeners: {_aga_listeners_needed}")

        _aga_listeners_created: list = []

        for _aga_listener in _aga_listeners_needed:
            _aga_listener = _aga_listener.upper()
            logger.debug(
                f"Creating AGA listener for {_aga_listener}: {_aga_listeners_needed[_aga_listener]}"
            )

            for _aga_protocol in _aga_listeners_needed[_aga_listener]["protocols"]:
                logger.debug(
                    f"Creating AGA listener for {_aga_listener}/{_aga_protocol}"
                )

                _port_spec_list: list = []
                for _port in _aga_listeners_needed[_aga_listener]["protocols"][
                    _aga_protocol
                ]["ports"]:
                    logger.debug(f"Adding {_aga_listener}/{_port} to PortSpec")
                    _port_spec_list.append(
                        globalaccelerator.CfnListener.PortRangeProperty(
                            from_port=_port, to_port=_port
                        )
                    )

                logger.debug(
                    f"Final PortSpec for {_aga_listener}/{_aga_protocol}: {_port_spec_list}"
                )

                # Now that we have built a portspec - we can create the multi-port listener
                self.soca_resources[f"aga_listener_{_aga_listener}_{_aga_protocol}"] = (
                    globalaccelerator.CfnListener(
                        self,
                        f"{user_specified_variables.cluster_id}-AGAListener-{_aga_listener}-{_aga_protocol}",
                        client_affinity=_aga_listeners_needed[_aga_listener][
                            "client_affinity"
                        ],
                        accelerator_arn=self.soca_resources["aga"].attr_accelerator_arn,
                        port_ranges=_port_spec_list,
                        protocol=_aga_protocol,
                    )
                )

                logger.debug(f"Creating AGA endpoint groups for {_aga_listener}")
                _aga_endpoint_group = globalaccelerator.CfnEndpointGroup(
                    self,
                    f"{user_specified_variables.cluster_id}-AGAEndpointGroup{_aga_listener}-{_aga_protocol}",
                    listener_arn=self.soca_resources[
                        f"aga_listener_{_aga_listener}_{_aga_protocol}"
                    ].attr_listener_arn,
                    endpoint_group_region=user_specified_variables.region,
                    endpoint_configurations=[
                        globalaccelerator.CfnEndpointGroup.EndpointConfigurationProperty(
                            endpoint_id=_aga_listeners_needed[_aga_listener][
                                "endpoint"
                            ],
                            weight=100,
                            client_ip_preservation_enabled=True,
                        )
                    ],
                )
                _aga_endpoint_group.node.add_dependency(
                    self.soca_resources[f"aga_listener_{_aga_listener}_{_aga_protocol}"]
                )

        # Make sure all of our listeners are listed as deps
        # for _aga_listener_name in _aga_listeners_created:
        #     logger.debug(f"Adding Dep for Endpoint group: {_aga_listener_name}")
        #     _aga_endpoint_group.node.add_dependency(self.soca_resources[_aga_listener_name])

        CfnOutput(
            self,
            "AGAAccessPoint",
            value=f'https://{self.soca_resources["aga"].attr_dns_name}/',
        )

        # _aga_ipv4_str: str = ", ".join(self.soca_resources["aga"].attr_ipv4_addresses)
        # CfnOutput(
        #     self,
        #     "AGAIPAddressList_ipv4",
        #     value=_aga_ipv4_str,
        # )

        # FIXME TODO
        # Output for IPv6?
        # _aga_ipv6_list = self.soca_resources["aga"].attr_ipv6_addresses
        # CfnOutput(
        #     self,
        #     "AGAIPAddresses_ipv4",
        #     value=f"{self.soca_resources["aga"].attr_ipv4_addresses}",
        # )

    def viewer_analytics_opensearch(self):
        """
        Configure the view for OpenSearch Analytics
        """
        if not user_specified_variables.os_endpoint:
            CfnOutput(
                self,
                "AnalyticsDashboard",
                value=f"https://{self.soca_resources['os_domain'].domain_endpoint}/_dashboards",
            )

        else:
            CfnOutput(
                self,
                "AnalyticsDashboard",
                value=f"https://{user_specified_variables.os_endpoint}/{'_dashboards' if get_config_key('Config.analytics.engine')  == 'opensearch' else '_plugin/kibana'}/",
            )

    def viewer_analytics_opensearch_serverless(self):
        """
        Configure the view for OpenSearch serverless.
        """
        logger.debug(f"viewer_analytics_opensearch_serverless")
        CfnOutput(
            self,
            "AnalyticsDashboard",
            value=f"https://{self.soca_resources['os_domain'].attr_dashboard_endpoint}",
        )

    @staticmethod
    def is_instance_available(instance_type: str, region: str) -> bool:
        """
        Check if the specified instance type is available in the given region.
        """
        ec2_client = boto3_helper.get_boto(
            service_name="ec2",
            profile_name=user_specified_variables.profile,
            region_name=region,
        )

        try:
            # pagination is not a concern since we are always looking at a single instance type
            response = ec2_client.describe_instance_types(
                InstanceTypes=[instance_type],
                Filters=[{"Name": "supported-usage-class", "Values": ["on-demand"]}],
            )
        except Exception as err:
            # This is a logger.warning vs logger.error since instance
            # types naturally vary between regions and do not represent
            # a hard error condition to concern the user.
            logger.warning(
                f"Error checking instance type availability for {instance_type} in {region}.  Error: {err}"
            )
            return False

        return len(response["InstanceTypes"]) > 0

    def select_best_instance(
        self, instance_list: list, region: str, fallback_instance: str
    ) -> tuple[str, str, str]:
        """
        Return the best instance type from a given list and region. This probes the region for instance availability and will return the first one that is available in the region.

        Returns tuple of (instance_type, instance_architecture, instance_ami).
        """
        _selected_instance: str = "amnesiac"
        _default_ami_for_instance: str = ""
        _instance_arch: str = "unknown"

        logger.debug(
            f"Selecting best instance from {instance_list} for region {region} ..."
        )
        for _instance in instance_list:
            if self.is_instance_available(instance_type=_instance, region=region):
                _instance_arch = get_arch_for_instance_type(
                    region=self._region, instancetype=_instance
                )
                _default_ami_for_instance = (
                    self.soca_resources.get("custom_ami_map", {})
                    .get(_instance_arch, {})
                    .get(self._base_os, "")
                )
                if _default_ami_for_instance:
                    _selected_instance = _instance
                    break
                else:
                    logger.warning(
                        f"No AMI found for {_instance} (arch {_instance_arch}, base os {self._base_os}, region {region}, testing next instance in selection"
                    )

        if _default_ami_for_instance is None:
            logger.fatal(
                "No AMI on region_map.yml found. Choose a different OS/Region or Architecture"
            )

        if _selected_instance == "amnesiac":
            _selected_instance = fallback_instance if fallback_instance else "m5.large"
            _instance_arch = "x86_64"

        logger.debug(
            f"Selected instance type of {_selected_instance} (Arch: {_instance_arch}) from {instance_list} in region {region} AMI is {_default_ami_for_instance}"
        )
        return _selected_instance, _instance_arch, _default_ami_for_instance

    @staticmethod
    def return_ebs_volume_name(base_os: str) -> str:
        """
        Return the EBS volume name based on the BaseOS.
        """
        _ebs_device_name: str = "unknown"

        if base_os.lower() in {"amazonlinux2", "amazonlinux2023"}:
            _ebs_device_name = "/dev/xvda"
        else:
            _ebs_device_name = "/dev/sda1"

        logger.debug(
            f"Returning EBS volume name {_ebs_device_name} for BaseOS: {base_os}"
        )
        return _ebs_device_name

    def dcv_infrastructure(self):
        # Create DCV Infrastructure - covers several items with different needs
        # session_manager - internal nlb
        # broker - internal nlb
        # gateway - external / internal nlb (depending on the deployment that the cluster uses)

        logger.debug(f"Entering DCV High Scale infrastructure")
        for _dcv_node_type in ("manager", "broker", "gateway"):
            _dcv_config: str = f"Config.dcv.{_dcv_node_type}"
            logger.debug(
                f"Creating DCV Node {_dcv_node_type} items using DCV configuration {_dcv_config} ..."
            )

            # Get our desired list of instances
            _dcv_desired_instance_type: list = get_config_key(
                key_name=f"{_dcv_config}.instance_type",
                expected_type=list,
                required=False,
                default=["m5.large"],
            )

            # What AMI should be used for this DCV instance?
            _dcv_desired_ami: str = get_config_key(
                key_name=f"{_dcv_config}.ami",
                expected_type=str,
                required=False,  # Fallback to default if needed
                default=self.soca_resources["ami_id"],
            )

            logger.debug(
                f"Creating DCV Node type - {_dcv_node_type} items using DCV configuration {_dcv_config}  Instance_Type: {_dcv_desired_instance_type}  AMI: {_dcv_desired_ami} ..."
            )

            # Determine the first-best instance type to use for this particular region
            logger.debug(
                f"Query instance availability for {_dcv_desired_instance_type}"
            )

            _dcv_selected_instance: str = (
                "m5.large"  # FIXME TODO - fallback set from select_best_instance
            )

            if isinstance(_dcv_desired_instance_type, list):
                logger.debug(
                    f"Checking for support of instance type (list) {_dcv_desired_instance_type} in region {user_specified_variables.region} for DCV {_dcv_node_type} ..."
                )

                _dcv_selected_instance, _dcv_selected_arch, _dcv_instance_ami = (
                    self.select_best_instance(
                        instance_list=_dcv_desired_instance_type,
                        region=user_specified_variables.region,
                        fallback_instance="m5.large",
                    )
                )

            # We manually replace the variable with the relevant ParameterStore as all ParamStore hierarchy is created at the very end of this CDK
            _user_data_variables = {
                "/configuration/BaseOS": user_specified_variables.base_os,
                "/configuration/ClusterId": user_specified_variables.cluster_id,
                "/configuration/UserDirectory/provider": get_config_key(
                    key_name="Config.directoryservice.provider"
                ),
                "/configuration/Region": Aws.REGION,
                "/configuration/Version": "25.5.0",
                "/configuration/CustomAMI": self.soca_resources[
                    "ami_id"
                ],  # FIXME TODO - This needs to be updated from the selected_instance and arch
                "/configuration/S3Bucket": user_specified_variables.bucket,
            }

            # add all System hierarchy
            _parameter_store_keys = flatten_parameterstore_config(
                get_config_key(key_name="Parameters", expected_type=dict)
            )
            for (
                _ssm_parameter_key,
                _ssm_parameter_value,
            ) in _parameter_store_keys.items():
                _user_data_variables[f"/{_ssm_parameter_key}"] = _ssm_parameter_value

            # Generate EC2 User Data
            _user_data_file: str = f"user_data/dcv_{_dcv_node_type}.sh.j2"
            logger.debug(
                f"Reading DCV Node {_dcv_node_type} User Data template {_user_data_file} ..."
            )

            # Generate EC2 User Data and clean all copyright header to save some space
            _user_data = self.jinja2_env.get_template(
                f"user_data/dcv_{_dcv_node_type}.sh.j2"
            ).render(
                context=_user_data_variables,
                ns=SimpleNamespace(template_already_included=[]),
            )

            # Create some roles
            _dcv_role = (
                self.soca_resources["compute_node_role"],
            )  # XXX FIXME TODO - DCV IAM ROle

            _volume_type = return_ebs_volume_type(
                volume_string=get_config_key(
                    key_name=f"{_dcv_config}.volume_type",
                    required=False,
                    default="gp3",
                    expected_type=str,
                ).lower()
            )
            self.soca_resources[f"dcv_{_dcv_node_type}_lt"] = ec2.LaunchTemplate(
                self,
                f"DCV-{_dcv_node_type}-LT",
                machine_image=ec2.MachineImage.generic_linux(
                    {user_specified_variables.region: _dcv_desired_ami}
                ),
                instance_type=ec2.InstanceType(_dcv_selected_instance),
                key_pair=ec2.KeyPair.from_key_pair_attributes(
                    self,
                    f"DCV-{_dcv_node_type}-KeyPair",
                    key_pair_name=user_specified_variables.ssh_keypair,
                ),
                require_imdsv2=True,
                role=self.soca_resources[f"dcv_{_dcv_node_type}_role"],
                block_devices=[
                    ec2.BlockDevice(
                        device_name=self.return_ebs_volume_name(
                            base_os=user_specified_variables.base_os
                        ),
                        volume=ec2.BlockDeviceVolume(
                            ebs_device=ec2.EbsDeviceProps(
                                volume_size=get_config_key(
                                    key_name=f"{_dcv_config}.volume_size",
                                    expected_type=int,
                                ),
                                volume_type=_volume_type,
                            )
                        ),
                    )
                ],
                # XXX FIXME TODO
                # security_group=self.soca_resources[f"dcv_{_dcv_node_type}_sg"],
                security_group=self.soca_resources[f"dcv_{_dcv_node_type}_sg"],
                user_data=ec2.UserData.custom(_user_data),
            )

            # Gateway potentially gets public while the others are private
            _subnet_type = ec2.SubnetType.PRIVATE_WITH_EGRESS
            if (
                _dcv_node_type == "gateway"
                and get_config_key("Config.entry_points_subnets").lower() == "public"
            ):
                _subnet_type = ec2.SubnetType.PUBLIC
            self.soca_resources[f"dcv_{_dcv_node_type}_asg"] = (
                autoscaling.AutoScalingGroup(
                    self,
                    f"DCV-{_dcv_node_type}-ASG",
                    vpc=self.soca_resources["vpc"],
                    launch_template=self.soca_resources[f"dcv_{_dcv_node_type}_lt"],
                    max_capacity=get_config_key(
                        key_name=f"{_dcv_config}.instance_count", expected_type=int
                    ),
                    min_capacity=get_config_key(
                        key_name=f"{_dcv_config}.instance_count", expected_type=int
                    ),
                    desired_capacity=get_config_key(
                        key_name=f"{_dcv_config}.instance_count", expected_type=int
                    ),
                    vpc_subnets=ec2.SubnetSelection(subnet_type=_subnet_type),
                )
            )

        # What are the ports that are we are interested in
        # TODO
        _port: int = 8443
        _protocol = elbv2.Protocol.TCP

        self.soca_resources[f"dcv_{_dcv_node_type}_tg"] = elbv2.NetworkTargetGroup(
            self,
            f"{user_specified_variables.cluster_id}-DCV-{_dcv_node_type}-TG",
            port=_port,
            protocol=_protocol,
            target_type=elbv2.TargetType.INSTANCE,
            vpc=self.soca_resources["vpc"],
            targets=[self.soca_resources[f"dcv_{_dcv_node_type}_asg"]],
            target_group_name=f"{user_specified_variables.cluster_id}-DCV-{_dcv_node_type}",
            health_check=elbv2.HealthCheck(port=str(_port), protocol=_protocol),
            connection_termination=True,
        )

        # Create NLBs
        for _dcv_nlb in {"frontend", "backend"}:
            _inet_facing: bool = False
            if (
                _dcv_nlb == "frontend"
                and get_config_key("Config.entry_points_subnets").lower() == "public"
            ):
                _inet_facing = True

            print(f"Creating DCV NLB for {_dcv_nlb} / Inet Facing: {_inet_facing}")

            self.soca_resources[f"dcv_{_dcv_nlb}_nlb"] = elbv2.NetworkLoadBalancer(
                self,
                f"SOCA-DCV-{_dcv_nlb}-NLB",
                load_balancer_name=f"{user_specified_variables.cluster_id}-dcv-{_dcv_nlb}-nlb",
                vpc=self.soca_resources["vpc"],
                # XXX FIXME TODO
                # security_groups=[self.soca_resources[f"dcv_{_dcv_nlb}_sg"]],
                security_groups=[self.soca_resources["compute_node_sg"]],
                internet_facing=_inet_facing,
            )

            if not user_specified_variables.os_endpoint:
                self.soca_resources[f"dcv_{_dcv_nlb}_nlb"].add_dependency(
                    self.soca_resources["os_domain"]
                )

            CfnOutput(
                self,
                f"DCV_{_dcv_nlb}-NLB",
                value=f"{self.soca_resources[f'dcv_{_dcv_nlb}_nlb'].load_balancer_dns_name}",
            )
        # FIXME To be migrated
        # Create listeners for each of the NLBs
        # XXX FIXME TODO
        # elbv2.NetworkListener(
        #     self,
        #     "SSHListener",
        #     load_balancer=self.soca_resources["nlb"],
        #     protocol=elbv2.Protocol.TCP,
        #     port=22,
        #     default_action=elbv2.NetworkListenerAction.forward(
        #         target_groups=[_dcv_node_target_groups]
        #     ),
        # )

        # Tags.of(_dcv_node_asg).add(
        #     "Name", f"{user_specified_variables.cluster_id}-DCV"
        # )
        # Tags.of(_dcv_node_asg).add("soca:NodeType", f"DCV-Infrastructure")


if __name__ == "__main__":
    app = App()

    # User specified variables/install properties, queryable as Python Object
    user_specified_variables = json.loads(
        json.dumps(
            {
                "install_properties": base64.b64decode(
                    app.node.try_get_context("install_properties")
                ).decode("utf-8"),
                "bucket": app.node.try_get_context("bucket"),
                "region": app.node.try_get_context("region"),
                "partition": app.node.try_get_context("partition"),
                "base_os": app.node.try_get_context("base_os"),
                "ssh_keypair": app.node.try_get_context("ssh_keypair"),
                "client_ip": app.node.try_get_context("client_ip"),
                "prefix_list_id": app.node.try_get_context("prefix_list_id"),
                "custom_ami": app.node.try_get_context("custom_ami"),
                "cluster_id": app.node.try_get_context("cluster_id"),
                "vpc_cidr": app.node.try_get_context("vpc_cidr"),
                "create_es_service_role": (
                    False
                    if app.node.try_get_context("create_es_service_role") == "False"
                    else True
                ),
                "vpc_azs": app.node.try_get_context("vpc_azs"),
                "vpc_id": app.node.try_get_context("vpc_id"),
                "public_subnets": (
                    app.node.try_get_context("public_subnets")
                    if app.node.try_get_context("public_subnets") is None
                    else ast.literal_eval(
                        base64.b64decode(
                            app.node.try_get_context("public_subnets")
                        ).decode("utf-8")
                    )
                ),
                "private_subnets": (
                    app.node.try_get_context("private_subnets")
                    if app.node.try_get_context("private_subnets") is None
                    else ast.literal_eval(
                        base64.b64decode(
                            app.node.try_get_context("private_subnets")
                        ).decode("utf-8")
                    )
                ),
                "fs_apps_provider": app.node.try_get_context("fs_apps_provider"),
                "fs_apps": app.node.try_get_context("fs_apps"),
                "fs_data_provider": app.node.try_get_context("fs_data_provider"),
                "fs_data": app.node.try_get_context("fs_data"),
                "compute_node_sg": app.node.try_get_context("compute_node_sg"),
                "controller_sg": app.node.try_get_context("controller_sg"),
                "alb_sg": app.node.try_get_context("alb_sg"),
                "nlb_sg": app.node.try_get_context("nlb_sg"),
                "login_node_sg": app.node.try_get_context("login_node_sg"),
                "vpc_endpoint_sg": app.node.try_get_context("vpc_endpoint_sg"),
                "elasticache_sg": app.node.try_get_context("elasticache_sg"),
                "compute_node_role": app.node.try_get_context("compute_node_role"),
                "controller_role": app.node.try_get_context("controller_role"),
                "directory_service_user": app.node.try_get_context(
                    "directory_service_user"
                ),
                "directory_service_user_password": app.node.try_get_context(
                    "directory_service_user_password"
                ),
                "directory_service_shortname": app.node.try_get_context(
                    "directory_service_shortname"
                ),
                "directory_service_name": app.node.try_get_context(
                    "directory_service_name"
                ),
                "directory_service_id": app.node.try_get_context(
                    "directory_service_id"
                ),
                "directory_service_ds_dns": app.node.try_get_context(
                    "directory_service_dns"
                ),
                "os_endpoint": app.node.try_get_context("os_endpoint"),
                "ldap_host": app.node.try_get_context("ldap_host"),
                "compute_node_role_name": app.node.try_get_context(
                    "compute_node_role_name"
                ),
                "compute_node_role_arn": app.node.try_get_context(
                    "compute_node_role_arn"
                ),
                "compute_node_role_from_previous_soca_deployment": app.node.try_get_context(
                    "compute_node_role_from_previous_soca_deployment"
                ),
                "controller_role_name": app.node.try_get_context(
                    "controller_role_name"
                ),
                "controller_role_arn": app.node.try_get_context("controller_role_arn"),
                "controller_role_from_previous_soca_deployment": app.node.try_get_context(
                    "controller_role_from_previous_soca_deployment"
                ),
                "spotfleet_role_name": app.node.try_get_context("spotfleet_role_name"),
                "spotfleet_role_arn": app.node.try_get_context("spotfleet_role_arn"),
                "spotfleet_role_from_previous_soca_deployment": app.node.try_get_context(
                    "spotfleet_role_from_previous_soca_deployment"
                ),
                "profile": (
                    None
                    if app.node.try_get_context("profile") == "False"
                    else app.node.try_get_context("profile")
                ),
            }
        ),
        object_hook=lambda d: SimpleNamespace(**d),
    )

    install_props = json.loads(
        user_specified_variables.install_properties,
    )

    # List of AWS endpoints & principals suffix
    endpoints_suffix = {
        "fsx_lustre": f"fsx.{Aws.REGION}.{Aws.URL_SUFFIX}",
        "fsx_openzfs": f"fsx.{Aws.REGION}.{Aws.URL_SUFFIX}",
        "fsx_ontap": f"fsx.{Aws.REGION}.{Aws.URL_SUFFIX}",
        "efs": f"efs.{Aws.REGION}.{Aws.URL_SUFFIX}",
    }

    principals_suffix = {
        "backup": f"backup.{Aws.URL_SUFFIX}",
        "cloudwatch": f"cloudwatch.{Aws.URL_SUFFIX}",
        "ec2": f"ec2.{Aws.URL_SUFFIX}",
        "lambda": f"lambda.{Aws.URL_SUFFIX}",
        "sns": f"sns.{Aws.URL_SUFFIX}",
        "spotfleet": f"spotfleet.{Aws.URL_SUFFIX}",
        "ssm": f"ssm.{Aws.URL_SUFFIX}",
    }

    # Apply default tag to all taggable resources
    if get_config_key(key_name="Config.custom_tags", required=False):
        for custom_tag in get_config_key(
            key_name="Config.custom_tags", expected_type=list
        ):
            Tags.of(app).add(custom_tag.get("Key"), custom_tag.get("Value"))
    Tags.of(app).add("soca:ClusterId", user_specified_variables.cluster_id)
    Tags.of(app).add("soca:CreatedOn", str(datetime.datetime.now(datetime.UTC)))
    Tags.of(app).add("soca:Version", get_config_key("Config.version"))

    # Launch Cfn generation
    cdk_env = Environment(
        account=os.environ["CDK_DEFAULT_ACCOUNT"],
        region=(
            user_specified_variables.region
            if user_specified_variables.region
            else os.environ["CDK_DEFAULT_REGION"]
        ),
    )

    install = SOCAInstall(
        app,
        user_specified_variables.cluster_id,
        env=cdk_env,
        description=f"SOCA cluster version {get_config_key('Config.version')}",
        termination_protection=get_config_key(
            key_name="Config.termination_protection",
            expected_type=bool,
            required=False,
            default=True,
        ),
    )
    app.synth()
