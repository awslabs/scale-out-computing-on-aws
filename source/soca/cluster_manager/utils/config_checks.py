# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import ast
import re
from utils.response import SocaResponse
from utils.error import SocaError
from typing import Any
from utils.aws.boto3_wrapper import get_boto
from botocore.exceptions import ClientError
import os
import yaml
import logging

logger = logging.getLogger("soca_logger")


class SocaConfigKeyVerifier:
    _IMMUTABLE_KEYS = [
        "/configuration/ClusterId",
        "/configuration/Region",
        "/packages/controller",
        "/packages/dcv_amazonlinux",
        "/packages/openldap_server",
        "/packages/sssd",
        "/packages/system",
    ]

    _SPECIAL_VALIDATION_TESTS = [
        "list_of_string",
        "list_of_int",
        "valid_iam_role",
        "valid_s3_bucket",
        "valid_ssh_keypair",
        "list_of_ec2_instances",
        "list_of_ec2_subnet_ids",
    ]

    _KEY_CONFIG_FILE = f"/opt/soca/{os.environ.get('SOCA_CLUSTER_ID')}/cluster_manager/utils/settings/socaconfig_key_validator.yml"

    def __init__(self, key: str):
        self.key = key

    @staticmethod
    def get_validation_test(schema: dict, keys: list):
        for key in keys:
            schema = schema.get(key)
            if schema is None:
                return None
        return schema

    def check(self, value: Any):
        # Note: All SSM are stored as str, however we just validate if the string value can be cast as expected type
        # ex: "['subnet-1', 'subnet-2', 'subnet-3']" -> Stored on SSM as String but retrieved on SOCA as list
        if not isinstance(value, str):
            value = str(value)

        if not self.key.startswith("/"):
            key = f"/{self.key}"
        else:
            key = self.key

        if key in SocaConfigKeyVerifier._IMMUTABLE_KEYS:
            return SocaError.SOCA_CONFIG_KEY_VERIFIER(
                helper=f"{key} is immutable, you cannot change its value"
            )

        logger.info(
            f"Reading SocaConfig key checkers {SocaConfigKeyVerifier._KEY_CONFIG_FILE}"
        )

        try:
            with open(SocaConfigKeyVerifier._KEY_CONFIG_FILE, "r") as file:
                try:
                    _schema = yaml.safe_load(file)
                except yaml.YAMLError as e:
                    return SocaError.SOCA_CONFIG_KEY_VERIFIER(
                        helper=f"Error parsing YAML file {SocaConfigKeyVerifier._KEY_CONFIG_FILE} because of  {e}"
                    )
        except Exception as err:
            return SocaError.SOCA_CONFIG_KEY_VERIFIER(
                helper=f"Unable to access YAML config file {SocaConfigKeyVerifier._KEY_CONFIG_FILE} due to {err}"
            )
        # /configuration/FileSystems tree has an extra unique UUID (fs name)
        # e.g /configuration/FileSystems/mycustompath/provider
        # We remove `mycustompath` as this is customer supplier and validate the key /configuration/FileSystems/provider
        if "/configuration/FileSystems/" in key:
            _key = key.split("/configuration/FileSystems/")[1]
            key = f"/configuration/FileSystems/{'/'.join(_key.split('/')[1:])}"

        # key uses this type of format /configuration/BaseOS, but yaml db is dict {"configuration": { "BaseOS": ... } }
        # we flatten the key e.g: ["configuration","BaseOS"] then parse the dictionary tree
        _validation_test = self.get_validation_test(
            _schema, [item for item in key.split("/") if item]
        )
        logger.debug(f"Detected Validation Test for {key} -> {_validation_test}")
        if _validation_test is None:
            return SocaError.SOCA_CONFIG_KEY_VERIFIER(
                helper=f"{key} does not exist in util.config_checks"
            )
        else:
            if _validation_test in SocaConfigKeyVerifier._SPECIAL_VALIDATION_TESTS:
                if _validation_test == "list_of_string":
                    _result = self.verify_list_of_type(
                        value=value, list_item_type="str", item_pattern=None
                    )
                elif _validation_test == "list_of_int":
                    _result = self.verify_list_of_type(
                        value=value, list_item_type="int"
                    )
                elif _validation_test == "valid_iam_role":
                    _result = self.valid_iam_role(role_name=value)

                elif _validation_test == "valid_s3_bucket":
                    _result = self.valid_s3_bucket(bucket_name=value)

                elif _validation_test == "valid_ssh_keypair":
                    _result = self.valid_ssh_keypair(key_name=value)

                elif _validation_test == "list_of_ec2_subnet_ids":
                    _list_of_subnets = ast.literal_eval(value)
                    if not isinstance(_list_of_subnets, list):
                        _result = SocaError.SOCA_CONFIG_KEY_VERIFIER(
                            helper=f"{value} is not a list"
                        )
                    else:
                        _result = self.valid_subnet_id(subnet_ids=_list_of_subnets)
            else:
                _result = self.verify_regex(value=value, regex_pattern=_validation_test)

            if _result is True:
                return SocaResponse(success=True, message="")
            else:
                return SocaResponse(success=False, message=_result)

    @staticmethod
    def valid_subnet_id(subnet_ids: list) -> [bool, str]:
        _ec2_client = get_boto(service_name="ec2").message
        try:
            _ec2_client.describe_subnets(SubnetIds=subnet_ids)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidSubnetID.NotFound":
                return f"One or more subnets in {subnet_ids} do not exist"
            else:
                return f"Unable to verify {subnet_ids} because of {e}"

    @staticmethod
    def valid_s3_bucket(bucket_name: str) -> [bool, str]:
        _s3_client = get_boto(service_name="s3").message
        try:
            _s3_client.head_bucket(Bucket=bucket_name)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "404":
                return f"{bucket_name} does not exist"
            else:
                return f"Unable to verify {bucket_name} because of {e}"

    @staticmethod
    def valid_ssh_keypair(key_name):
        _ec2_client = get_boto(service_name="ec2").message

        try:
            _ec2_client.describe_key_pairs(KeyNames=[key_name])
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidKeyPair.NotFound":
                return f"{key_name} does not seem to exist in the region"
            else:
                return f"Unable to verify {key_name} because of {e}"

    @staticmethod
    def valid_iam_role(role_name: str) -> [bool, str]:
        _iam_client = get_boto(service_name="iam").message
        try:
            _iam_client.get_role(RoleName=role_name)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "NoSuchEntity":
                return "IAM role does not exist"
            else:
                return f"Unable to check IAM role due to {e}"

    @staticmethod
    def verify_list_of_type(
        value: str, list_item_type: str, item_pattern: str = None
    ) -> [bool, str]:
        _allowed_item_type = ["str", "int", "float", "dict", "list"]

        if list_item_type not in _allowed_item_type:
            return f"list_item_type must be {' '.join(_allowed_item_type)}"

        if item_pattern and list_item_type != "str":
            return "item_pattern can only be set if list_item_type is set to str"

        if isinstance(value, list):
            if list_item_type == "str":
                if item_pattern:
                    if all(
                        isinstance(item, str) and re.match(item_pattern, item)
                        for item in value
                    ):
                        return True
                    else:
                        return f"One or more items in the list do not match the pattern {item_pattern}"
                else:
                    if all(isinstance(item, str) for item in value):
                        return True
                    else:
                        return f"One or more items in the list are not strings"

            elif list_item_type == "int":
                if all(isinstance(item, int) for item in value):
                    return True
                else:
                    return f"One or more items in the list are not integers"

            elif list_item_type == "float":
                if all(isinstance(item, float) for item in value):
                    return True
                else:
                    return f"One or more items in the list are not floats"

            elif list_item_type == "dict":
                if all(isinstance(item, dict) for item in value):
                    return True
                else:
                    return f"One or more items in the list are not dictionaries"

            elif list_item_type == "list":
                if all(isinstance(item, list) for item in value):
                    return True
                else:
                    return f"One or more items in the list are not lists"

        return False

    @staticmethod
    def verify_regex(value: str, regex_pattern: str) -> [bool, str]:
        if re.match(regex_pattern, value):
            return True
        else:
            return f"{value} is does not match {regex_pattern}"
