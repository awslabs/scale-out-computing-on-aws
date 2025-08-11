# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from utils.aws.ssm_parameter_store import SocaConfig
import ast
from typing import Any
import logging

logger = logging.getLogger("soca_logger")


# note: keys are received from System Manager and stored as str
def parse_feature_flags(flag_name: str, value: Any = None) -> dict:
    _default_enabled = True
    _default_allowed_users = []
    _default_denied_users = []
    logger.debug(f"Feature Flag {flag_name=}: {value=}")
    try:
        parsed = ast.literal_eval(value)
    except Exception as err:
        logger.error(
            f"Unable to parse feature flag, default value to {_default_enabled=} {_default_allowed_users=} {_default_denied_users=} .."
        )
        return {
            "enabled": _default_enabled,
            "allowed_users": _default_allowed_users,
            "denied_users": _default_denied_users,
        }

    if not isinstance(parsed, dict):
        return {
            "enabled": _default_enabled,
            "allowed_users": _default_allowed_users,
            "denied_users": _default_denied_users,
        }

    # Received valid dictionary
    if str(parsed.get("enabled")).lower() == "true":
        _enabled = True
    elif str(parsed.get("enabled")).lower() == "false":
        _enabled = False
    else:
        _enabled = _default_enabled

    try:
        _allowed_users = parsed.get("allowed_users", _default_allowed_users)
        if not isinstance(_allowed_users, list):
            _allowed_users = _default_allowed_users
    except Exception as err:
        logger.error(
            f"Unable to parse allowed_users due to {err}, default to {_default_allowed_users=}"
        )
        _allowed_users = _default_allowed_users

    try:
        _denied_users = parsed.get("denied_users", _default_denied_users)
        if not isinstance(_denied_users, list):
            _denied_users = _default_denied_users
    except Exception as err:
        logger.error(
            f"Unable to parse denied_isers due to {err}, default to {_default_denied_users=}"
        )
        _denied_users = _default_denied_users

    return {
        "enabled": _enabled,
        "allowed_users": _allowed_users,
        "denied_users": _denied_users,
    }


if (
    result := SocaConfig(key="/configuration/FeatureFlags/").get_value(return_as=dict)
).success:
    _feature_list = result.message
else:
    _feature_list = {}


# ------------------------------------------------------------------------------
# FEATURE FLAGS
# Use enabled: False to fully disable a feature for everyone regardless of user lists.
# If enabled: True and allowed_users is empty, it implies all users are allowed unless explicitly denied.
# if enabled: True and allowed_users is not empty, it implies only those users are allowed unless explicitly denied.
#
#
# - VIRTUAL_DESKTOPS: Manage Virtual Desktops Views and APIs
# - TARGET_NODES: Manage Target Nodes Views and APIs
# - LOGIN_NODES: Manage Login Nodes Views and APIs (e.g: SSH section on the web UI)
# - HPC: Manage HPC Views and APIs, including My Jobs Queue, and web based job submission
# - FILE_BROWSER: Manage File Browser (My Files) Views and APIs
# - USERS_GROUPS_MANAGEMENT: Users/Groups Management
# - CONTAINER_MANAGEMENT: Manage Containers Views and APIs
# - MY_API_KEY_MANAGEMENT: Manage API Key Views and APIs
# - SFTP_INSTRUCTIONS: Manage SFTP View
# - MY_ACCOUNT_MANAGEMENT: Manage My Account Views
# - ANALYTICS_COST_MANAGEMENT: Manage Budget/Analytics Views
# ------------------------------------------------------------------------------

FEATURE_FLAGS = {
    "VIRTUAL_DESKTOPS": parse_feature_flags(
        flag_name="VIRTUAL_DESKTOPS",
        value=_feature_list.get(
            "/configuration/FeatureFlags/WebInterface/VirtualDesktops", {}
        ),
    ),
    "TARGET_NODES": parse_feature_flags(
        flag_name="TARGET_NODES",
        value=_feature_list.get(
            "/configuration/FeatureFlags/WebInterface/TargetNodes", {}
        ),
    ),
    "LOGIN_NODES": parse_feature_flags(
        flag_name="LOGIN_NODES",
        value=_feature_list.get(
            "/configuration/FeatureFlags/WebInterface/LoginNodes", {}
        ),
    ),
    "HPC": parse_feature_flags(
        flag_name="HPC",
        value=_feature_list.get("/configuration/FeatureFlags/WebInterface/Hpc", {}),
    ),
    "FILE_BROWSER": parse_feature_flags(
        flag_name="FILE_BROWSER",
        value=_feature_list.get(
            "/configuration/FeatureFlags/WebInterface/FileBrowser", {}
        ),
    ),
    "USERS_GROUPS_MANAGEMENT": parse_feature_flags(  # remove admin capability for user/group management
        flag_name="USERS_GROUPS_MANAGEMENT",
        value=_feature_list.get(
            "/configuration/FeatureFlags/WebInterface/UsersGroupsManagement", {}
        ),
    ),
    "CONTAINERS_MANAGEMENT": parse_feature_flags(
        flag_name="CONTAINERS_MANAGEMENT",
        value=_feature_list.get(
            "/configuration/FeatureFlags/WebInterface/ContainersManagement", {}
        ),
    ),
    "MY_API_KEY_MANAGEMENT": parse_feature_flags(
        flag_name="MY_API_KEY_MANAGEMENT",
        value=_feature_list.get(
            "/configuration/FeatureFlags/WebInterface/MyApiKeyManagement", {}
        ),
    ),
    "SFTP_INSTRUCTIONS": parse_feature_flags(
        flag_name="SFTP_INSTRUCTIONS",
        value=_feature_list.get(
            "/configuration/FeatureFlags/WebInterface/SftpInstructions", {}
        ),
    ),
    "MY_ACCOUNT_MANAGEMENT": parse_feature_flags(  # WARNING: this will remove password reset ability for your users
        flag_name="MY_ACCOUNT_MANAGEMENT",
        value=_feature_list.get(
            "/configuration/FeatureFlags/WebInterface/MyAccountManagement", {}
        ),
    ),
    "ANALYTICS_COST_MANAGEMENT": parse_feature_flags(
        flag_name="ANALYTICS_COST_MANAGEMENT",
        value=_feature_list.get(
            "/configuration/FeatureFlags/WebInterface/AnalyticsCostManagement", {}
        ),
    ),
}
