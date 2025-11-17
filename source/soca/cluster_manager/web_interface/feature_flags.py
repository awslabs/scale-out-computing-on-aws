# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from utils.aws.ssm_parameter_store import SocaConfig
import ast
from typing import Any
import logging

logger = logging.getLogger("soca_logger")


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
# - RUN_REMOTE_COMMAND: Allow to run Remote Command on the Controller
# - FILE_BROWSER: Manage File Browser (My Files) Views and APIs
# - USERS_GROUPS_MANAGEMENT: Users/Groups Management
# - CONTAINER_MANAGEMENT: Manage Containers Views and APIs
# - MY_API_KEY_MANAGEMENT: Manage API Key Views and APIs
# - SFTP_INSTRUCTIONS: Manage SFTP View
# - MY_ACCOUNT_MANAGEMENT: Manage My Account Views
# - ANALYTICS_COST_MANAGEMENT: Manage Budget/Analytics Views
# ------------------------------------------------------------------------------

FEATURE_FLAGS = {
    "VIRTUAL_DESKTOPS": {"enabled": True, "allowed_users": [], "denied_users": []},
    "TARGET_NODES": {"enabled": True, "allowed_users": [], "denied_users": []},
    "LOGIN_NODES": {"enabled": True, "allowed_users": [], "denied_users": []},
    "HPC": {"enabled": True, "allowed_users": [], "denied_users": []},
    "RUN_REMOTE_COMMAND": {"enabled": False, "allowed_users": [], "denied_users": []}, # WARNING: this will allow user to run remote command on the scheduler
    "FILE_BROWSER": {"enabled": True, "allowed_users": [], "denied_users": []},
    "USERS_GROUPS_MANAGEMENT": {
        "enabled": True,
        "allowed_users": [],
        "denied_users": [],
    },
    "CONTAINERS_MANAGEMENT": {
        "enabled": False,
        "allowed_users": [],
        "denied_users": [],
    },
    "MY_API_KEY_MANAGEMENT": {"enabled": True, "allowed_users": [], "denied_users": []},
    "SFTP_INSTRUCTIONS": {"enabled": True, "allowed_users": [], "denied_users": []},
    "MY_ACCOUNT_MANAGEMENT": {  # WARNING: this will remove password reset ability for your users
        "enabled": True,
        "allowed_users": [],
        "denied_users": [],
    },
    "ANALYTICS_COST_MANAGEMENT": {
        "enabled": True,
        "allowed_users": [],
        "denied_users": [],
    },
}
