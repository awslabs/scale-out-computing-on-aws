# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
This hook reject the job if the user specify invalid security group or IAM roles
Doc:
> https://awslabs.github.io/scale-out-computing-on-aws-documentation/documentation/security/use-custom-sgs-roles/
"""

from __future__ import annotations


import logging
from utils.response import SocaResponse
from utils.error import SocaError
from utils.identity_provider_client import SocaIdentityProviderClient

logger = logging.getLogger("soca_logger")


def get_users_in_group(
    soca_identity: SocaIdentityProviderClient, group_list: list
) -> list:
    _users = []
    for group_name in group_list:
        logger.debug(f"Checking users in group {group_name}")
        if soca_identity.provider in [
            "openldap",
            "existing_openldap",
        ]:
            _filter = f"(&(objectClass=posixGroup)({group_name}))"
            _attr_list = ["memberUid"]
        else:

            _filter = f"(&(objectClass=user)(memberOf:1.2.840.113556.1.4.1941:={group_name},{soca_identity.ldap_group_search_base}))"
            _attr_list = ["sAMAccountName"]

        _check_membership = soca_identity.search(
            base=soca_identity.ldap_group_search_base,
            filter=_filter,
            attr_list=_attr_list,
        )

        if _check_membership.get("success") is False:
            logger.error(
                f"Unable to retrieve users in group {group_name} due to {_check_membership.get('message')}"
            )
        else:
            logger.debug(f"Found {_check_membership.get('message')} in {_filter}")
            for _user_cn, _user_attrs in _check_membership.get("message", []):
                if soca_identity.provider in ("openldap", "existing_openldap"):
                    for uid in _user_attrs.get("memberUid", [None])[0]:
                        if uid not in _users:
                            _users.append(uid)

                else:
                    sam_name = _user_attrs.get("sAMAccountName", [None])[0]
                    if sam_name and sam_name not in _users:
                        _users.append(sam_name)

    logger.debug(f"Found {_users=} for groups in list: {group_list}")
    return _users


def main(
    obj: "SocaHpcHooksValidator",
) -> SocaResponse | SocaError:

    logger.debug(f"Validating Queue ACLs for job owner {obj.job_owner}")

    allowed_users = (
        []
        if not obj.queue_config.get("allowed_users")
        else obj.queue_config.get("allowed_users")
    )  # Lsit of allowed individual/groups

    excluded_users = (
        []
        if not obj.queue_config.get("excluded_users")
        else obj.queue_config.get("excluded_users")
    )  # List of excluded individual users/groups

    if isinstance(allowed_users, list) is not True:
        return SocaError.GENERIC_ERROR(
            helper=f"allowed_users on {obj.queue_settings_file} for queue {obj.job_queue} must be a list. Detected: {type(allowed_users)}"
        )

    if isinstance(excluded_users, list) is not True:
        return SocaError.GENERIC_ERROR(
            helper=f"excluded_users on {obj.queue_settings_file} for queue {obj.job_queue} must be a list. Detected: {type(excluded_users)}"
        )

    allowed_users_groups = [
        user for user in allowed_users if "cn=" in user.lower()
    ]  # List of allowed groups
    excluded_users_groups = [
        user for user in excluded_users if "cn=" in user.lower()
    ]  # List of excluded groups

    users_in_allowed_groups = []  # List of users that belong to any allowed groups
    users_in_excluded_groups = []  # List of users that belongs to any excluded groups

    logger.debug(
        f"{allowed_users=} / {excluded_users=} / {allowed_users_groups=} / {excluded_users_groups=} for {obj.job_queue}"
    )

    # Reject if allowed_users is empty
    if allowed_users == []:
        return SocaError.GENERIC_ERROR(f"{obj.job_owner} is excluded on this queue")

    # Reject explicit deny (this does not include if users belong to any groups, which will be checked later)
    if "*" in excluded_users or obj.job_owner in excluded_users:
        return SocaError.GENERIC_ERROR(f"{obj.job_owner} is excluded on this queue")

    # check if groups are specified
    if excluded_users_groups or allowed_users_groups:
        # Find Group Associated to user
        _soca_identity_client = SocaIdentityProviderClient()
        _soca_identity_client.initialize()
        _soca_identity_client.bind_as_service_account()
        if allowed_users_groups:
            users_in_allowed_groups = get_users_in_group(
                soca_identity=_soca_identity_client, group_list=allowed_users_groups
            )

        if excluded_users_groups:
            users_in_excluded_groups = get_users_in_group(
                soca_identity=_soca_identity_client, group_list=excluded_users_groups
            )

    logger.debug(
        f"Users in Allowed Groups {users_in_allowed_groups}, users in Excluded Groups {users_in_excluded_groups}"
    )
    # merge the two lists, allowed/excluded users now include users that belong to the groups mentioned in both lists
    allowed_users = list(set(allowed_users) | set(users_in_allowed_groups))
    excluded_users = list(set(excluded_users) | set(users_in_excluded_groups))

    # Validate ACLs, starting with deny
    if obj.job_owner in excluded_users:
        return SocaError.GENERIC_ERROR(
            helper=f"{obj.job_owner} is excluded on this queue"
        )
    else:
        # if user is not explicitly excluded, check if he is allowed
        if "*" in allowed_users or obj.job_owner in allowed_users:
            return SocaResponse(success=True, message="Validated queue ACLs")
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"{obj.job_owner} is not authorized to use this queue"
            )
