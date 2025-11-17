# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0  

from typing import Optional
import pwd
import os
import subprocess
from flask import session
import logging
from pathlib import Path
from enum import IntFlag
from utils.error import SocaError
from functools import lru_cache

logger = logging.getLogger("soca_logger")


class Permissions(IntFlag):
    READ = 1
    WRITE = 2
    EXECUTE = 4


@lru_cache(maxsize=1)
def get_test_bin_path() -> str:
    if Path("/bin/test").exists():
        return "/bin/test"
    elif Path("/usr/bin/test").exists():
        return "/usr/bin/test"
    else:
        raise FileNotFoundError("Unable to find /bin/test or /usr/bin/test")


def drop_privileges(user: str):
    """
    Returns a function that drops the current process's privileges to those of the specified user.

    This includes setting the user's:
        - Supplementary group memberships
        - Primary group ID (GID)
        - User ID (UID)

    This is essential for accurately emulating user-level file permissions, especially when group-based access is involved.

    Args:
        user (str): The username whose privileges should be assumed.

    Returns:
        Callable[[], None]: A no-argument function suitable for passing as `preexec_fn`
        in `subprocess.run`, which applies the UID/GID/group changes.

    Raises:
        KeyError: If the specified user is not found in the system's password database.
        PermissionError: If the process lacks sufficient privileges (e.g., not running as root)
        to change UID/GID/groups.

    Example:
        subprocess.run(
            ["test", "-r", "/some/file"],
            preexec_fn=drop_privileges("mickael"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    """
    pw_record = pwd.getpwnam(user)
    user_uid = pw_record.pw_uid
    if user_uid < 1000:
        logger.error(f"Unable to set UID for user {user} as {user_uid} is < 1000")
        raise PermissionError()

    user_gid = pw_record.pw_gid

    # Get all groups the user belongs to
    user_groups = os.getgrouplist(user, user_gid)
    logger.info(
        f"{user=} with {user_uid=} and all groups {user_gid=} and {user_groups=}"
    )

    def _set_ids():
        os.setgroups(user_groups)  # Set supplementary groups
        os.setgid(user_gid)  # Set primary group
        os.setuid(user_uid)  # Set user ID

    return _set_ids


def check_user_permission(
    path: str,
    permissions: Permissions,
    user: Optional[str] = None,
    paths_to_restrict: Optional[list[str]] = None
) -> bool:
    """
    Check if a given user has the specified permission (read or write) for a file or directory.

    Args:
        path (str): The absolute path to the file or directory.
        permission_required (Literal["write", "read"]): The type of permission to check for.
        user (Optional[str], optional): The username to check permissions for. If None, attempts
            to get it from the session.

    Returns:
        bool: True if the user has the specified permission on the path, False otherwise.

    Logs:
        - Errors if the user cannot be determined or if an invalid permission type is passed.
        - Info logs for permission checks and results.

    Notes:
        - This function is Unix-specific and requires appropriate privileges to drop user IDs.
        - It uses `os.setuid()` which will only work if the Python process has sufficient
          permissions (typically root).
        - Ensure `session` is a valid context variable and `logger` is properly configured.
    """
    _file_path = Path(path).resolve()
    logger.info(f"Checking user acl for {_file_path=}, {permissions=}, {user=}")

    if _file_path.exists() is False:
        logger.error(f"{path} does not exist")
        return False

    user = user or session.get("user", "")
    if not user:
        logger.error("Unable to find user in session")
        return False

    if _file_path.is_symlink():
        # Resolve the target as stored in the symlink (may be relative)
        _raw_target = _file_path.readlink()
        # resolve absolute
        _file_path = _raw_target.resolve()
        logger.info(f"Symlink detected, using destination {_file_path}")

    if _file_path.is_dir():
        _folder_location = _file_path
    else:
        _folder_location = _file_path.parent

    logger.info(f"Folder location {_folder_location.resolve()} for {_file_path=}")
    if paths_to_restrict:
        for restricted_path in paths_to_restrict:
            if _folder_location.resolve().is_relative_to(Path(restricted_path).resolve()):
                logger.error(f"{_file_path=} is in restricted path {restricted_path}")
                return False

    logger.info(f"Checking if user {user} has permission to {path}")

    permissions_flags = {
        Permissions.READ: "-r",
        Permissions.WRITE: "-w",
        Permissions.EXECUTE: "-x",
    }

    if not permissions:
        logger.error("No permission specified")
        return False

    try:
        _test_bin_path = get_test_bin_path()
    except FileNotFoundError as e:
        return SocaError.GENERIC_ERROR(helper=str(e)).as_flask()

    has_permission = True
    for perm, flag in permissions_flags.items():
        if permissions & perm:
            _run_test_command = subprocess.run(
                [_test_bin_path, flag, path],
                preexec_fn=drop_privileges(user),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            if _run_test_command.returncode != 0:
                logger.error(
                    f"Missing permission for {user} : {perm.name.lower()} on {path}"
                )
                has_permission = False
    logger.info(f"{user=} {has_permission=} {permissions=} {path=}")
    return has_permission
