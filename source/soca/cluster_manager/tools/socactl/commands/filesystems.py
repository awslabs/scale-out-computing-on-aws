# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import click
from click.testing import CliRunner

import re
from commands.common import print_output, is_controller_instance
from commands.config import set as config_set
from commands.config import get as config_get
from commands.config import key_exists as config_key_exists


@click.group()
def filesystems():
    pass


@filesystems.command()
@click.option(
    "-k",
    "--key",
    help="Specify a top level FileSystem UUID key (e.g: apps, data ...)",
)
@click.option(
    "--output",
    default="text",
    type=click.Choice(["text", "json", "yaml"]),
    help="Output result as: text, json, yaml",
)
@click.option(
    "--flatten",
    is_flag=True,
    default=False,
    help="Flatten Key as stored on SSM",
)
@click.pass_context
def get(ctx, key, output, flatten):
    if key is not None:
        if not key.endswith("/"):
            key = f"{key}/"

        if "/configuration/FileSystems/" in key:
            _ssm_key = key
        else:
            _ssm_key = f"/configuration/FileSystems/{key}"
    else:
        _ssm_key = f"/configuration/FileSystems/"

    ctx.meta["echo"] = False
    _get_key = ctx.invoke(config_get, key=_ssm_key)
    if flatten:
        print_output(message=_get_key, output=output)
    else:
        _fs_data = {}
        for key, value in _get_key.items():
            parts = key.replace("/configuration/FileSystems/", "").split("/")
            current_dict = _fs_data
            for part in parts[:-1]:
                if part not in current_dict:
                    current_dict[part] = {}
                current_dict = current_dict[part]

            current_dict[parts[-1]] = value
        print_output(message=_fs_data, output=output)


@filesystems.command()
@click.option(
    "-n",
    "--filesystem-name",
    type=str,
    required=True,
    help="Specify a top level FileSystem UUID key (e.g: apps, data ...)",
)
@click.option(
    "-p",
    "--provider",
    type=click.Choice(
        [
            "efs",
            "nfs",
            "fsx_lustre",
            "fsx_ontap",
            "fsx_openzfs",
            "s3",
        ]
    ),
    required=True,
    help="Specify a provider for the filesystem",
)
@click.option(
    "-m",
    "--mount-path",
    type=str,
    required=True,
    help="Specify a mount path for the filesystem",
)
@click.option(
    "-t",
    "--mount-target",
    type=str,
    required=True,
    help="Specify the mount target for the filesystem",
)
@click.option(
    "-o",
    "--mount-options",
    required=False,
    help="Specify mount options for the filesystem",
)
@click.option(
    "-f",
    "--on-mount-failure",
    type=click.Choice(["ignore", "exit"]),
    default="ignore",
    help="Specify on mount failure behavior",
)
@click.option(
    "-e",
    "--enabled",
    type=click.Choice(["true", "false"]),
    default="true",
    help="Enable the filesystem",
)
@click.option(
    "--force",
    is_flag=True,
    default=False,
    type=bool,
    help="Force create, ignore confirmation message",
)
@click.pass_context
def set(
    ctx,
    filesystem_name,
    provider,
    mount_path,
    mount_target,
    mount_options,
    on_mount_failure,
    enabled,
    force,
):

    _providers = {
        "efs": {
            "target_regex": r"fs-[0-9a-z]{8,40}",
            "help_message": "Expected mount_target is a valid EFS Filesystem ID (e.g fs-abcde123)",
            "default_mount_options": "nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport",
        },
        "nfs": {
            "target_regex": r"^((?:(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2, }|(?:\d{1, 3}\.){3}\d{1, 3}))(?::\d+)?(?:\/[\w\-/]*)?$",
            "help_message": "Expected mount_target is a valid IP or DNS name with optional :/path ",
            "default_mount_options": "nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport",
        },
        "fsx_lustre": {
            "target_regex": r"fs-[0-9a-z]{8,40}",
            "help_message": "Expected mount_target is a valid FSx Lustre Filesystem ID (e.g fs-abcde123)",
            "default_mount_options": "defaults,noatime,flock,_netdev",
        },
        "fsx_ontap": {
            "target_regex": r"^fsvol-\w{8,}$",
            "help_message": "Expected mount_target is a valid FSx for NetApp Ontap Volume ID (e.g fsvol-abcde123)",
            "default_mount_options": "defaults,noatime,_netdev",
        },
        "fsx_openzfs": {
            "target_regex": r"fs-[0-9a-z]{8,40}",
            "help_message": "Expected mount_target is a valid Fsx for OpenZFS Filesystem ID (e.g fs-abcde123)",
            "default_mount_options": "nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport",
        },
        "s3": {
            "target_regex": r"(?!(^(xn--|sthree-|sthree-configurator)|.+(-s3alias|--ol-s3)$))^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$",
            "help_message": "Expected mount_target is a valid S3 bucket name",
            "default_mount_options": "--read-only",
        },
    }

    if provider not in _providers.keys():
        print_output(
            message=f"Provider selected is not part of {_providers.keys()}", error=True
        )

    if not mount_path.startswith("/"):
        print_output(message=f"Mount path must start with /", error=True)

    # s3-mountpoint expects just the bucket name
    if provider == "s3" and mount_target.startswith("s3://"):
        mount_target = mount_target.replace("s3://", "")

    if mount_options is None:
        mount_options = _providers[provider]["default_mount_options"]
        print_output(
            message=f"Mount options not specified. Using default: {mount_options}"
        )

    if not re.match(_providers[provider]["target_regex"], mount_target):
        print_output(
            message=f"Selected mount_target {mount_target} is not valid for provider {provider}. {_providers[provider]['help_message']}. Expected Regex: {_providers[provider]['target_regex']}",
            error=True,
        )

    # Reminder: All SSM keys are stored as str
    _ssm_keys = {
        f"/configuration/FileSystems/{filesystem_name}/provider": str(provider),
        f"/configuration/FileSystems/{filesystem_name}/mount_path": str(mount_path),
        f"/configuration/FileSystems/{filesystem_name}/mount_target": str(mount_target),
        f"/configuration/FileSystems/{filesystem_name}/enabled": str(enabled).lower(),
        f"/configuration/FileSystems/{filesystem_name}/on_mount_failure": str(
            on_mount_failure
        ),
        f"/configuration/FileSystems/{filesystem_name}/mount_options": str(
            mount_options
        ),
    }
    if force is False:
        print_output(_ssm_keys, output="json")
        while input(
            "Do you want to create this new filesystem (add --force to skip this confirmation)? (yes/no)"
        ) not in ["yes", "no"]:
            if (
                input(
                    "Do you want to create this new filesystem (add --force to skip this confirmation? (yes/no)"
                )
                == "no"
            ):
                print_output(message="Exiting", error=True)
            else:
                break

    # proceed to actual filesystem creation
    for key, value in _ssm_keys.items():
        ctx.meta["echo"] = True
        ctx.invoke(config_set, key=key, value=value, called_from="filesystems")


@filesystems.command()
@click.option(
    "-n",
    "--filesystem-name",
    type=str,
    required=True,
    help="Specify a top level FileSystem UUID key (e.g: apps, data ...)",
)
@click.option(
    "-k",
    "--key",
    type=click.Choice(["mount_options", "enabled", "mount_path"]),
    help="You can only update mount_options, enabled or mount_path key for an existing filesystem.",
    required=True,
)
@click.option("-v", "--value", help="New value", required=True)
@click.pass_context
def update(ctx, filesystem_name, key, value):
    if filesystem_name in ["apps", "data"]:
        print_output(message="You cannot update apps or data filesystems", error=True)

    if key == "mount_path" and not value.startswith("/"):
        print_output(message="Mount path must start with /", error=True)

    if key == "enabled" and value.lower() not in ["true", "false"]:
        print_output(message="Enabled must be true or false", error=True)

    if ctx.invoke(get, key=f"/configuration/FileSystems/{filesystem_name}/") is False:
        print_output(message=f"Filesystem {filesystem_name} does not exist", error=True)
    else:
        ctx.meta["echo"] = True
        ctx.invoke(
            config_set,
            key=f"/configuration/FileSystems/{filesystem_name}/{key}",
            value=value,
            called_from="filesystems",
        )
