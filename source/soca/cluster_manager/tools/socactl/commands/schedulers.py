# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import click
import ast
from commands.common import print_output, is_controller_instance
from commands.config import set as config_set
from commands.config import get as config_get
from commands.config import key_exists as config_key_exists


@click.group()
def schedulers():
    pass


@schedulers.command()
@click.option(
    "--scheduler-identifier",
    help="Specify a scheduler identifier",
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
def get(ctx, scheduler_identifier, output, flatten):
    if scheduler_identifier is not None:
        if "/configuration/Schedulers/" in scheduler_identifier:
            _ssm_key = scheduler_identifier
        else:
            _ssm_key = f"/configuration/Schedulers/{scheduler_identifier}"
    else:
        _ssm_key = "/configuration/Schedulers/"

    ctx.meta["echo"] = False
    _get_key = ctx.invoke(config_get, key=_ssm_key)
    if scheduler_identifier:
        try:
            _get_key = ast.literal_eval(_get_key)
        except Exception as e:
            print_output(
                message=f"Unable to convert {_get_key} to dict. Received error {e}",
                error=True,
            )

    if flatten:
        print_output(message=_get_key, output=output)
    else:
        if not isinstance(_get_key, dict):
            print_output(
                message=f"Unable to get scheduler information for {scheduler_identifier} as valid dict. Received output {_get_key}",
                error=True,
            )
        _scheduler_data = {}
        for key, value in _get_key.items():
            parts = key.replace("/configuration/Schedulers/", "").split("/")
            current_dict = _scheduler_data
            for part in parts[:-1]:
                if part not in current_dict:
                    current_dict[part] = {}
                current_dict = current_dict[part]

            current_dict[parts[-1]] = value
        print_output(message=_scheduler_data, output=output)


@schedulers.command()
@click.option(
    "--scheduler-identifier",
    type=str,
    required=True,
    help="Specify name of a scheduler",
)
@click.option(
    "--provider",
    type=click.Choice(
        [
            "slurm",
            "openpbs",
            "lsf",
        ]
    ),
    required=True,
    help="Specify a provider for the scheduler",
)
@click.option(
    "-e",
    "--endpoint",
    type=str,
    required=True,
    help="Endpoint of the scheduler",
)
@click.option(
    "--binary-folder-paths",
    type=str,
    required=False,
    help="Paths to prepend to the system path. e.g: /custom/path1:/custom:path2",
)
@click.option(
    "--manage-host-provisioning",
    type=click.Choice(["true", "false"]),
    required=True,
    help="Specify whether SOCA will orchestrate capacity for the scheduler",
)
@click.option(
    "--lsf-configuration",
    required=False,
    type=str,
    help="Additional configuration when using LSF",
)
@click.option(
    "--pbs-configuration",
    required=False,
    type=str,
    help="Additional configuration when using PBS",
)
@click.option(
    "--slurm-configuration",
    required=False,
    type=str,
    help="Additional configuration when using Slurm",
)
@click.option(
    "-e",
    "--enabled",
    type=click.Choice(["true", "false"]),
    default="true",
    help="Enable/Disable the scheduler",
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
    scheduler_identifier,
    provider,
    endpoint,
    binary_folder_paths,
    manage_host_provisioning,
    lsf_configuration,
    pbs_configuration,
    slurm_configuration,
    enabled,
    force,
):
    if not is_controller_instance():
        print_output(
            "This command can only be executed from the SOCA controller host",
            error=True,
        )

    _scheduler_configuration = {
        "enabled": True if enabled == "true" else False,
        "provider": provider,
        "endpoint": endpoint,
        "binary_folder_paths": binary_folder_paths if binary_folder_paths else "",
        "soca_managed_nodes_provisioning": (
            True if manage_host_provisioning == "true" else False
        ),
        "identifier": scheduler_identifier,
    }

    _required_scheduler_specific = {
        "lsf": [
            "version",
            "lsf_top",
        ],
        "openpbs": ["install_prefix_path", "pbs_home"],
        "pbspro": ["install_prefix_path", "pbs_home"],
        "slurm": ["install_prefix_path", "install_sysconfig_path"],
    }

    if provider == "lsf":
        if lsf_configuration is None:
            print_output(
                message="You must specify --lsf-configuration when using LSF as a provider.",
                error=True,
            )
        else:
            try:
                _config_as_dict = ast.literal_eval(lsf_configuration)
            except Exception as err:
                print_output(
                    message=f"Unable to convert lsf_configuration to dict. Received error {err}",
                    error=True,
                )
            for _key in _required_scheduler_specific["lsf"]:
                if _key not in _config_as_dict.keys():
                    print_output(
                        message=f"Missing {_key} in lsf_configuration",
                        error=True,
                    )

            _scheduler_configuration["lsf_configuration"] = lsf_configuration

    if provider == "slurm":
        if slurm_configuration is None:
            print_output(
                message="You must specify --slurm-configuration when using Slurm as a provider.",
                error=True,
            )
        else:
            for _key in _required_scheduler_specific["slurm"]:
                try:
                    _config_as_dict = ast.literal_eval(slurm_configuration)
                except Exception as err:
                    print_output(
                        message=f"Unable to convert slurm_configuration to dict. Received error {err}",
                        error=True,
                    )
                if _key not in _config_as_dict.keys():
                    print_output(
                        message=f"Missing {_key} in slurm_configuration",
                        error=True,
                    )

            _scheduler_configuration["slurm_configuration"] = slurm_configuration

    if provider in ["pbspro", "openpbs"]:
        if pbs_configuration is None:
            print_output(
                message="You must specify --pbs-configuration when using PBSPro/OpenPBS as a provider.",
                error=True,
            )
        else:
            try:
                _config_as_dict = ast.literal_eval(pbs_configuration)
            except Exception as err:
                print_output(
                    message=f"Unable to convert pbs_configuration to dict. Received error {err}",
                    error=True,
                )
            for _key in _required_scheduler_specific[provider]:
                if _key not in _config_as_dict.keys():
                    print_output(
                        message=f"Missing {_key} in pbs_configuration",
                        error=True,
                    )

            _scheduler_configuration["pbs_configuration"] = pbs_configuration

    if force is False:
        print_output(_scheduler_configuration, output="json")
        while input(
            "Do you want to create this new scheduler (add --force to skip this confirmation)? (yes/no)"
        ) not in ["yes", "no"]:
            if (
                input(
                    "Do you want to create this new scheduler (add --force to skip this confirmation? (yes/no)"
                )
                == "no"
            ):
                print_output(message="Exiting", error=True)
            else:
                break

    if ctx.invoke(
        config_key_exists, key=f"/configuration/Schedulers/{scheduler_identifier}"
    ):
        print_output(
            message=f"Scheduler {scheduler_identifier} already exists", error=True
        )
    # proceed to scsheduler creation
    ctx.meta["echo"] = True
    ctx.invoke(
        config_set,
        key=f"/configuration/Schedulers/{scheduler_identifier}",
        value=str(_scheduler_configuration),
        called_from="schedulers",
    )


@schedulers.command()
@click.option(
    "-n",
    "--scheduler-identifier",
    type=str,
    required=True,
    help="Specify scheduler identifier",
)
@click.option(
    "-k",
    "--key",
    type=click.Choice(
        [
            "enabled",
            "endpoint",
            "binary_folder_paths",
            "lsf_configuration",
            "pbs_configuration",
            "slurm_configuration",
            "soca_managed_nodes_provisioning",
        ]
    ),
    help="You can only update enabled, endpoint, binary_folder_paths, lsf_configuration, pbs_configuration, slurm_configuration, soca_managed_nodes_provisioning for an existing scheduler",
    required=True,
)
@click.option("-v", "--value", help="New value", required=True)
@click.pass_context
def update(ctx, scheduler_identifier, key, value):
    if not is_controller_instance():
        print_output(
            "This command can only be executed from the SOCA controller host",
            error=True,
        )

    _existing_config = ctx.invoke(
        get, scheduler_identifier=f"{scheduler_identifier}", output="json"
    )
    if isinstance(_existing_config, dict):
        _existing_config[key] = value
        ctx.meta["echo"] = True

        ctx.invoke(
            set,
            scheduler_identifier=_existing_config.get("scheduler_identifier", None),
            provider=_existing_config.get("provider", None),
            endpoint=_existing_config.get("endpoint", None),
            binary_folder_paths=_existing_config.get("binary_folder_paths", ""),
            manage_host_provisioning=_existing_config.get(
                "soca_managed_nodes_provisioning", None
            ),
            lsf_configuration=_existing_config.get("lsf_configuration", None),
            pbs_configuration=_existing_config.get("pbs_configuration", None),
            slurm_configuration=_existing_config.get("slurm_configuration", None),
            enabled=_existing_config.get("enabled", None),
            force=True,
        )
    else:
        print_output(
            message=f"{_existing_config} does not seems to be a valid dictionary",
            error=True,
        )
