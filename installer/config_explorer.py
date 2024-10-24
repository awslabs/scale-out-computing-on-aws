#!/usr/bin/env python

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import yaml
from typing import Any
import argparse
import sys
import json
import click
from pathlib import Path


def load_yaml_file(file_path: str) -> dict:
    try:
        with open(file_path, 'r') as _file:
            _data = yaml.safe_load(_file)
    except FileNotFoundError:
        print(f"Unable to locate your config file, verify path")
        sys.exit(1)
    except Exception as _e:
        print(f"Unable to parse your config file, due to {_e} verify syntax.")
        sys.exit(1)

    return _data


def save_yaml_file(data, file_path):
    """
    Save dictionary data to a YAML file.
    """
    with open(file_path, 'w') as file:
        yaml.dump(data, file)


def get_config_key(data: dict, key_name: str) -> Any:
    _result = data
    for _key in key_name.split("."):
        _result = _result.get(_key)
        if _result is None:
            break
    return _result


def set_variable(data, variable_path, value):
    """
    Set a variable in YAML data based on the variable path.
    """
    keys = variable_path.split('.')
    current_dict = data
    for key in keys[:-1]:
        if key not in current_dict:
            current_dict[key] = {}
        current_dict = current_dict[key]
    current_dict[keys[-1]] = value


@click.group()
def cli():
    pass


@cli.group()
def config():
    pass


@config.command()
@click.option('-k', '--key', multiple=True, required=True, help='Specify at least one key (e.g: --key Config.directoryservice). Support multiple --key as needed')
@click.option('-c', '--config', default=f"{Path(__file__).resolve().parent}/default_config.yml", help='Path of the SOCA configuration file')
@click.option('-f', '--format', default="text", type=click.Choice(["text", "json", "yaml"]), help='Output result as: text, json, yaml')
def get(**kwargs):
    _config_path = kwargs.get("config")
    _format = kwargs.get("format")
    _keys = kwargs.get("key")
    _soca_configuration = load_yaml_file(_config_path)
    for _key in _keys:
        _value = get_config_key(_soca_configuration, _key)
        if _format == "json":
            click.echo(json.dumps({_key: _value}))
        elif _format == "text":
            click.echo(f"Value of {_key}: {_value}")
        elif _format == "yaml":
            click.echo(yaml.dump({_key: _value}))


@config.command()
@click.option('--new_value', help='New value for configuration')
def update(new_value):
    click.echo("Editing configuration with new value: {}".format(new_value))


if __name__ == "__main__":
    cli()

'''
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    config_group = parser.add_argument_group("Configuration Actions")

    config_action_parser = config_group.add_mutually_exclusive_group(required=True)
    config_action_parser.add_argument('--get', action='store_true', help='Get configuration')
    config_action_parser.add_argument('--edit', action='store_true', help='Edit configuration')

    # Arguments specific to getting configuration
    get_config_group = parser.add_argument_group("Get Configuration Options")
    get_config_group.add_argument('-k', '--key', action="append",
                                  help="Specify at least one key (e.g: --key Config.directoryservice). Support multiple --key as needed", required=True)
    get_config_group.add_argument('-c', '--config', dest="config", default="default_config.yml")
    get_config_group.add_argument('-f', '--format', dest="format", choices=["json", "text"], default="json")

    # Arguments specific to editing configuration
    edit_config_group = parser.add_argument_group("Edit Configuration Options")
    edit_config_group.add_argument('--new_value', help='New value for configuration')



    args = parser.parse_args()

    soca_configuration = load_yaml_file(args.config)




    keys = args.key
    for key in keys:
        value = get_config_key(soca_configuration, key)
        if args.format == "json":
            print(json.dumps({key: value}))
        else:
            print(f"Value of {key}: {value}")

    # Example of editing variable
    #new_value = "new_value"
    #set_variable(yaml_data, variable_path, new_value)
    #print(f"Updated value of {variable_path}: {get_variable(yaml_data, variable_path)}")

    ## Save modified YAML data back to file
    #save_yaml_file(yaml_data, file_path)
'''