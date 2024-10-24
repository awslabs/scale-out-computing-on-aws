# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import click
import sys
from utils.logger import SocaLogger
from utils.aws.ssm_parameter_store import SocaConfig
from utils.jinjanizer import SocaJinja2Generator
import os
import re
@click.command()
@click.option('--get-template', "get_template", required=True, help='Path to your Jinja2 Template file based on the value of --template-dirs')
@click.option('--template-dirs', "template_dirs", required=True, multiple=True, help='Path to include any additional jinja2 files')
@click.option('--add-value', "add_value", multiple=True, help='Add Additional keys/value to the list of variables e.g: --add-value "KEY=/job/NodeType VALUE=login_node TYPE=str"')
@click.option('--output-file',  "output_file", help='Location of the output file')
@click.option('--ssm-key',  "ssm_key", required=True, help='Input variable')
def main(get_template: str, add_value: str, template_dirs: tuple, output_file: str, ssm_key: str):
    '''
    ex: /apps/soca/soca-dev/python/latest/bin/python3 j2generator/app.py \
       --get-template "controller/setup.j2" \
       --output-file "/root/rendered_template.sh \
       --ssm-key "/Configuration/" \
       --template-dirs = "/apps/soca/soca-test/cluster_node_bootstrap/"
       This command will fetch the entire SOCA Configuration. Retrieve value via {{ context.get("<SSM_KEY>") }}

       Note: if --output-file is not specified, the rendered template will be printed to stdout
    '''

    logger.debug("Fetching variable from Parameter Store")
    # note: cache_admin is false ensure this tool can be run anywhere. (plus we don't really need to be admin here)
    _get_variables = SocaConfig(key=ssm_key, cache_admin=False).get_value(cache_result=False)
    if _get_variables.success:
        _variables = _get_variables.message
        logger.debug(_variables)
    else:
        click.echo(_get_variables.message)
        sys.exit(1)

    if add_value is not None:
        logger.debug("Merging additional values")
        for entry in list(add_value):
            pattern = r"KEY=(\S+)\s+VALUE=(\S+)\s+TYPE=(\S+)"

            match = re.search(pattern, entry)
            if match:
                _key_name = match.group(1)
                _key_value = match.group(2)
                _value_type = match.group(3).lower()
            else:
                click.echo(f"Invalid --add-value entry: {entry}. Expected: {pattern}")
                sys.exit(1)

            if _key_name in _variables.keys():
                click.echo(f"Error: {_key_name} seems to already exist in the variable list")
                sys.exit(1)
            else:
                _allowed_types = {
                    "str": str,
                    "int": int,
                    "float": float,
                    "bool": bool,
                    "list": list,
                    "tuple": tuple,
                    "dict": dict
                }
                _type_func = _allowed_types.get(_value_type, False)
                if _type_func is False:
                    click.echo(f"Error: Invalid type {_value_type}. Supported types: {', '.join(_allowed_types.keys())}")
                    sys.exit(1)
                else:
                    _variables[_key_name] = _type_func(_key_value)

    if template_dirs is not None:
        logger.debug("Converting back tuple(s) to list")
        template_dirs = list(template_dirs)

    if output_file:
        logger.debug(f"Rendering j2 template {get_template} to {output_file}")
        _req = SocaJinja2Generator(
            get_template=get_template,
            template_dirs=template_dirs,
            variables=_variables).to_file(output_file_path=output_file, autocast_values=True)

    else:
        logger.debug(f"Rendering j2 template {get_template} to stdout")
        _req = SocaJinja2Generator(
            get_template=get_template,
            template_dirs=template_dirs,
            variables=_variables).to_stdout(autocast_values=True)

    click.echo(_req.message)


if __name__ == '__main__':
    _log_file_location = f"{os.path.expanduser('~')}/.soca/j2generator.log"
    logger = SocaLogger().rotating_file_handler(file_path=_log_file_location)
    main()