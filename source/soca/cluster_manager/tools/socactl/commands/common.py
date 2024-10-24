# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import yaml
import click
import sys
import os


def is_controller_instance() -> bool:
    if os.environ.get("SOCA_NODE_TYPE", None) == "controller":
        return True
    else:
        return False


def print_output(
    message: [str, dict], output: str = "text", error: bool = False
) -> [str, json, yaml]:
    if output == "json":
        click.echo(json.dumps(message, indent=4, default=str))
    elif output == "text":
        click.echo(message)
    elif output == "yaml":
        click.echo(yaml.dump(message))
    else:
        click.echo(
            "Unrecognized output format. Supported values are text, json or yaml"
        )
        sys.exit(1)

    if error:
        sys.exit(1)
