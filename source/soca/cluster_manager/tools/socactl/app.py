# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import click
from commands.config import config
from commands.cache import cache
from commands.filesystems import filesystems
from commands.ad import ad
from commands.schedulers import schedulers

from utils.logger import SocaLogger
import os

@click.group()
@click.pass_context
def cli(ctx):
    # Log file is located in the user's home directory
    _log_file_location = f"{os.path.expanduser('~')}/.soca/socactl.log"
    logger = SocaLogger().rotating_file_handler(file_path=_log_file_location)
    ctx.obj = {}
    ctx.obj['logger'] = logger

cli.add_command(config)
cli.add_command(cache)
cli.add_command(filesystems)
cli.add_command(ad)
cli.add_command(schedulers)

if __name__ == "__main__":
    cli(obj={})