# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import click
from commands.config import config
from commands.cache import cache
from utils.logger import SocaLogger
import os


@click.group()
def cli():
    pass


cli.add_command(config)
cli.add_command(cache)

if __name__ == "__main__":
    # Log file is located in the user's home directory
    _log_file_location = f"{os.path.expanduser('~')}/.soca/socactl.log"
    logger = SocaLogger().rotating_file_handler(file_path=_log_file_location)
    cli()
