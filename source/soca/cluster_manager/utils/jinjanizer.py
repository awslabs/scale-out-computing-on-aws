# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from jinja2 import Environment, FileSystemLoader, select_autoescape
from utils.cast import SocaCastEngine
from utils.error import SocaError
from utils.response import SocaResponse
import logging
import os
import sys
import pathlib
from typing import Optional

logger = logging.getLogger("soca_logger")


class SocaJinja2Generator:
    def __init__(self, get_template: str,
                 variables: dict,
                 template_dirs: list):
        self._get_template = get_template
        self._template_dirs = template_dirs
        self._variables = variables

    def build_jinja2_environment(self):
        _as_list = SocaCastEngine(data=self._template_dirs).cast_as(list)
        if _as_list.success is True:
            self._template_dirs = _as_list.message
        else:
            return SocaError.JINJA_GENERATOR_ERROR(
                helper=f"Unable to cast {self._template_dirs} as list. Verify format")

        logger.info(f"Jinja2 template dir: {self._template_dirs}")
        _jinja2_env = Environment(
            loader=FileSystemLoader(self._template_dirs),
            extensions=['jinja2.ext.do'],
            autoescape=select_autoescape(
                enabled_extensions=("j2", "jinja2"),
                default_for_string=True,
                default=True,
            ),
        )
        return _jinja2_env

    def to_stdout(self, autocast_values: bool = False):
        try:
            _j2_env = self.build_jinja2_environment()
            if autocast_values:
                _autocast = SocaCastEngine(data=self._variables).autocast()
                if _autocast.success:
                    self._variables = _autocast.message
                else:
                    return SocaError.JINJA_GENERATOR_ERROR(helper=_autocast.message)

            _rendered_template = _j2_env.get_template(self._get_template).render(context=self._variables)
            return SocaResponse(success=True, message=_rendered_template)
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.JINJA_GENERATOR_ERROR(helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}")

    def to_file(self, output_file_path: str, autocast_values: bool = False):
        try:
            logger.info("Checking if output_file_path is a valid location")
            _output_file = pathlib.Path(output_file_path)
            if str(_output_file.parent) != ".":
                if not _output_file.parent.exists:
                    return SocaError.GENERIC_ERROR(helper=f"{_output_file.parent} does not seems to be a valid/writeable location")

            _j2_env = self.build_jinja2_environment()

            if autocast_values:
                _autocast = SocaCastEngine(data=self._variables).autocast()
                if _autocast.success:
                    self._variables = _autocast.message
                else:
                    return SocaError.JINJA_GENERATOR_ERROR(helper=_autocast.message)

            _rendered_template = _j2_env.get_template(self._get_template).render(context=self._variables)
            logger.info(f"Writing rendered template to {_output_file}")
            output_file = pathlib.Path(_output_file)
            if _output_file.exists():
                return SocaError.JINJA_GENERATOR_ERROR(helper=f"{output_file} already exists")
            else:
                output_file.write_text(_rendered_template)
                return SocaResponse(success=True, message=f"Rendered template written to {_output_file}")

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.JINJA_GENERATOR_ERROR(helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}")