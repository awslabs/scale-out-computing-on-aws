# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import subprocess
import shlex
from utils.error import SocaError
import logging
from typing import Optional, Literal
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


class SocaSubprocessClient:
    def __init__(self, run_command: str):
        self._command = run_command

    def run(
        self,
        capture_output: Optional[bool] = True,
        text: Optional[bool] = True,
        shell: Optional[bool] = False,
        cwd: Optional[str] = None,
        timeout: Optional[int] = None,
        universal_newlines: Optional[bool] = None,  # cannot be set with text = True
        stdin: Optional[Literal[subprocess.PIPE, subprocess.DEVNULL]] = None,
        stdout: Optional[Literal[subprocess.PIPE, subprocess.DEVNULL]] = None,
        stderr: Optional[Literal[subprocess.STDOUT]] = None,
        env: Optional[str] = None,
        non_fatal_rcs: Optional[list[int]] = None,
    ) -> dict:
        """
        Execute the shell command.

        Args:
            capture_output (bool): Whether to capture the output.
            text (bool): Whether to return output as a string vs byte.
            shell (bool): Whether to run the command in the shell. Be careful when you use this.
            cwd (str): The current working directory.
            timeout (int): The timeout in seconds.
            universal_newlines (bool): Whether to use universal newlines.
            stdin (subprocess.PIPE or subprocess.DEVNULL): The input stream.
            stdout (subprocess.PIPE or subprocess.DEVNULL): The output stream.
            stderr (subprocess.STDOUT): The error stream.
            env (str): The environment variables.
            non_fatal_rcs(list of ints): non-zero return codes that are considered non-fatal.

        Returns:
            dict: The result of the command.
        """
        if non_fatal_rcs is None:
            non_fatal_rcs: list = []

        logger.info(
            f"Running Subprocess command {self._command}, capture_output: {capture_output}, text: {text}, shell: {shell}"
        )
        logger.debug(f"Subprocess Command info: {locals()}")
        if text in [True, False] and universal_newlines is not None:
            return SocaError.SUBPROCESS_ERROR(
                command=self._command,
                stdout=None,
                stderr=None,
                returncode=-1,
                helper=f"You cannot set both text and universal_newlines as they are mutually exclusive",
            )

        try:
            if shell:
                logger.warning(
                    f"Running command in shell mode is dangerous. Make sure you sanitized the command ({self._command}) correctly"
                )
                _run_cmd = self._command
            else:
                _run_cmd = shlex.split(self._command)

            try:
                _process = subprocess.run(
                    _run_cmd,
                    capture_output=capture_output,
                    stdin=stdin,
                    stdout=stdout,
                    stderr=stderr,
                    text=text,
                    env=env,
                    shell=shell,
                    cwd=cwd,
                    timeout=timeout,
                    universal_newlines=universal_newlines,
                ) # nosec

                logger.debug(f"Subprocess command {_process}")

                _stdout = _process.stdout
                _stderr = _process.stderr
                _returncode = _process.returncode
                logger.debug(f"Subprocess command result {_process}")

            except subprocess.CalledProcessError as e:
                return SocaError.SUBPROCESS_ERROR(
                    command=self._command,
                    stdout=None,
                    stderr=f"{e.stderr.decode()}",
                    returncode=-1,
                    helper=f"{self._command} failed: ",
                )

        except Exception as e:
            return SocaError.SUBPROCESS_ERROR(
                command=self._command,
                stdout=None,
                stderr=f"{e}",
                returncode=-1,
                helper=f"Unable to run {self._command}",
            )

        if _stderr or _returncode != 0:
            if _returncode in non_fatal_rcs:
                return SocaResponse(
                    success=False,
                    message={
                        "command": self._command,
                        "stdout": _stdout,
                        "stderr": _stderr,
                        "returncode": _returncode,
                        "helper": "Command ran with nonfatal returncode",
                    },
                )
            else:
                return SocaError.SUBPROCESS_ERROR(
                    command=self._command,
                    stdout=None,
                    stderr=_stderr,
                    returncode=_returncode,
                    helper=f"{self._command} has returned an error",
                )
        else:
            return SocaResponse(
                success=True,
                message={
                    "command": self._command,
                    "stdout": _stdout,
                    "stderr": _stderr,
                    "returncode": _returncode,
                    "helper": "Command ran successfully",
                },
            )
