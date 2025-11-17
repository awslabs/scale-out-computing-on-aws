# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Optional
import inspect
from utils.error import SocaError

def SUBPROCESS_ERROR(
    command: str,
    stdout: str,
    stderr: str,
    returncode: str,
    env: Optional[str] = "", # env is passed as base64 hash
    helper: Optional[str] = "",
    status_code: Optional[int] = 500,
    error_doc_url: Optional[str] = None,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message={
            "command": command,
            "stdout": stdout if stdout is not None else "",
            "stderr": stderr if stderr is not None else "",
            "returncode": returncode,
            "env": env,
            "helper": helper,
        },
        error_doc_url=error_doc_url,
        status_code=status_code,
    )
