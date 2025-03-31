# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Optional
import inspect
from utils.error import SocaError


def AWS_API_ERROR(
    service_name: str,
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
    error_doc_url: Optional[str] = None,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"Error while invoking {service_name} API.",
        error_doc_url=error_doc_url,
        helper=helper,
        status_code=status_code,
    )
