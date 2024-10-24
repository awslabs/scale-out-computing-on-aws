# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Optional, Union
import inspect
from utils.error import SocaError


def DB_ERROR(
    query: str,
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
    error_doc_url: Optional[str] = None,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"Database Error: ",
        helper=f"Query {query}. Helper: {helper}",
        error_doc_url=error_doc_url,
        status_code=status_code,
    )
