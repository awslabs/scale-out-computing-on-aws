# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Optional
import inspect
from utils.error import SocaError


def PBS_JOB(
    job_id: str,
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
    error_doc_url: Optional[str] = None,
):
    # raise this error when querying a single job
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"Job {job_id}: ",
        error_doc_url=error_doc_url,
        helper=helper,
        status_code=status_code,
    )


def PBS_JOBS(
    queue_name: Optional[str] = None,
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
    error_doc_url: Optional[str] = None,
):
    # Raise this error when querying more than 1 job
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"Unable to list jobs (queue specific: {queue_name}): ",
        error_doc_url=error_doc_url,
        helper=helper,
        status_code=status_code,
    )


def PBS_QUEUE(
    queue_name: Optional[str] = None,
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
    error_doc_url: Optional[str] = None,
):
    if queue_name:
        return SocaError.return_error(
            error_id=inspect.currentframe().f_code.co_name,
            error_message=f"Queue {queue_name}: ",
            error_doc_url=error_doc_url,
            helper=helper,
            status_code=status_code,
        )
    else:
        return SocaError.return_error(
            error_id=inspect.currentframe().f_code.co_name,
            error_message=f"All Queues: ",
            error_doc_url=error_doc_url,
            helper=helper,
            status_code=status_code,
        )


def PBS_REQUEST_NOT_JOB_OWNER(
    job_id: str,
    requester: str,
    job_owner: str,
    helper: Optional[str] = None,
    status_code: Optional[int] = 500,
    error_doc_url: Optional[str] = None,
):
    return SocaError.return_error(
        error_id=inspect.currentframe().f_code.co_name,
        error_message=f"{requester} is not the owner of job {job_id} (owner: {job_owner}): ",
        error_doc_url=error_doc_url,
        helper=helper,
        status_code=status_code,
    )
