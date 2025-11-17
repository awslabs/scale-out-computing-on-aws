# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations


from typing import Optional

from utils.datamodels.hpc.shared.job import SocaHpcJob
from pydantic import Field


class SocaHpcJobPBS(SocaHpcJob):
    # Required attributes are inherited from SocaHpcJob

    # Optional PBS job attributes, not needed for SOCA, but added here in case you want to add additional customization
    # This map the attributes from qstat -f -F json
    pbs_job_name: Optional[str] = None  # Job Name
    pbs_job_owner: Optional[str] = None  # Job Owner
    pbs_job_state: Optional[str] = None  # Job State
    pbs_error_path: Optional[str] = None  # Job Error_Path
    pbs_output_path: Optional[str] = None  # Job Output_Path
    pbs_queue: Optional[str] = None  # Job Queue
    pbs_server: Optional[str] = None  # Job Server
    pbs_checkpoint: Optional[str] = None  # Job checkpoint
    pbs_ctime: Optional[str] = None  # Job creation time
    pbs_hold_types: Optional[str] = None  # Job Hold_Types
    pbs_join_path: Optional[str] = None  # Job Join_Path
    pbs_keep_files: Optional[str] = None  # Job Keep_Files
    pbs_mail_points: Optional[str] = None  # Job Mail_Points
    pbs_mtime: Optional[str] = None  # Job modification time
    pbs_priority: Optional[int] = None  # Job Priority
    pbs_qtime: Optional[str] = None  # Job queue time
    pbs_rerunable: Optional[bool] = None  # Job Rerunable
    pbs_resource_list: Optional[dict] = Field(default_factory=dict)  # Job Resource_List
    pbs_schedselect: Optional[str] = None  # Job Schedselect
    pbs_substate: Optional[int] = None  # Job Substate
    pbs_variable_list: Optional[dict] = Field(
        default_factory=dict
    )  # Job Variable_List
    pbs_euser: Optional[str] = None  # Job euser
    pbs_egroup: Optional[str] = None  # Job egroup
    pbs_queue_rank: Optional[int] = None  # Job queue rank
    pbs_queue_type: Optional[str] = None  # Job queue type
    pbs_comment: Optional[str] = None  # Job comment
    pbs_etime: Optional[str] = None  # Job elapsed time
    pbs_submit_arguments: Optional[str] = None  # Job submit arguments
    pbs_executable: Optional[str] = None  # Job executable
    pbs_argument_list: Optional[str] = None  # Job argument list
    pbs_submit_host: Optional[str] = None  # Submission Host
    pbs_project: Optional[str] = None  # Job project
