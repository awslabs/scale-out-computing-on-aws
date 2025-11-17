# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pydantic import Field
from typing import Literal, Optional
from utils.datamodels.hpc.shared.scheduler_node_resources import (
    SocaSchedulerNodeResourceModel,
)
import logging

logger = logging.getLogger("soca_logger")


class SocaHpcNodePBS(SocaSchedulerNodeResourceModel):
    # Fields inherited from SocaSchedulerNodeResourceModel
    # job_id: str
    # scheduler_info: SocaHpcScheduler
    # keep_forever: bool
    # terminate_when_idle: int
    # instance_id: str
    # node_state: SocaSchedulerNodeState
    # compute_node: str
    # last_state_change_timestamp: int

    pbs_mom: str
    
    # Optional Fields, specific to PBS, map output of pbsnodes -a -F json
    pbs_port: Optional[int] = None
    pbs_pbs_version: Optional[str] = None
    pbs_ntype: Optional[str] = None
    pbs_state: Optional[str] = None
    pbs_pcpus: Optional[int] = None
    pbs_jobs: Optional[list] = []
    pbs_resources_available: Optional[dict] = Field(default_factory=dict)
    pbs_resources_assigned: Optional[dict] = Field(default_factory=dict)
    pbs_queue: Optional[str] = None
    pbs_resv_enable: Optional[bool] = None
    pbs_sharing: Optional[str] = None
    pbs_license: Optional[str] = None
    pbs_last_state_change_time: Optional[int] = None
