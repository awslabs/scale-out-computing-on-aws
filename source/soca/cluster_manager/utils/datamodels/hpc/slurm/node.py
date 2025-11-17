# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pydantic import BaseModel, Field
from typing import Literal, Optional
from utils.datamodels.hpc.shared.scheduler_node_resources import (
    SocaSchedulerNodeResourceModel,
)
import logging

logger = logging.getLogger("soca_logger")


class SocaHpcNodeSlurm(SocaSchedulerNodeResourceModel):
    # Fields inherited from SocaSchedulerNodeResourceModel
    # job_id: str
    # scheduler_info: SocaHpcScheduler
    # keep_forever: bool 
    # terminate_when_idle: int
    # instance_id: str
    # node_state: SocaSchedulerNodeState
    # compute_node: str
    # last_state_change_timestamp: int

    # Specific to Slurm
    name: Optional[str] = None
    state: Optional[str] = None
    cpus: Optional[int] = None
    memory: Optional[str] = None
    gres: Optional[str] = None
