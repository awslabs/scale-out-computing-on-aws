# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from pydantic import BaseModel, field_validator
from enum import Enum
import logging
import re
from typing import Optional, Union, Literal
from utils.datamodels.hpc.scheduler import SocaHpcScheduler

logger = logging.getLogger("soca_logger")


class SocaSchedulerNodeState(str, Enum):
    ACTIVE = "active"  # Node is up and actively running jobs
    IDLE = "idle"  # Node is up but not running any jobs. Node must be in this state to be subject to terminate if --terminate_when_idle is set
    DOWN = "down"  # Node is not available
    OTHER = "other"  # Reserved or unknown states


class SocaSchedulerNodeResourceModel(BaseModel):
    # Job ID associated to the node
    job_id: str

    # Scheduler info associated to the node
    scheduler_info: SocaHpcScheduler

    # Compute Node associated to the node (tbd = no capacity associated yet, otherwise use job id)
    compute_node: Union[Literal["tbd"], str, int]

    # Last time node changed state
    last_state_change_timestamp: int

    # CloudFormation Stack ID associated to the node
    stack_id: str

    # Node state
    node_state: SocaSchedulerNodeState

    # Whether the host is AlwaysOn
    keep_forever: bool

    # Time (in minutes) after a idle node is removed. 0 to disable
    terminate_when_idle: int

    # Instance ID associated to this node
    instance_id: Optional[str] = None

    # Cloudformation Stack associated to the node
    stack_id: Optional[str] = None
    # Scheduler Specific attributes will be added in the relevant class (e.g: SocaHpcNodePBS, SocaHpcNodeLSF ...)

    @field_validator("compute_node")
    @classmethod
    def validate_compute_node(cls, v):
        if v == "tbd" or (
            isinstance(v, str) and re.match(r"^job", v)
        ):  # job<str> for legacy dispatcher, next gen expect either tbd or int
            return v
        if isinstance(v, int):
            return v
        raise ValueError("compute_node must be 'tbd', job<int>, or numeric")
