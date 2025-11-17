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

class SocaHpcNodeLSFLshostsOutput(BaseModel):
    # lshosts -o "HOST_NAME type model cpuf ncpus maxmem maxswp server RESOURCES ndisks maxtmp rexpri nprocs ncores nthreads RUN_WINDOWS" -json
    host_name: str
    resources: Optional[str] = None # This one contains only Boolean and Numerics resources. For String resource (aka: stack_id, compute_node) refer to string_resources:
    type: Optional[str] = None
    model: Optional[str] = None
    cpuf: Optional[str] = None
    ncpus: Optional[str] = None
    maxmem: Optional[str] = None
    maxswp: Optional[str] = None
    server: Optional[str] = None
    ndisks: Optional[str] = None
    maxtmp: Optional[str] = None
    rexpri: Optional[str] = None
    nprocs: Optional[str] = None
    ncores: Optional[str] = None
    nthreads: Optional[str] = None
    run_windows: Optional[str] = None
    # lshosts -sl -> list all string resources as the other lshosts does not include it
    string_resources: Optional[dict] =  Field(default_factory=dict)  

 
class SocaHpcNodeLSFBhostsOutput(BaseModel):
    # bhosts -o "all" -json
    host_name: str
    status: Optional[str] = None
    cpuf: Optional[str] = None
    jl_u: Optional[str] = None
    max: Optional[str] = None
    njobs: Optional[str] = None
    run: Optional[str] = None
    ssusp: Optional[str] = None
    ususp: Optional[str] = None
    rsv: Optional[str] = None
    dispatch_window: Optional[str] = None
    slots: Optional[str] = None
    slots_alloc: Optional[str] = None
    ngpus: Optional[str] = None
    ngpus_alloc: Optional[str] = None
    ngpus_excl_alloc: Optional[str] = None
    ngpus_shared_alloc: Optional[str] = None
    ngpus_shared_jexcl_alloc: Optional[str] = None
    ngpus_excl_avail: Optional[str] = None
    ngpus_shared_avail: Optional[str] = None
    attribute: Optional[str] = None
    comments: Optional[str] = None
    mig_alloc: Optional[str] = None
    total_mem: Optional[str] = None
    reserved_mem: Optional[str] = None
    available_mem: Optional[str] = None


class SocaHpcNodeLSF(SocaSchedulerNodeResourceModel):
    # Fields inherited from SocaSchedulerNodeResourceModel
    # job_id: str
    # scheduler_info: SocaHpcScheduler
    # keep_forever: bool
    # terminate_when_idle: int
    # instance_id: str
    # node_state: SocaSchedulerNodeState
    # compute_node: str
    # last_state_change_timestamp: int

    # Specific to LSF
    lshosts: SocaHpcNodeLSFLshostsOutput
    bhosts: SocaHpcNodeLSFBhostsOutput
    
  
