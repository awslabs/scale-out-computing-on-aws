# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations

from typing import Optional 

from utils.datamodels.hpc.shared.job import SocaHpcJob

class SocaHpcJobLSF(SocaHpcJob):
    # Required attributes are inherited from SocaHpcJob
    
    # Job Description for LSF
    # Contains SOCA resource information "instance_type=m6i.xlarge root_size=50 ..."
    lsf_job_description: str
 
    # Optional LSF job attributes, not needed for SOCA, but added here in case you want to add additional customization
    # This map the attributes of bhost -o "all" -json 

    lsf_jobid: Optional[str] = None  # Job ID
    lsf_state: Optional[str] = None  # Job State
    lsf_user: Optional[str]= None  # Job owner
    lsf_queue: Optional[str] = None  # Job Queue
    lsf_job_name: Optional[str] = None  # Job Name
    lsf_proj_name: Optional[str] = None  # Job Project
    lsf_application: Optional[str] = None  # Job Application
    lsf_service_class: Optional[str] = None  # Job Service Class
    lsf_user_group: Optional[str] = None  # Job User Group
    lsf_job_group: Optional[str] = None  # Job Group
    lsf_job_priority: Optional[str] = None  # Job Priority
    lsf_job_dependency: Optional[str] = None  # Job Dependency
    lsf_aps: Optional[str] = None  # Job APS
    lsf_immediate_orphan_term: Optional[str] = None  # Job Immediate Orphan Term
    lsf_exclusive: Optional[str] = None # Job Exclusive
    lsf_interactive: Optional[str] = None  # Job Interactive
    lsf_pendstate: Optional[str] = None  # Job Pend State
    lsf_pend_reason: Optional[str] = None # Job Pend Reason
    lsf_plimit_remain: Optional[str] = None # Job PLimit Remain
    lsf_eplimit_remain: Optional[str] = None # Job EPLimit Remain
    lsf_charged_saap: Optional[str] = None # Job Charged Saap
    lsf_jobindex: Optional[str] = None # Job Index
    lsf_rsvid: Optional[str] = None # Job RSVID
    lsf_command: Optional[str] = None # Job Command
    lsf_pre_exec_command: Optional[str] = None # Job Pre Exec Command
    lsf_post_exec_command: Optional[str] = None # Job Post Exec Command
    lsf_resize_notification_command: Optional[str] = None # Job Resize Notification Command
    lsf_pids: Optional[str] = None # Job PIDs
    lsf_exit_code: Optional[str] = None # Job Exit Code
    lsf_exit_reason: Optional[str] = None # Job Exit Reason
    lsf_from_host: Optional[str] = None # Job From Host
    lsf_first_host: Optional[str] = None # Job First Host
    lsf_exec_host: Optional[str] = None # Job Exec Host
    lsf_nexec_host: Optional[str] = None # Job NExec Host
    lsf_ask_host: Optional[str] = None # Job Ask Host
    lsf_submit_time: Optional[str] = None # Job Submit Time
    lsf_start_time: Optional[str] = None # Job Start Time
    lsf_estimated_start_time: Optional[str] = None # Job Estimated Start Time
    lsf_specified_start_time: Optional[str] = None # Job Specified Start Time
    lsf_specified_terminate_time: Optional[str] = None # Job Specified Terminate Time
    lsf_time_left: Optional[str] = None # Job Time Left
    lsf_finish_time: Optional[str] = None # Job Finish Time
    lsf_pctcomplete: Optional[str] = None # Job PCTComplete
    lsf_warning_action: Optional[str] = None # Job Warning Action
    lsf_action_warning_time: Optional[str] = None # Job Action Warning Time
    lsf_estimated_sim_start_time: Optional[str] = None # Job Estimated Sim Start Time
    lsf_pend_time: Optional[str] = None # Job Pend Time
    lsf_ependtime: Optional[str] = None # Job EPendTime
    lsf_ipendtime: Optional[str] = None # Job IPEndTime
    lsf_estimated_run_time: Optional[str] = None # Job Estimated Run Time
    lsf_ru_utime: Optional[str] = None # Job RU_UTime
    lsf_ru_stime: Optional[str] = None # Job RU_STime
    lsf_cpu_used: Optional[str] = None # Job CPU Used
    lsf_run_time: Optional[str] = None # Job Run Time
    lsf_idle_factor: Optional[str] = None # Job Idle Factor
    lsf_exception_status: Optional[str] = None # Job Exception Status
    lsf_slots: Optional[str] = None # Job Slots
    lsf_mem: Optional[str] = None # Job Mem
    lsf_max_mem: Optional[str] = None # Job Max Mem
    lsf_avg_mem: Optional[str] = None # Job Avg Mem
    lsf_memlimit: Optional[str] = None # Job MeMLimit
    lsf_swap: Optional[str] = None # Job Swap
    lsf_swaplimit: Optional[str] = None # Job SwapLimit
    lsf_min_req_proc: Optional[str] = None # Job Min Req Proc
    lsf_max_req_proc: Optional[str] = None # Job Max Req Proc
    lsf_effective_resreq: Optional[str] = None # Job Effective ResReq
    lsf_network_req: Optional[str] = None # Job Network Req
    lsf_combined_resreq: Optional[str] = None # Job Combined ResReq
    lsf_file_limit: Optional[str] = None # Job File Limit
    lsf_corelimit: Optional[str] = None # Job CoreLimit
    lsf_stacklimit: Optional[str] = None # Job StackLimit
    lsf_processlimit: Optional[str] = None # Job ProcessLimit
    lsf_runtimelimit: Optional[str] # Job RUNTIMELIMIT
    lsf_effective_plimit: Optional[str] = None # Job Effective PLimit
    lsf_effective_eplimit: Optional[str] = None # Job Effective EPLimit
    lsf_plimit: Optional[str] = None # Job PLimit
    lsf_eplimit: Optional[str] = None # Job EPLimit
    lsf_input_file: Optional[str] = None # Job Input File
    lsf_output_file: Optional[str] = None # Job Output File
    lsf_error_file: Optional[str] = None # Job Error File
    lsf_output_dir: Optional[str] = None # Job Output Dir
    lsf_sub_cwd: Optional[str] = None # Job Sub CWD
    lsf_exec_home: Optional[str] = None # Job Exec Home
    lsf_exec_cwd: Optional[str] = None # Job Exec CWD
    lsf_forward_cluster: Optional[str] = None # Job Forward Cluster
    lsf_forward_time: Optional[str] = None # Job Forward Time
    lsf_source_cluster: Optional[str] = None # Job Source Cluster
    lsf_srcjobid: Optional[str] = None # Job Source Job ID
    lsf_dstjobid: Optional[str] # Job Destination Job ID
    lsf_host_file: Optional[str] = None # Job Host File
    lsf_nalloc_slot: Optional[str] = None # Job NAlloc Slot
    lsf_alloc_slot: Optional[str] = None # Job Alloc Slot
    lsf_hrusage: Optional[list] = []  # Job HRUsage
    lsf_nthreads: Optional[str] = None # Job NThreads
    lsf_licproject: Optional[str] = None # Job LicProject
    lsf_esub: Optional[str] = None # Job ESub
    lsf_image: Optional[str] = None # Job Image
    lsf_ctxuser: Optional[str] = None # Job CtxUser
    lsf_container_name: Optional[str] = None # Job Container Name
    lsf_energy: Optional[str] = None # Job Energy
    lsf_gpfsio: Optional[str] = None # Job GPFSIO
    lsf_killreason: Optional[str] = None # Job Kill Reason
    lsf_nreq_slot: Optional[str] = None # Job NReq Slot
    lsf_suspendreason: Optional[str] = None # Job Suspend Reason
    lsf_resumereason: Optional[str] = None # Job Resume Reason
    lsf_kill_issue_host: Optional[str] = None # Job Kill Issue Host
    lsf_suspend_issue_host: Optional[str] = None # Job Suspend Issue Host
    lsf_resume_issue_host: Optional[str] = None # Job Resume Issue Host
    lsf_j_exclusive: Optional[str] = None # Job J Exclusive
    lsf_gpu_mode: Optional[str] = None # Job GPU Mode
    lsf_gpu_num: Optional[str] = None # Job GPU Num
    lsf_gpu_alloc: Optional[str] = None # Job GPU Alloc
    lsf_longjobid: Optional[str] = None # Job LongJobID
    lsf_k8s: Optional[str] = None # Job K8S
    lsf_plan_start_time: Optional[str] = None # Job Plan Start Time
    lsf_block: Optional[str] = None # Job Block
    lsf_cpu_peak: Optional[str] = None # Job CPU Peak
    lsf_cpu_peak_efficiency: Optional[str] = None # Job CPU Peak Efficiency
    lsf_mem_efficiency: Optional[str] = None # Job Mem Efficiency
    lsf_average_cpu_efficiency: Optional[str] = None # Job Average CPU Efficiency
    lsf_cpu_peak_reached_duration: Optional[str] = None # Job CPU Peak Reached Duration