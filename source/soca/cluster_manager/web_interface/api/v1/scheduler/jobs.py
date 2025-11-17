# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import sys
from flask_restful import Resource, reqparse
import logging
from decorators import private_api, feature_flag
from utils.error import SocaError
from utils.subprocess_client import SocaSubprocessClient
from utils.response import SocaResponse
from utils.cast import SocaCastEngine
from utils.hpc.job_fetcher import SocaHpcJobFetcher
from utils.datamodels.hpc.scheduler import get_schedulers
import json

logger = logging.getLogger("soca_logger")


class Jobs(Resource):
    @private_api
    @feature_flag(flag_name="HPC", mode="api")
    def get(self):
        """
        List LSF/Slurm/PBS jobs for a given queue/users/scheduler. Returns all jobs if no arguments are specified
        ---
        openapi: 3.1.0
        operationId: getJobs
        tags:
          - Scheduler
        parameters:
          - name: X-SOCA-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: admin
          - name: X-SOCA-TOKEN
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA authentication token
            example: abc123token
          - name: user
            in: query
            schema:
              type: string
              pattern: '^[a-zA-Z0-9._-]+$'
              minLength: 1
            required: false
            description: Filter jobs by specific user (returns all jobs if not specified)
            example: john.doe
          - name: queue
            in: query
            schema:
              type: string
              pattern: '^[a-zA-Z0-9._-]+$'
              minLength: 1
            required: false
            description: Filter jobs by specific queue (returns all jobs if not specified)
            example: normal
          - name: scheduler_id
            in: query
            schema:
              type: string
              pattern: '^[a-zA-Z0-9._-]+$'
              minLength: 1
            required: false
            description: Filter jobs by specific scheduler_id (returns all jobs if not specified)
            example: openpbs-soca-default
        responses:
          '200':
            description: Jobs retrieved successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: object
                      description: Jobs list and list of scheduler that returned an error
                      additionalProperties:
                        type: object
                        properties:
                          Job_Name:
                            type: string
                            example: my_job
                          Job_Owner:
                            type: string
                            example: john.doe@cluster
                          job_state:
                            type: string
                            enum: [Q, R, H, S, E, F]
                            example: R
                          queue:
                            type: string
                            example: normal
                      example: {
                        "123.scheduler": {
                          "Job_Name": "my_job",
                          "Job_Owner": "john.doe@cluster",
                          "job_state": "R",
                          "queue": "normal"
                        }
                      }
          '401':
            description: Authentication required
          '500':
            description: SOCA scheduler error or JSON parsing failure
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="args")
        parser.add_argument("queue", type=str, location="args")
        parser.add_argument("scheduler_id", type=str, location="args")
        args = parser.parse_args()
        _user = args.get("user", "")
        _queue = args.get("queue", "")
        _scheduler_id = args.get("scheduler_id", "all")

        logger.debug(f"Listing all jobs for {_user=} / {_queue=} / {_scheduler_id}")

        _all_jobs = []
        _unsuccessful_schedulers = []

        _schedulers_to_query = []
        try:
            if _scheduler_id == "all":
                logger.debug(
                    "No scheduler_id specified, will query all available schedulers"
                )
                _schedulers_to_query = get_schedulers()
            else:
                logger.debug(
                    f"{_scheduler_id=} specified, checking if it's a valid one"
                )
                _schedulers_to_query = get_schedulers(
                    scheduler_identifiers=[_scheduler_id]
                )
                if not _schedulers_to_query:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Scheduler {_scheduler_id=} is not a valid scheduler"
                    ).as_flask()
            
            logger.info(f"Detected Schedulers: {_schedulers_to_query}")
            for _scheduler in _schedulers_to_query:
                logger.debug(f"Querying {_scheduler.identifier} for jobs")
                _get_jobs_response = SocaHpcJobFetcher(
                    scheduler_info=_scheduler
                ).get_all_jobs(
                    queue=None if not _queue else _queue,
                    user=None if not _user else _user,
                )
                if _get_jobs_response.get("success") is True:
                    logger.debug(
                        f"Retrieved jobs: {_get_jobs_response.get('message')=}"
                    )
                    _get_jobs = _get_jobs_response.get("message")
                    if not _get_jobs:
                        logger.info(
                            f"No jobs found for {_queue=} / {_user=} on {_scheduler.identifier}"
                        )
                        continue
                    else:
                        logger.info(
                            f"Retrieved jobs {_queue=} / {_user=} on {_scheduler.identifier}: {_get_jobs=}"
                        )
                        for _job in _get_jobs:
                            _serialize = SocaCastEngine(data=_job).serialize_json()
                            if _serialize.get("success") is True:
                                _all_jobs.append(json.loads(_serialize.message))
                            else:
                                return SocaError.GENERIC_ERROR(
                                    helper=f"Unable to serialize job {_job=} due to {_serialize.get('message')}"
                                )
                else:
                    logger.error(
                        f"Unable to retrieve jobs for {_queue=} / {_user=} on {_scheduler.identifier} due to {_get_jobs_response.get('message')}"
                    )
                    _unsuccessful_schedulers.append(_scheduler.identifier)

            return SocaResponse(
                success=True,
                message={
                    "jobs": _all_jobs,
                    "scheduler_errors": _unsuccessful_schedulers,
                },
            ).as_flask()

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve jobs for {_queue=} / {_user=} / {_scheduler_id=} due to {e} {exc_type} {fname} {exc_tb.tb_lineno}"
            ).as_flask()
