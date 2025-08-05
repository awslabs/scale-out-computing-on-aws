######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import config
import re
from flask_restful import Resource, reqparse
import logging
from decorators import private_api, feature_flag
from utils.error import SocaError
from utils.subprocess_client import SocaSubprocessClient
from utils.response import SocaResponse
from utils.cast import SocaCastEngine

logger = logging.getLogger("soca_logger")


class Jobs(Resource):
    @private_api
    @feature_flag(flag_name="HPC", mode="api")
    def get(self):
        """
        List PBS Pro jobs in the queue
        ---
        openapi: 3.1.0
        operationId: getJobs
        tags:
          - PBS Pro Scheduler
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
                      description: Job information keyed by job ID
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
            description: PBS scheduler error or JSON parsing failure
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="args")
        args = parser.parse_args()
        user = args["user"]
        logger.debug("Listing all jobs in queue")
        qstat_command = SocaSubprocessClient(
            run_command=f"{config.Config.PBS_QSTAT} -f -Fjson"
        ).run()
        if qstat_command.success:
            get_job_info = qstat_command.message.get("stdout")
            try:
                for match in re.findall('"project":(\d+),', get_job_info, re.MULTILINE):
                    # Clear case where project starts with digits to prevent leading zero errors
                    logger.debug(
                        f'Detected "project":{match}, > Will be replaced to prevent int leading zero error'
                    )
                    get_job_info = get_job_info.replace(
                        f'"project":{match},', f'"project":"{match}",'
                    )

                _get_job_info = SocaCastEngine(data=get_job_info).as_json()
                if _get_job_info.get("success") is False:
                    return SocaError.PBS_JOBS(
                        helper=f"Unable to query get_job_info due to {_get_job_info.get("message")} with job data {get_job_info}"
                    ).as_flask()
                else:
                    job_info = _get_job_info.get("message")

            except Exception as err:
                return SocaError.PBS_JOBS(
                    helper=f"Unable to query get_job_info due to {err} with job data {get_job_info}"
                ).as_flask()

            if user is None:
                return SocaResponse(
                    success=True,
                    message=job_info["Jobs"] if "Jobs" in job_info.keys() else {},
                ).as_flask()

            else:
                job_for_user = {"Jobs": {}}
                if "Jobs" in job_info.keys():
                    job_ids_key = list(job_info["Jobs"].keys())
                    for job_id in job_ids_key:
                        job_owner = job_info["Jobs"][job_id]["Job_Owner"].split("@")[0]
                        if job_owner == user:
                            job_for_user["Jobs"][job_id] = job_info["Jobs"][job_id]
                return SocaResponse(
                    success=True, message=job_for_user["Jobs"]
                ).as_flask()
        else:
            return SocaError.PBS_JOBS(
                helper=f"{qstat_command.get('message').get('helper')}: {qstat_command.get('message').get('stderr')}"
            ).as_flask()
