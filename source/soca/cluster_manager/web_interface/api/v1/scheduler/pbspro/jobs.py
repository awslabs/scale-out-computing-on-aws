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
from decorators import private_api
from utils.error import SocaError
from utils.subprocess_client import SocaSubprocessClient
from utils.response import SocaResponse
from utils.cast import SocaCastEngine

logger = logging.getLogger("soca_logger")


class Jobs(Resource):
    @private_api
    def get(self):
        """
        List all jobs in the queue
        ---
        tags:
          - Scheduler
        responses:
          200:
            description: List of all jobs
          500:
            description: Backend error
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
