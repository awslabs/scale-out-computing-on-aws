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
import subprocess

import ast
import re
from flask import request
from flask_restful import Resource, reqparse
import logging
import base64
from decorators import private_api
from requests import get
import json
import shlex

logger = logging.getLogger("api")


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

        try:
            qstat_command = config.Config.PBS_QSTAT + " -f -Fjson"
            try:
                get_job_info = subprocess.check_output(shlex.split(qstat_command))
                try:
                    sanitize_input = get_job_info.decode("utf-8")
                    for match in re.findall(
                        '"project":(\d+),', sanitize_input, re.MULTILINE
                    ):
                        # Clear case where project starts with digits to prevent leading zero errors
                        print(
                            f'Detected "project":{match}, > Will be replaced to prevent int leading zero error'
                        )
                        sanitize_input = sanitize_input.replace(
                            f'"project":{match},', f'"project":"{match}",'
                        )

                    job_info = ast.literal_eval(sanitize_input)
                except Exception as err:
                    logger.error(
                        f"Unable to query get_job_info due to {err} with job data {get_job_info}"
                    )

                    return {
                        "success": False,
                        "message": f"Unable to retrieve this job. Job may have terminated. Error {err}",
                    }, 500

                if user is None:
                    return {
                        "success": True,
                        "message": job_info["Jobs"]
                        if "Jobs" in job_info.keys()
                        else {},
                    }, 200
                else:
                    job_for_user = {"Jobs": {}}
                    if "Jobs" in job_info.keys():
                        job_ids_key = list(job_info["Jobs"].keys())
                        for job_id in job_ids_key:
                            job_owner = job_info["Jobs"][job_id]["Job_Owner"].split(
                                "@"
                            )[0]
                            if job_owner == user:
                                job_for_user["Jobs"][job_id] = job_info["Jobs"][job_id]
                    return {"success": True, "message": job_for_user["Jobs"]}, 200

            except Exception as err:
                logger.error(f"Unable to retrieve Job ID due to {err}")
                return {
                    "success": False,
                    "message": "Unable to retrieve Job ID (job may have terminated and is no longer in the queue)",
                }, 500

        except Exception as err:
            return {"success": False, "message": "Unknown error: " + str(err)}, 500
