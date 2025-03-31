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
from flask import request
from flask_restful import Resource, reqparse
import logging
import base64
from decorators import private_api
from requests import get
import ast
import shlex
import sys
import errors
import os
import re
import random
import string
import shutil
from utils.error import SocaError
from utils.subprocess_client import SocaSubprocessClient
from utils.http_client import SocaHttpClient
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


class Job(Resource):
    @private_api
    def get(self):
        """
        Return information for a given job
        ---
        tags:
          - Scheduler
        parameters:
          - in: body
            name: body
            schema:
              optional:
                - job_id
              properties:
                job_id:
                   type: string
                   description: ID of the job
        responses:
          200:
            description: List of all jobs
          500:
            description: Backend error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("job_id", type=str, location="args")
        args = parser.parse_args()
        job_id = args["job_id"]
        logger.debug(f"Get job information for job_id: {job_id}")
        if job_id is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="job_id").as_flask()

        qstat_command = SocaSubprocessClient(
            f"{config.Config.PBS_QSTAT} -f {job_id} -Fjson"
        ).run()
        if qstat_command.success:
            get_job_info = qstat_command.message.get("stdout")
            for match in re.findall('"project":(\d+),', get_job_info, re.MULTILINE):
                # Clear case where project starts with digits to prevent leading zero errors
                logger.debug(
                    f'Detected "project":{match}, > Will be replaced to prevent int leading zero error'
                )
                get_job_info = get_job_info.replace(
                    f'"project":{match},', f'"project":"{match}",'
                )
            job_info = ast.literal_eval(get_job_info)
            job_key = list(job_info["Jobs"].keys())[0]
            return SocaResponse(success=True, message=job_info["Jobs"][job_key]).as_flask()
        else:
            return SocaError.PBS_JOB(job_id=job_id, helper="Job may have terminated.", status_code=210).as_flask()

    @private_api
    def post(self):
        """
        Submit a job to the queue
        ---
        tags:
          - Scheduler
        parameters:
          - in: body
            name: body
            schema:
              required:
                - payload
              optional:
                - interpreter
              properties:
                payload:
                  type: string
                  description: Base 64 encoding of a job submission file
                interpreter:
                  type: string
                  description: Interpreter to use qsub or bash
        responses:
          200:
            description: Job submitted correctly
          500:
            description: Backend error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("payload", type=str, location="form")
        parser.add_argument("interpreter", type=str, location="form")
        parser.add_argument("input_file_path", type=str, location="form")
        args = parser.parse_args()
        logger.debug(f"Received job submission request {args}")
        try:
            payload = base64.b64decode(args["payload"]).decode()
        except KeyError:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="payload").as_flask()

        except UnicodeError:
            return SocaError.GENERIC_ERROR(
                helper="payload (str) does not seems to be a valid base64"
            ).as_flask()
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()
        try:
            request_user = request.headers.get("X-SOCA-USER")
            if request_user is None:
                return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

            # Basic Input verification
            check_job_name = re.search(r"#PBS -N (.+)", payload)
            check_job_project = re.search(r"#PBS -P (.+)", payload)

            if check_job_name:
                sanitized_job_name = re.sub(
                    r"\W+", "", check_job_name.group(1)
                )  # remove invalid char,space etc...
                payload = payload.replace(
                    "#PBS -N " + check_job_name.group(1),
                    "#PBS -N " + sanitized_job_name,
                )
            else:
                sanitized_job_name = ""

            if check_job_project:
                sanitized_job_project = re.sub(
                    r"\W+", "", check_job_project.group(1)
                )  # remove invalid char,space etc...
                payload = payload.replace(
                    "#PBS -P " + check_job_project.group(1),
                    "#PBS -P " + sanitized_job_project,
                )

            if args["interpreter"] is None:
                interpreter = config.Config.PBS_QSUB
            else:
                interpreter = args["interpreter"]
            try:
                random_id = "".join(
                    random.choice(string.ascii_letters + string.digits)
                    for _i in range(10)
                )
                job_submit_file = f"job_submit_{random_id}.sh"

                group_ownership = f"{request_user}{config.Config.DIRECTORY_GROUP_NAME_SUFFIX}"
                if args["input_file_path"]:
                    job_output_path = args["input_file_path"]
                else:
                    job_output_folder = (
                        f"{config.Config.USER_HOME}/{request_user}/soca_job_output/"
                    )
                    job_output_path = (
                        f"{job_output_folder}{sanitized_job_name}_{random_id}"
                    )
                    logger.debug(
                        f"Creating job submission directory path {job_output_folder}"
                    )
                    os.makedirs(job_output_path)
                    logger.debug("Applying 0o700 permission to the folder")
                    os.chmod(job_output_folder, 0o700)
                    shutil.chown(
                        job_output_folder, user=request_user, group=group_ownership
                    )
                    shutil.chown(
                        job_output_path, user=request_user, group=group_ownership
                    )
                    os.chmod(job_output_path, 0o700)

                os.chdir(job_output_path)
                with open(job_submit_file, "w") as text_file:
                    text_file.write(payload)
                shutil.chown(
                    job_output_path + "/" + job_submit_file,
                    user=request_user,
                    group=group_ownership,
                )
                os.chmod(job_output_path + "/" + job_submit_file, 0o700)
                submit_job_command = f"{interpreter} {job_output_path}/{job_submit_file}"
                logger.debug(f"About to run su {request_user} -c '{submit_job_command}'")
                launch_job = SocaSubprocessClient(
                    run_command=f"su {request_user} -c '{submit_job_command}'"
                ).run()
                if launch_job.success is True:
                    if interpreter == config.Config.PBS_QSUB:
                        job_id = (
                            launch_job.message.get("stdout")
                            .rstrip()
                            .lstrip()
                            .split(".")[0]
                        )
                        return SocaResponse(success=True, message=str(job_id)).as_flask()
                    else:
                        return SocaResponse(success=True, message=f"Your Linux command has been executed successfully. Output (if any) can be accessed on <a href='/my_files?path={job_output_path}'>{job_output_path}</a>").as_flask()

                else:
                    return SocaError.PBS_JOB(job_id=False, helper=f"Unable to submit job: {launch_job.get('message')}").as_flask()

            except subprocess.CalledProcessError as e:
                return SocaError.SUBPROCESS_ERROR(
                    command=e.cmd,
                    returncode=e.returncode,
                    stderr=e.stderr,
                    helper=f"Unable to submit the job. Please verify your script file (eg: malformed inputs, syntax error, extra space in the PBS variables ...) or refer to the 'stderr' message.",
                ).as_flask()

            except Exception as err:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to submit job because of {err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
                ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to generate and submit job because of {err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

    @private_api
    def delete(self):
        """
        Delete a job from the queue
        ---
        tags:
          - Scheduler
        parameters:
          - in: body
            name: body
            schema:
              required:
                - job_id
              properties:
                job_id:
                  type: string
                  description: ID of the job to remove
        responses:
          200:
            description: Job submitted correctly
          500:
            description: Backend error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("job_id", type=str, location="form")
        args = parser.parse_args()
        job_id = args["job_id"]
        logger.debug(f"Received job deletion request {args}")
        if job_id is None or job_id == "":
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="job_id").as_flask()

        get_job_info = SocaHttpClient(
            endpoint="/api/scheduler/job",
            headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
        ).get(
            params={"job_id": job_id},
        )

        if get_job_info.success is False:
            return SocaError.PBS_JOB(job_id=job_id, helper="Job may have terminated.").as_flask()
        else:
            job_info = get_job_info.message
            job_owner = job_info["Job_Owner"].split("@")[0]
            request_user = request.headers.get("X-SOCA-USER")
            if request_user is None:
                return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

            if request_user != job_owner:
                return SocaError.PBS_REQUEST_NOT_JOB_OWNER(
                    job_id=job_id, requester=request_user, job_owner=job_owner
                ).as_flask()
            try:
                logger.debug("Submitting the job deletion request")
                delete_job = SocaSubprocessClient(
                    run_command=f"{config.Config.PBS_QDEL} {job_id}"
                ).run()
                if delete_job.success:
                    logger.info(f"Job {job_id} deleted successfully")
                    return SocaResponse(success=True, message="Job deleted successfully").as_flask()
                else:
                    return SocaError.PBS_JOB(
                        job_id=job_id,
                        helper=f"Unable to delete because of {delete_job.message}",
                    ).as_flask()

            except Exception as err:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                return SocaError.GENERIC_ERROR(
                    helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
                ).as_flask()
