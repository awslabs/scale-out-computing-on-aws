import config
import subprocess
from flask import request
from flask_restful import Resource, reqparse
import logging
import base64
from decorators import private_api
from requests import get
import json
import shlex
import sys
import errors
import os
import uuid
import re
import random
import string
import shutil

logger = logging.getLogger("api")


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
        parser.add_argument('job_id', type=str, location='args')
        args = parser.parse_args()
        job_id = args['job_id']
        if job_id is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "job_id (str) parameter is required")

        try:
            qstat_command = config.Config.PBS_QSTAT + " -f " + job_id + " -Fjson"
            try:
                get_job_info = subprocess.check_output(shlex.split(qstat_command))
                try:
                    job_info = json.loads(((get_job_info.decode('utf-8')).rstrip().lstrip()))
                except Exception as err:
                    return {"success": False, "message": "Unable to retrieve this job. Job may have terminated. Error: " + str(job_info)}, 210

                job_key = list(job_info["Jobs"].keys())[0]
                return {"success": True, "message": job_info["Jobs"][job_key]}, 200

            except Exception as err:
                return {"succes": False, "message": "Unable to retrieve Job ID (job may have terminated and is no longer in the queue)"}, 210

        except Exception as err:
            return {"success": False, "message": "Unknown error: " + str(err)}, 500

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
        parser.add_argument('payload', type=str, location='form')
        parser.add_argument('interpreter', type=str, location='form')
        parser.add_argument('input_file_path', type=str, location='form')
        args = parser.parse_args()
        try:
            payload = base64.b64decode(args['payload']).decode()
        except KeyError:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "payload (base64) parameter is required")
        except UnicodeError:
            return errors.all_errors("UNICODE_ERROR", "payload (str) does not seems to be a valid base64")
        except Exception as err:
            return errors.all_errors(type(err).__name__, err)

        try:
            request_user = request.headers.get("X-SOCA-USER")
            if request_user is None:
                return errors.all_errors("X-SOCA-USER_MISSING")

            # Basic Input verification
            check_job_name = re.search(r'#PBS -N (.+)', payload)
            check_job_project = re.search(r'#PBS -P (.+)', payload)

            if check_job_name:
                sanitized_job_name = re.sub(r'\W+', '', check_job_name.group(1))  # remove invalid char,space etc...
                payload = payload.replace("#PBS -N " + check_job_name.group(1), "#PBS -N " + sanitized_job_name)
            else:
                sanitized_job_name = ""

            if check_job_project:
                sanitized_job_project = re.sub(r'\W+', '', check_job_project.group(1))  # remove invalid char,space etc...
                payload = payload.replace("#PBS -P " + check_job_project.group(1), "#PBS -P " + sanitized_job_project)

            if args['interpreter'] is None:
                interpreter = config.Config.PBS_QSUB
            else:
                interpreter = args['interpreter']
            try:
                random_id = ''.join(random.choice(string.ascii_letters + string.digits) for i in range(10))
                job_submit_file = "job_submit_" + str(random_id) + ".sh"

                if args['input_file_path']:
                    job_output_path = args['input_file_path']
                else:
                    # create new job directory if needed
                    job_output_folder = config.Config.USER_HOME + "/" + request_user + "/soca_job_output/"
                    job_output_path = job_output_folder + sanitized_job_name + "_" + str(random_id)
                    os.makedirs(job_output_path)
                    os.chmod(job_output_folder, 0o700)
                    shutil.chown(job_output_folder, user=request_user, group=request_user)
                    shutil.chown(job_output_path, user=request_user, group=request_user)
                    os.chmod(job_output_path, 0o700)

                os.chdir(job_output_path)
                with open(job_submit_file, "w") as text_file:
                    text_file.write(payload)
                shutil.chown(job_output_path + "/" + job_submit_file, user=request_user, group=request_user)
                os.chmod(job_output_path + "/"+job_submit_file, 0o700)
                submit_job_command = interpreter + " " + job_submit_file

                launch_job = subprocess.check_output(['su', request_user, '-c', submit_job_command], stderr=subprocess.PIPE)
                if interpreter == config.Config.PBS_QSUB:
                    job_id = ((launch_job.decode('utf-8')).rstrip().lstrip()).split('.')[0]
                    return {"success": True, "message": str(job_id)}, 200
                else:
                    return {"success": True, "message": "Your Linux command has been executed successfully. Output (if any) can be accessed on <a href='/my_files?path="+job_output_path+"'>"+job_output_path+"</a>"}, 200

            except subprocess.CalledProcessError as e:
                return {"succes": False,
                        "message": {
                            "error": "Unable to submit the job. Please verify your script file (eg: malformed inputs, syntax error, extra space in the PBS variables ...) or refer to the 'stderr' message.",
                            "stderr": '{}'.format(e.stderr.decode(sys.getfilesystemencoding())),
                            "stdout": '{}'.format(e.output.decode(sys.getfilesystemencoding())),
                            "job_script": str(payload)}
                        }, 500

            except Exception as err:
                return {"succes": False, "message": {"error": "Unable to run Qsub command.",
                                                     "trace": str(err),
                                                     "job_script": str(payload)}}, 500


        except Exception as err:
            return errors.all_errors(type(err).__name__, err)

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
        parser.add_argument('job_id', type=str, location='args')
        args = parser.parse_args()
        job_id = args['job_id']
        if job_id is None:
            return errors.all_errors("CLIENT_MISSING_PARAMETER", "job_id (str) parameter is required")

        get_job_info = get(config.Config.FLASK_ENDPOINT + "/api/scheduler/job",
                           headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                           params={"job_id": job_id},
                           verify=False)

        if get_job_info.status_code != 200:
            return {"success": False, "message": "Unable to retrieve this job. Job may have terminated"}, 500
        else:
            job_info = get_job_info.json()["message"]
            job_owner = job_info["Job_Owner"].split("@")[0]
            request_user = request.headers.get("X-SOCA-USER")
            if request_user is None:
                return errors.all_errors("X-SOCA-USER_MISSING")
            if request_user != job_owner:
                return errors.all_errors("CLIENT_NOT_OWNER")
            try:
                qdel_command = config.Config.PBS_QDEL + " " + job_id
                try:
                    delete_job = subprocess.check_output(shlex.split(qdel_command))
                    return {"success": True, "message": "Job deleted"}
                except Exception as err:
                    return {"succes": False, "message": "Unable to execute qsub command: " + str(err)}, 500

            except Exception as err:
                return {"success": False, "message": "Unknown error: " + str(err)}, 500
