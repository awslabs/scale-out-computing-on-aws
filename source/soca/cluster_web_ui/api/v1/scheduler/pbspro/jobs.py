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
        parser.add_argument('user', type=str, location='args')
        args = parser.parse_args()
        user = args['user']

        try:
            qstat_command = config.Config.PBS_QSTAT + " -f -Fjson"
            try:
                get_job_info = subprocess.check_output(shlex.split(qstat_command))
                try:
                    job_info = json.loads(((get_job_info.decode('utf-8')).rstrip().lstrip()))
                except Exception as err:
                    return {"success": False, "message": "Unable to retrieve this job. Job may have terminated."}, 500

                if user is None:
                    return {"success": True, "message": job_info["Jobs"] if "Jobs" in job_info.keys() else {}}, 200
                else:
                    job_for_user = {"Jobs": {}}
                    if "Jobs" in job_info.keys():
                        job_ids_key = list(job_info["Jobs"].keys())
                        for job_id in job_ids_key:
                            job_owner = job_info["Jobs"][job_id]["Job_Owner"].split("@")[0]
                            if job_owner == user:
                                job_for_user["Jobs"][job_id] = job_info["Jobs"][job_id]
                    return {"success": True, "message": job_for_user["Jobs"]}, 200

            except Exception as err:
                return {"succes": False, "message": "Unable to retrieve Job ID (job may have terminated and is no longer in the queue)"}, 500

        except Exception as err:
            return {"success": False, "message": "Unknown error: " + str(err)}, 500

