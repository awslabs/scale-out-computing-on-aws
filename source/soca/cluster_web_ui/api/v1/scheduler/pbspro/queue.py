import config
import subprocess
from flask_restful import Resource, reqparse
from requests import get
import logging
from decorators import private_api, admin_api
import shlex
logger = logging.getLogger("api")


class Queue(Resource):
    @admin_api
    def post(self):
        """
        Create a new queue
        ---
        tags:
          - Scheduler
        responses:
          200:
            description: List of queues
          500:
            description: Backend error
        """
        parser = reqparse.RequestParser()
        parser.add_argument('type', type=str, location='form')
        parser.add_argument('name', type=str, location='form')
        args = parser.parse_args()
        queue_type = args['type']
        queue_name = args['name']
        QUEUE_TYPE = ["ondemand", "alwayson"]
        if queue_name is None:
            return {"success": False, "message": "name (str) is required parameter"}, 400

        if queue_type not in QUEUE_TYPE:
            return {"success": False, "message": "Invalid queue type, must be alwayson or ondemand"}, 400

        get_all_queues = get(config.Config.FLASK_ENDPOINT + "/api/scheduler/queues",
                             headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                             verify=False)
        if get_all_queues.status_code == 200:
            all_queues = get_all_queues.json()["message"]
        else:
            return {"success": False, "message": "Unable to retrieve all queues"}

        if queue_name in all_queues:
            return {"success": False, "message": "Queue already exist. Delete it first"}

        try:
            commands_ondemand = ["create queue " + queue_name,
                                 "set queue " + queue_name + " queue_type = Execution",
                                 "set queue " + queue_name + " default_chunk.compute_node = tbd",
                                 "set queue " + queue_name + " enabled = True",
                                 "set queue " + queue_name + " started = True"]

            commands_alwayson = ["create queue " + queue_name,
                                 "set queue " + queue_name + " queue_type = Execution",
                                 "set queue " + queue_name + " enabled = True",
                                 "set queue " + queue_name + " started = True"]

            if queue_type == "ondemand":
                for command in commands_ondemand:
                    try:
                        subprocess.Popen(shlex.split(config.Config.PBS_QMGR + ' -c "' + command + '"'))
                    except Exception as err:
                        return {"success": False, "message": "Error with " + command + " Trace: " + str(err)}, 500
            else:
                for command in commands_alwayson:
                    try:
                        subprocess.Popen(shlex.split(config.Config.PBS_QMGR + ' -c "' + command + '"'))
                    except Exception as err:
                        return {"success": False, "message": "Error with " + command + " Trace: " + str(err)}, 500

            return {"success": True, "message": "Queue created"}, 200
        except Exception as err:
            return {"success": False, "message": "Unknown error: " + str(err)}, 500

    @admin_api
    def delete(self):
        """
        Delete a queue
        ---
        tags:
          - Scheduler
        responses:
          200:
            description: List of queue
          500:
            description: Backend error
        """
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, location='form')
        args = parser.parse_args()
        queue_name = args['name']
        if queue_name is None:
            return {"success": False, "message": "name (str) is required parameter"}, 400

        get_all_queues = get(config.Config.FLASK_ENDPOINT + "/api/scheduler/queues",
                             headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
                             verify=False)
        if get_all_queues.status_code == 200:
            all_queues = get_all_queues.json()["message"]
        else:
            return {"success": False, "message": "Unable to retrieve all queues"}

        if queue_name not in all_queues:
            return {"success": False, "message": "Queue does not exist. Create it first"}

        try:
            delete_queue = subprocess.Popen(shlex.split(config.Config.PBS_QMGR + ' -c "delete queue ' + queue_name + '"'))
            return {"success": True, "message": "Queue deleted"}, 200
        except Exception as err:
            return {"success": False, "message": "Unable to delete queue: " + str(err) + ". Trace: " + str(delete_queue)}, 200
