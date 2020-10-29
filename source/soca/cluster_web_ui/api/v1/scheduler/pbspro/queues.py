import config
import subprocess
from flask_restful import Resource
import logging
from decorators import private_api
import shlex
logger = logging.getLogger("api")


class Queues(Resource):
    @private_api
    def get(self):
        """
        List all queues
        ---
        tags:
          - Scheduler
        responses:
          200:
            description: List of queues
          500:
            description: Backend error
        """
        # List all queue
        try:
            cmd_1 = subprocess.Popen(shlex.split(config.Config.PBS_QSTAT + " -Q"), stdout=subprocess.PIPE)
            cmd_2 = subprocess.Popen(shlex.split("awk '{print $1}'"), stdin=cmd_1.stdout, stdout=subprocess.PIPE)
            cmd_3 = subprocess.Popen(shlex.split("tail -n +3"), stdin=cmd_2.stdout, stdout=subprocess.PIPE)
            out, err = cmd_3.communicate()
            cmd_1.kill()
            cmd_2.kill()
            cmd_3.kill()
            queue_list = list(filter(lambda x: x != "", out.decode("utf-8").split("\n")))
            return {"success": True, "message": queue_list}, 200
        except Exception as err:
            return {"success": False, "message": "Unknown error: " + str(err)}, 500
