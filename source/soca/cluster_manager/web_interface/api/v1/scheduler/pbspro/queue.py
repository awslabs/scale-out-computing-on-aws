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
from flask_restful import Resource, reqparse
import logging
from decorators import private_api, admin_api
from utils.error import SocaError
from utils.subprocess_client import SocaSubprocessClient
from utils.http_client import SocaHttpClient
from utils.response import SocaResponse
import os
import sys

logger = logging.getLogger("soca_logger")


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
        parser.add_argument("type", type=str, location="form")
        parser.add_argument("name", type=str, location="form")
        args = parser.parse_args()
        queue_type = args["type"]
        queue_name = args["name"]
        QUEUE_TYPE = ["ondemand", "alwayson"]
        logger.debug(f"Received queue creation request {args}")
        if queue_name is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="name").as_flask()

        if queue_type not in QUEUE_TYPE:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="type",
                helper="Invalid queue type, must be alwayson or ondemand",
            ).as_flask()

        get_all_queues = SocaHttpClient(
            "/api/scheduler/queues",
            headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
        ).get()
        if get_all_queues.success:
            all_queues = get_all_queues.message
        else:
            return SocaError.PBS_QUEUE(helper="Unable to retrieve all queues").as_flask()

        if queue_name in all_queues:
            return SocaError.PBS_QUEUE(
                queue_name=queue_name, helper="Queue already exist. Delete it first"
            ).as_flask()

        try:
            commands_ondemand = [
                f"create queue {queue_name}",
                f"set queue {queue_name} queue_type = Execution",
                f"set queue {queue_name} default_chunk.compute_node = tbd",
                f"set queue {queue_name} enabled = True",
                f"set queue {queue_name} started = True",
            ]

            commands_alwayson = [
                f"create queue {queue_name}",
                f"set queue {queue_name} queue_type = Execution",
                f"set queue {queue_name} enabled = True",
                f"set queue {queue_name} started = True",
            ]

            if queue_type == "ondemand":
                logger.debug("Creating ondemand queue")
                _run_cmd = commands_ondemand
            else:
                logger.debug("Creating alwayson queue")
                _run_cmd = commands_alwayson

            for command in _run_cmd:
                logger.debug(f"Running cmd {command}")
                _cmd = SocaSubprocessClient(
                    run_command=f"{config.Config.PBS_QMGR} -c '{command}'"
                ).run()
                if not _cmd.success:
                    return SocaError.PBS_QUEUE(
                        helper="Unable to execute command, check SubProcess error"
                    ).as_flask()

            return SocaResponse(success=True, message=f"Queue {queue_name} created").as_flask()
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            )

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
        parser.add_argument("name", type=str, location="form")
        args = parser.parse_args()
        queue_name = args["name"]
        logger.debug(f"Received queue deletion request {args}")
        if queue_name is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="name").as_flask()

        get_all_queues = SocaHttpClient(
            endpoint="/api/scheduler/queues",
            headers={"X-SOCA-TOKEN": config.Config.API_ROOT_KEY},
        ).get()
        if get_all_queues.success:
            all_queues = get_all_queues.message
        else:
            return SocaError.PBS_QUEUE(helper="Unable to retrieve all queues").as_flask()

        if queue_name not in all_queues:
            return SocaError.PBS_QUEUE(
                queue_name=queue_name, helper="Queue does not exist, create it first"
            ).as_flask()

        delete_queue = SocaSubprocessClient(
            run_command=f"{config.Config.PBS_QMGR} -c 'delete queue {queue_name}'"
        ).run()
        if not delete_queue.success:
            return SocaError.PBS_QUEUE(
                helper="Unable to execute command, check SubProcess error"
            ).as_flask()
        else:
            return SocaResponse(success=True, message=f"Queue {queue_name} deleted").as_flask()
