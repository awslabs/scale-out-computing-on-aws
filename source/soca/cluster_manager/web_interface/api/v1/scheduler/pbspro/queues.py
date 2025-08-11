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
from flask_restful import Resource
import logging
from decorators import private_api, feature_flag
from utils.error import SocaError
from utils.subprocess_client import SocaSubprocessClient
from utils.response import SocaResponse
import subprocess

logger = logging.getLogger("soca_logger")


class Queues(Resource):
    @private_api
    @feature_flag(flag_name="HPC", mode="api")
    def get(self):
        """
        List all PBS Pro queues
        ---
        openapi: 3.1.0
        operationId: getQueues
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
        responses:
          '200':
            description: List of queues retrieved successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: array
                      items:
                        type: string
                        pattern: '^[a-zA-Z0-9_-]+$'
                      example: ["normal", "high", "low", "gpu"]
          '401':
            description: Authentication required
          '500':
            description: PBS scheduler error or backend failure
        """
        logger.debug("Get all queues")
        _get_all_queues = SocaSubprocessClient(
            run_command=f"{config.Config.PBS_QSTAT} -Q | awk 'NR>2 {{print $1}}'"
        ).run(stdout=subprocess.PIPE, shell=True, capture_output=False)
        if _get_all_queues.success:
            queue_list = list(
                filter(
                    lambda x: x != "",
                    _get_all_queues.message.get("stdout").split("\n"),
                )
            )
            return SocaResponse(success=True, message=queue_list).as_flask()
        else:
            return SocaError.PBS_QUEUE(
                helper="Unable to retrieve all queues name. Refer to subprocess logs"
            ).as_flask()
