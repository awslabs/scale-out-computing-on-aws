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

from flask_restful import Resource, reqparse
import logging
from decorators import private_api, feature_flag
from flask import request
import shlex

import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.response import SocaResponse
from utils.subprocess_client import SocaSubprocessClient


logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class RunRemoteCommand(Resource):
    @feature_flag(flag_name="RUN_REMOTE_COMMAND", mode="api")
    @private_api
    def post(self):
        """
        Execute remote command as user on the SOCA controller
        Disabled by default, manage API permissions/access via cluster_manager/web_interface/feature_flags
        ---
        openapi: 3.1.0
        operationId: runRemoteCommand
        tags:
          - User
        summary: Execute a command as the specified user
        description: Executes a command on the system as the specified user (private API)
        parameters:
          - name: X-SOCA-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username to execute command as
            example: user.name
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - command
                properties:
                  command:
                    type: string
                    minLength: 1
                    description: Command to execute
                    example: "ls -la /home"
        responses:
          '200':
            description: Command executed successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: string
                      description: Command output
                      example: "total 4\ndrwxr-xr-x 3 root root 4096 Jan 1 12:00 user.name"
          '400':
            description: Missing required parameter or header
          '500':
            description: Command execution failed
        """

        parser = reqparse.RequestParser()
        parser.add_argument("command", type=str, default="", location="data")
        args = parser.parse_args()
        _command = args.get("command", "")
        _user = request.headers.get("X-SOCA-USER", "")

        logger.debug(f"Received RunRemoteCommand {_command=} as {_user=}")

        if not _command:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="command").as_flask()

        if not _user:
            return SocaError.CLIENT_MISSING_HEADER(header="X-SOCA-USER").as_flask()

        _run_as_command = f"{shlex.quote(_command)}"

        # Note: Highly recommended to keep shell=False
        _run_command = SocaSubprocessClient(
            run_command=_run_as_command, run_as=_user
        ).run(shell=False)
        if _run_command.get("success"):
            logger.debug(f"Command {_command} executed successfully")
            return SocaResponse(
                success=True, message=_run_command.get("message")
            ).as_flask()
        else:
            logger.error(
                f"Failed to execute command {_run_as_command} due to {_run_command}"
            )
            return SocaError.GENERIC_ERROR(helper=_run_command.get("message"))
