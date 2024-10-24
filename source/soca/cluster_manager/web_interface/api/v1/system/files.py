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
import ldap
from flask_restful import Resource, reqparse
import logging
from decorators import admin_api, restricted_api, private_api
import re
import os
import sys
import base64
import binascii
from utils.error import SocaError
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


class Files(Resource):
    @admin_api
    def get(self):
        """
        Retrieve content of a file
        ---
        tags:
          - System
        responses:
          200:
            description: Pair of user/token is valid
          203:
            description: Invalid user/token pair
          400:
            description: Malformed client input
        """
        parser = reqparse.RequestParser()
        parser.add_argument("file", type=str, location="args")
        args = parser.parse_args()
        file_to_read = args["file"]

        if file_to_read is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="file").as_flask()
        try:
            with open(file_to_read) as file:
                return SocaResponse(success=True, message=file.read()).as_flask()

        except IsADirectoryError:
            return SocaError.GENERIC_ERROR(helper=f"{file_to_read} is a directory. Specify a file instead").as_flask()

        except FileNotFoundError:
            return SocaError.GENERIC_ERROR(helper=f"{file_to_read} does not exist.").as_flask()

        except UnicodeDecodeError:
            return SocaError.GENERIC_ERROR(helper=f"{file_to_read} is not readable (this is probably not a valid text format)").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}").as_flask()

    @admin_api
    def post(self):
        """
        Create a new file
        ---
        tags:
          - System
        responses:
          200:
            description: Pair of user/token is valid
          203:
            description: Invalid user/token pair
          400:
            description: Malformed client input
        """
        parser = reqparse.RequestParser()
        parser.add_argument("file_name", type=str, location="form")
        parser.add_argument("file_content", type=str, location="form")
        args = parser.parse_args()

        if args["file_name"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="file_name").as_flask()
        if args["file_content"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="file_content").as_flask()

        try:
            file_name = base64.b64decode(args["file_name"]).decode("utf-8")
            file_content = base64.b64decode(args["file_content"]).decode("utf-8")
        except binascii.Error:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to decode payload. Make sure you have encoded the data with b64").as_flask()

        try:
            with open(file_name, "w") as file:
                file.write(file_content)
            return SocaResponse(success=True, message="File Updated.").as_flask()

        except IsADirectoryError:
            return SocaError.GENERIC_ERROR(helper=f"{file_name} is a directory. Specify a file instead").as_flask()

        except FileNotFoundError:
            return SocaError.GENERIC_ERROR(helper=f"{file_name} does not exist.").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(helper=f"Unable to update {file_name}: {err}, {exc_type}, {fname}, {exc_tb.tb_lineno}").as_flask()