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

import base64
import binascii
import logging
import re

import config
import ldap
from decorators import admin_api, private_api, restricted_api
from flask_restful import Resource, reqparse

logger = logging.getLogger("api")


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
            return {"success": False, "message": "file (str) parameter is required"}, 400
        try:
            with open(file_to_read) as file:
                data = file.read()
            return {"success": True, "message": list(filter(lambda x: x != "", data.split("\n")))}
        except IsADirectoryError:
            return {"success": False, "message": file_to_read + " seems to be a directory. Specify a file instead"}, 500
        except FileNotFoundError:
            return {"success": False, "message": "Files does not seems to exist"}, 500
        except UnicodeDecodeError:
            return {
                "success": False,
                "message": "This file cannot be read (this is probably not a valid text format)",
            }, 500
        except Exception as err:
            return {"success": False, "message": "Unknown error: " + str(err)}, 50

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
        try:
            file_name = base64.b64decode(args["file_name"]).decode("utf-8")
            file_content = base64.b64decode(args["file_content"]).decode("utf-8")
        except binascii.Error:
            return {
                "success": False,
                "message": "Unable to decode payload. Make sure you have encoded the data with b64",
            }, 500

        if file_name is None or file_content is None:
            return {"success": False, "message": "file_content (str) and file_name (str) parameters are required"}, 400

        with open(file_name, "w") as file:
            file.write(file_content)

        return {"success": True, "message": "File Updated."}, 200
