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
from models import db, VirtualDesktopSessions
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


class GetVirtualDesktopsSessionState(Resource):
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("session_uuid", type=str, location="args")
        args = parser.parse_args()
        logger.debug(
            f"Received parameter for listing DCV desktop session state: {args}"
        )

        _sessions_uuid = args["session_uuid"].split(",")
        _session_results = {}
        for _session in _sessions_uuid:
            _check_session = VirtualDesktopSessions.query.filter(
                VirtualDesktopSessions.session_uuid == _session,
                VirtualDesktopSessions.is_active == True,
            ).first()
            if _check_session:
                _session_results[_check_session.session_uuid] = (
                    _check_session.session_state
                )

        logger.debug(
            f"Complete User Sessions Check Session State details to return: {_session_results}"
        )
        return SocaResponse(success=True, message=_session_results).as_flask()
