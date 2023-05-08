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

import logging
from flask import render_template, session, Blueprint
from decorators import login_required
import read_secretmanager

logger = logging.getLogger("application")
sftp = Blueprint("sftp", __name__, template_folder="templates")


@sftp.route("/sftp", methods=["GET"])
@login_required
def home():
    scheduler_ip = read_secretmanager.get_soca_configuration()["SchedulerIP"]
    return render_template("sftp.html", scheduler_ip=scheduler_ip, user=session["user"])
