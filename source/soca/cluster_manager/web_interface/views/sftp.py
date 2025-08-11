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
from flask import render_template, session, Blueprint, flash
from decorators import login_required, feature_flag
from utils.aws.ssm_parameter_store import SocaConfig

logger = logging.getLogger("soca_logger")
sftp = Blueprint("sftp", __name__, template_folder="templates")


@sftp.route("/sftp", methods=["GET"])
@login_required
@feature_flag(flag_name="SFTP_INSTRUCTIONS", mode="view")
def home():
    _login_nodes_endpoint = (
        SocaConfig(key="/configuration/NLBLoadBalancerDNSName").get_value().message
    )
    return render_template("sftp.html", login_nodes_endpoint=_login_nodes_endpoint)
