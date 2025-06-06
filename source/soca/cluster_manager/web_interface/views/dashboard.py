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
import config
from decorators import login_required
from flask import Blueprint, render_template, session
from utils.aws.ssm_parameter_store import SocaConfig

logger = logging.getLogger("soca_logger")
dashboard = Blueprint("dashboard", __name__, template_folder="templates")


@dashboard.route("/dashboard", methods=["GET"])
@login_required
def index():
    loadbalancer_dns_name = (
        SocaConfig(key="/configuration/LoadBalancerDNSName").get_value().get("message")
    )
    _user = session.get("user", "unknown-user")

    kibana_url = "https://" + loadbalancer_dns_name + "/_dashboards/"
    return render_template("dashboard.html", kibana_url=kibana_url, user=_user)
