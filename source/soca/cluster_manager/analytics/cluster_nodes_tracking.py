#!/usr/bin/python
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
import sys
import json
import ast
import datetime
from utils.aws.ssm_parameter_store import SocaConfig
from utils.analytics_client import SocaAnalyticsClient
from utils.subprocess_client import SocaSubprocessClient
from utils.logger import SocaLogger


if __name__ == "__main__":
    _index_name = "soca_nodes"

    _log_file_location = f"/apps/soca/{SocaConfig(key='/configuration/ClusterId').get_value().message}/cluster_manager/analytics/cluster_nodes_tracking.log"
    logger = SocaLogger(name="analytics_cluster_nodes_tracking").rotating_file_handler(file_path=_log_file_location)

    logger.info(f"Tracking active SOCA HPC compute nodes. Log: {_log_file_location}")

    _analytics_client = SocaAnalyticsClient(
        endpoint=SocaConfig(key="/configuration/Analytics/endpoint").get_value().get("message"),
        engine=SocaConfig(key="/configuration/Analytics/engine").get_value().get("message")
    )

    if _analytics_client.is_enabled().success is False:
        logger.info("Analytics is not enabled, exiting")
        sys.exit(1)
    else:
        _analytics_client.initialize()
        logger.info("Analytics client initialized")

    # pbsnodes exists with rc==1 when there is no
    # nodes in the pbsnodes list.
    # This is not a fatal problem for dynamic clusters that are cloud native
    # nodes come and go - and there may be times when there are simply no nodes yet.
    _command = SocaSubprocessClient(
        run_command="/opt/pbs/bin/pbsnodes -a -F json",
    ).run(
        non_fatal_rcs=[1]
    )
    if _command.success is False:
        # _message = ast.literal_eval(_command.message)
        _message = _command.message
        # False Positive
        if "pbsnodes: server has no node list" in _message.get("stderr").lower():
            _msg = "No nodes found, exiting"
            logger.info(_msg)
            sys.exit(0)
        else:
            logger.error(_command.message)
            sys.exit(1)

    else:
        # Compute Nodes detected
        pbsnodes_output = json.loads(_command.message.get("stdout"))
        for hostname, data in pbsnodes_output["nodes"].items():

            try:
                data["timestamp"] = datetime.datetime.fromtimestamp(pbsnodes_output["timestamp"]).isoformat()
            except Exception as err:
                logger.error(f"Unable to process record: {hostname=} / {data=} / {pbsnodes_output=}")

            _index_data = _analytics_client.index(index=_index_name, body=data)
            if _index_data.success:
                logger.info(f"RECORD INDEXED SUCCESSFULLY > {data}")
            else:
                logger.error(f"Error while indexing {data}")