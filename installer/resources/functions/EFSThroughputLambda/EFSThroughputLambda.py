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

import json
import boto3
import datetime
import os
import logging

cw_client = boto3.client("cloudwatch")
efs_client = boto3.client("efs")

logging.getLogger().setLevel(logging.INFO)


def lambda_handler(event, context):
    logging.info(f"Received SNS event: {json.dumps(event)}")
    message = json.loads(event["Records"][0]["Sns"]["Message"])
    _fs_id = message["Trigger"]["Dimensions"][0]["value"]
    logging.info(f"FilesystemID: {_fs_id}")
    logging.info(f"Thresholds: BurstCreditLowThreshold={os.environ['EFSBurstCreditLowThreshold']} BurstCreditHighThreshold={os.environ['EFSBurstCreditHighThreshold']}")

    now = datetime.datetime.now()
    start_time = now - datetime.timedelta(seconds=300)
    end_time = min(now, start_time + datetime.timedelta(seconds=300))

    response = cw_client.get_metric_statistics(
        Namespace="AWS/EFS",
        MetricName="BurstCreditBalance",
        Dimensions=[{"Name": "FileSystemId", "Value": _fs_id}],
        Period=60,
        StartTime=start_time,
        EndTime=end_time,
        Statistics=["Average"],
    )

    efsAverageBurstCreditBalance = response["Datapoints"][0]["Average"]
    logging.info(f"EFS AverageBurstCreditBalance: {efsAverageBurstCreditBalance}")

    response = efs_client.describe_file_systems(FileSystemId=_fs_id)
    logging.info(f"EFS Lookup Response: {response}")

    ThroughputMode = response["FileSystems"][0]["ThroughputMode"]
    logging.info(f"EFS ThroughputMode: {ThroughputMode}")

    if efsAverageBurstCreditBalance < int(os.environ["EFSBurstCreditLowThreshold"]):
        # CreditBalance is less than LowThreshold --> Change to ProvisionedThroughput
        if ThroughputMode == "bursting":
            # Update filesystem to Provisioned
            logging.info(f"Updating EFS: {_fs_id} to Provisioned ThroughputMode with 50 MiB/sec")
            response = efs_client.update_file_system(
                FileSystemId=_fs_id,
                ThroughputMode="provisioned",
                ProvisionedThroughputInMibps=50.0,
            )
            logging.info(f"EFS Update Response: {response}")


    elif efsAverageBurstCreditBalance > int(os.environ["EFSBurstCreditHighThreshold"]):
        # CreditBalance is greater than HighThreshold --> Change to Bursting
        if ThroughputMode == "provisioned":
            # Update filesystem to Bursting
            logging.info(f"Updating EFS: {_fs_id} to Bursting ThroughputMode")

            response = efs_client.update_file_system(
                FileSystemId=_fs_id, ThroughputMode="bursting"
            )
            logging.info(f"Response: {response}")

