import json
import boto3
import datetime
import os


def lambda_handler(event, context):
    cw_client = boto3.client("cloudwatch")
    efs_client = boto3.client("efs")
    # print("Received event: " + json.dumps(event, indent=2))
    message = json.loads(event["Records"][0]["Sns"]["Message"])
    FileSystemId = message["Trigger"]["Dimensions"][0]["value"]
    print("FilesystemID: " + FileSystemId)

    now = datetime.datetime.now()
    start_time = now - datetime.timedelta(seconds=300)
    end_time = min(now, start_time + datetime.timedelta(seconds=300))
    response = cw_client.get_metric_statistics(
        Namespace="AWS/EFS",
        MetricName="BurstCreditBalance",
        Dimensions=[{"Name": "FileSystemId", "Value": FileSystemId}],
        Period=60,
        StartTime=start_time,
        EndTime=end_time,
        Statistics=["Average"],
    )
    efsAverageBurstCreditBalance = response["Datapoints"][0]["Average"]
    print("EFS AverageBurstCreditBalance: " + str(efsAverageBurstCreditBalance))

    response = efs_client.describe_file_systems(FileSystemId=FileSystemId)
    ThroughputMode = response["FileSystems"][0]["ThroughputMode"]
    print("EFS ThroughputMode: " + str(ThroughputMode))

    if efsAverageBurstCreditBalance < int(os.environ["EFSBurstCreditLowThreshold"]):
        # CreditBalance is less than LowThreshold --> Change to ProvisionedThroughput
        if ThroughputMode == "bursting":
            # Update filesystem to Provisioned
            response = efs_client.update_file_system(
                FileSystemId=FileSystemId,
                ThroughputMode="provisioned",
                ProvisionedThroughputInMibps=5.0,
            )
            print(
                "Updating EFS: "
                + FileSystemId
                + " to Provisioned ThroughputMode with 5 MiB/sec"
            )
    elif efsAverageBurstCreditBalance > int(os.environ["EFSBurstCreditHighThreshold"]):
        # CreditBalance is greater than HighThreshold --> Change to Bursting
        if ThroughputMode == "provisioned":
            # Update filesystem to Bursting
            response = efs_client.update_file_system(
                FileSystemId=FileSystemId, ThroughputMode="bursting"
            )
            print("Updating EFS: " + FileSystemId + " to Bursting ThroughputMode")
