import json
import sys
import datetime
import cfnresponse
import urllib3
import os

"""
To improve performance and usability, SOCA sends anonymous metrics to AWS.
You can disable this by setting "DefaultMetricCollection" to "False" in AWS Secrets Manager for the cluster configuration.
Data tracked:
  - SOCA Instance information (Type, Count, BaseOS, Disk sizing, EFA, DCV) 
  - SOCA Job Launch/Delete time
  - SOCA Version ID
  - SOCA Installed Region
  - SOCA FSx/Lustre configuration/sizing
  - SOCA Misc (from configuration; used for troubleshooting with AWS)
"""


def metrics(solution_id, uuid, data, url, request_timestamp):
    try:
        time_stamp = {"TimeStamp": request_timestamp}
        params = {"Solution": solution_id, "UUID": uuid, "Data": data}

        metrics = dict(time_stamp, **params)
        json_data = json.dumps(metrics, indent=4)
        print(params)
        http = urllib3.PoolManager()
        headers = {"content-type": "application/json"}
        req = http.request("POST", url, body=json_data.encode("utf-8"), headers=headers)
        rsp_code = req.status
        print(f"Response Code: {rsp_code}")
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)


def lambda_handler(event, context):
    try:
        request_timestamp = str(datetime.datetime.utcnow().isoformat())
        solution_id = "SO0072"
        uuid = event["RequestId"]
        data = {
            "RequestType": event["RequestType"],
            "RequestTimeStamp": request_timestamp,
        }
        # Add data items from the request
        for item in {
            "StackUUID",
            "DesiredCapacity",
            "BaseOS",
            "InstanceType",
            "Efa",
            "Dcv",
            "ScratchSize",
            "RootSize",
            "SpotPrice",
            "KeepForever",
            "FsxLustre",
            "Version",
            "Region",
            "Misc",
        }:
            data[item] = event.get("ResourceProperties", {}).get(item, "")

        # Metrics Account (Production)
        metrics_url = "https://metrics.awssolutionsbuilder.com/generic"
        # Send Anonymous Metrics
        metrics(solution_id, uuid, data, metrics_url, request_timestamp)
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)
    finally:
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, "")
