import json
import sys
import datetime
import cfnresponse
import urllib3
import os

'''
To improve performance and usability, SOCA sends anonymous metrics to AWS.
You can disable this by switching "Send AnonymousData" to "No" on cloudformation_builder.py
Data tracked:
  - SOCA Instance information
  - SOCA Instance Count
  - SOCA Launch/Delete time
'''


def metrics(solution_id, uuid, data, url, request_timestamp):
    try:
        time_stamp = {'TimeStamp': request_timestamp}
        params = {'Solution': solution_id,
                  'UUID': uuid,
                  'Data': data}

        metrics = dict(time_stamp, **params)
        json_data = json.dumps(metrics, indent=4)
        print(params)
        http = urllib3.PoolManager()
        headers = {'content-type': 'application/json'}
        req = http.request('POST',
                           url,
                           body=json_data.encode('utf-8'),
                           headers=headers)
        rsp_code = req.status
        print('Response Code: {}'.format(rsp_code))
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print(exc_type, fname, exc_tb.tb_lineno)


def lambda_handler(event, context):
    request_type = event['RequestType']
    if event['RequestType'] == 'Delete':
        cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, 'Deleting')
        return

    else:
        try:
            request_timestamp = str(datetime.datetime.utcnow().isoformat())
            solution_id = 'SO0072'
            uuid = event['RequestId']
            data = {
                'RequestType': event['RequestType'],
                'RequestTimeStamp': request_timestamp,
                'StackUUID': event['ResourceProperties']['StackUUID'],
                'DesiredCapacity': event['ResourceProperties']['DesiredCapacity'],
                'BaseOS': event['ResourceProperties']['BaseOS'],
                'InstanceType': event['ResourceProperties']['InstanceType'],
                'Efa': event['ResourceProperties']['Efa'],
                'Dcv': event['ResourceProperties']['Dcv'],
                'ScratchSize': event['ResourceProperties']['ScratchSize'],
                'RootSize': event['ResourceProperties']['RootSize'],
                'SpotPrice': event['ResourceProperties']['SpotPrice'],
                'KeepForever': event['ResourceProperties']['KeepForever'],
                'FsxLustre': event['ResourceProperties']['FsxLustre']
            }
            # Metrics Account (Production)
            metrics_url = 'https://metrics.awssolutionsbuilder.com/generic'
            # Send Anonymous Metrics
            metrics(solution_id, uuid, data, metrics_url, request_timestamp)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(exc_type, fname, exc_tb.tb_lineno)

        cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, '')