import cfnresponse
import boto3
import json
import logging
import os
'''
Tag EC2 Resource
'''
logging.getLogger().setLevel(logging.INFO)
def lambda_handler(event, context):
    try:
        logging.info("event: {}".format(event))
        resourceId = event['ResourceProperties']['ResourceId']
        logging.info("resourceId: {}".format(resourceId))
        tags = event['ResourceProperties']['Tags']
        logging.info("tags: {}".format(tags))

        ec2_client = boto3.client('ec2')
        ec2_client.create_tags(
            Resources=[resourceId],
            Tags=tags
        )
    except Exception as e:
        logging.exception("Unhandled exception")
        cfnresponse.send(event, context, cfnresponse.FAILED, {'error': str(e)}, str(e))

    cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, "")
