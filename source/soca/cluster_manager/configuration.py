import boto3
import os
import json


def get_aligo_configuration():
    '''
    Return general configuration parameter
    '''
    secretsmanager_client = boto3.client('secretsmanager')
    configuration_secret_name = os.environ['SOCA_CONFIGURATION']
    response = secretsmanager_client.get_secret_value(SecretId=configuration_secret_name)
    return json.loads(response['SecretString'], strict=False)


def return_desktop_queues():
    '''
    List of queued dedicated to DCV.
    These queues does not have any compute_node mapping and multiple PBS jobs can land on the same harwdware
    '''
    return ['desktop']
