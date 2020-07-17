#!/usr/bin/python
import sys
import subprocess
import json
import boto3
from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth
import pytz
import datetime
import os

def get_aligo_configuration():
    '''
    Return general configuration parameter
    '''
    secretsmanager_client = boto3.client('secretsmanager')
    configuration_secret_name = os.environ['SOCA_CONFIGURATION']
    response = secretsmanager_client.get_secret_value(SecretId=configuration_secret_name)
    return json.loads(response['SecretString'])

def es_index_new_item(body):
    index = "pbsnodes"
    doc_type = "item"
    add = es.index(index=index,
                   doc_type=doc_type,
                   body=body)
    if add['result'] == 'created':
        return True
    else:
        return False


if __name__ == "__main__":
    aligo_configuration = get_aligo_configuration()
    pbsnodes = '/opt/pbs/bin/pbsnodes'
    pbsnodes_args = ' -a -F json'
    tz = pytz.timezone('America/Los_Angeles')
    es_endpoint = 'https://' + aligo_configuration['ESDomainEndpoint']
    session = boto3.Session()
    credentials = session.get_credentials()
    awsauth = AWS4Auth(credentials.access_key,
                       credentials.secret_key,
                       session.region_name,
                       'es', session_token=credentials.token)

    es = Elasticsearch([es_endpoint], port=443,
                       http_auth=awsauth,
                       use_ssl=True,
                       verify_certs=True,
                       connection_class=RequestsHttpConnection)

    try:
        command = subprocess.Popen((pbsnodes + pbsnodes_args).split(), stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        stdout, stderr = command.communicate()
        if 'pbsnodes: Server has no node list' in stdout.decode("utf-8"):
            exit(0)
        else:
            pbsnodes_output = json.loads(stdout)
    except subprocess.CalledProcessError as e:
        print('CalledProcessError: ' + str(e))
        exit(1)
    except Exception as e:
        print('Unknown Error: '+ str(e))
        exit(1)

    timestamp = pbsnodes_output['timestamp']
    for hostname, data in pbsnodes_output['nodes'].items():
        data['timestamp'] = (datetime.datetime.fromtimestamp(timestamp, tz).isoformat())

        if es_index_new_item(json.dumps(data)) is False:
            print('Error while indexing ' + str(data))