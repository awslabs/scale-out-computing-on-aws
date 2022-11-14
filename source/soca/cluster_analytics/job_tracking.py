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

from __future__ import division
import ast
import base64
import datetime
import json
import os
import re
import sys
import boto3
import pytz
import urllib3
from elasticsearch import Elasticsearch, RequestsHttpConnection
from elasticsearch.exceptions import NotFoundError as NotFoundError
from requests_aws4auth import AWS4Auth
from botocore import config as botocore_config

def boto_extra_config():
    aws_solution_user_agent = {"user_agent_extra": "AwsSolution/SO0072/2.7.2"}
    return botocore_config.Config(**aws_solution_user_agent)


def get_soca_configuration():
    secretsmanager_client = boto3.client('secretsmanager', config=boto_extra_config())
    configuration_secret_name = os.environ['SOCA_CONFIGURATION']
    response = secretsmanager_client.get_secret_value(SecretId=configuration_secret_name)
    return json.loads(response['SecretString'])


def get_aws_pricing(ec2_instance_type):
    pricing = {}
    static_pricing_json = '/apps/soca/' + os.environ['SOCA_CONFIGURATION'] + '/cluster_analytics/pricing_index.json'
    if session.region_name == "cn-north-1" or session.region_name == "cn-northwest-1":
        f = open(static_pricing_json,)
        data = json.load(f)
        for k, v in data['terms'].items():
            if k == 'OnDemand':
                for skus in v.keys():
                    for offertermcode in v[skus].keys():
                        for ratecode in v[skus][offertermcode]['priceDimensions'].keys():
                            instance_data = v[skus][offertermcode]['priceDimensions'][ratecode]
                            if 'on demand linux ' + str(ec2_instance_type) + ' instance hour' in instance_data['description'].lower():
                                pricing['ondemand'] = float(instance_data['pricePerUnit']['CNY'])
            elif k == 'Reserved':
                for skus in v.keys():
                    for offertermcode in v[skus].keys():
                        if v[skus][offertermcode]['termAttributes']['OfferingClass'] == 'standard' \
                                and v[skus][offertermcode]['termAttributes']['LeaseContractLength'] == '1yr' \
                                and v[skus][offertermcode]['termAttributes']['PurchaseOption'] == 'No Upfront':
                            for ratecode in v[skus][offertermcode]['priceDimensions'].keys():
                                instance_data = v[skus][offertermcode]['priceDimensions'][ratecode]
                                if 'Linux/UNIX (Amazon VPC)' in instance_data['description']:
                                    pricing['reserved'] = float(instance_data['pricePerUnit']['CNY'])
    else:
        response = client.get_products(
            ServiceCode='AmazonEC2',
            Filters=[
                {
                    'Type': 'TERM_MATCH',
                    'Field': 'usageType',
                    'Value': 'BoxUsage:' + ec2_instance_type
                },
            ],

        )
        for data in response['PriceList']:
            data = ast.literal_eval(data)
            for k, v in data['terms'].items():
                if k == 'OnDemand':
                    for skus in v.keys():
                        for ratecode in v[skus]['priceDimensions'].keys():
                            instance_data = v[skus]['priceDimensions'][ratecode]
                            if 'on demand linux ' + str(ec2_instance_type) + ' instance hour' in instance_data['description'].lower():
                                pricing['ondemand'] = float(instance_data['pricePerUnit']['USD'])
                else:
                    for skus in v.keys():
                        if v[skus]['termAttributes']['OfferingClass'] == 'standard' \
                                and v[skus]['termAttributes']['LeaseContractLength'] == '1yr' \
                                and v[skus]['termAttributes']['PurchaseOption'] == 'No Upfront':
                            for ratecode in v[skus]['priceDimensions'].keys():
                                instance_data = v[skus]['priceDimensions'][ratecode]
                                if 'Linux/UNIX (Amazon VPC)' in instance_data['description']:
                                    pricing['reserved'] = float(instance_data['pricePerUnit']['USD'])
    return pricing


def es_entry_exist(job_uuid,  es_index_name):
    # Make sure the entry has not already been ingested on the ElasticSearch cluster.
    # Job UUID is base64 encoded: <job_id>_<cluster_id>_<timestamp_when_job_completed>
    json_to_push = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"job_uuid": job_uuid}}],
                "filter": [
                    {"range":
                        {
                            "start_iso": {
                                "gte": (datetime.datetime.now() - datetime.timedelta(days=60)).isoformat() + 'Z',
                                "lt": "now"
                            }
                        }
                    }],
            },
        },
    }
    try:
        response = es.search(index=es_index_name, scroll='2m', size=1000, body=json_to_push)
    except NotFoundError:
        print("First entry, Index doest not exist but will be created automatically.")
        return False

    sid = response['_scroll_id']
    scroll_size = response['hits']['total']['value']
    existing_entries = []

    while scroll_size > 0:
        data = [doc for doc in response['hits']['hits']]

        for key in data:
            existing_entries.append(key["_source"])

        response = es.scroll(scroll_id=sid, scroll='2m')
        sid = response['_scroll_id']
        scroll_size = len(response['hits']['hits'])


    if existing_entries.__len__() == 0:
        return False
    else:
        return True


def es_index_new_item(body, index):
    doc_type = "item"
    add = es.index(index=index,
                   doc_type=doc_type,
                   body=body)

    if add['result'] == 'created':
        return True
    else:
        return False


def read_file(filename):
    print(f"Opening {filename}")
    try:
        log_file = open(filename, 'r')
        content = log_file.read()
        log_file.close()
    except:
        # handle case were file does not exist
        content = ''
    return content


if __name__ == "__main__":
    urllib3.disable_warnings()
    try:
        soca_configuration = get_soca_configuration()
    except Exception as err:
        print(f"Unable to retrieve SOCA configuration due to {err}")
        sys.exit(1)

    # Pricing API is only available us-east-1
    client = boto3.client('pricing', region_name='us-east-1', config=boto_extra_config())
    accounting_log_path = '/var/spool/pbs/server_priv/accounting/'
    tz = pytz.timezone('America/Los_Angeles')     # Change PyTZ as needed
    session = boto3.Session()
    credentials = session.get_credentials()
    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, session.region_name, 'es', session_token=credentials.token)
    es_endpoint = 'https://' + soca_configuration['ESDomainEndpoint']
    es_index_name = "soca_jobs"
    cluster_id = os.environ.get('SOCA_CONFIGURATION', None)
    if cluster_id is None:
        print("SOCA_CONFIGURATION environment variable not found. Make sure to source /etc/environment before executing this script")
        sys.exit(1)
    try:
        es = Elasticsearch([es_endpoint], port=443, http_auth=awsauth, use_ssl=True, verify_certs=True, connection_class=RequestsHttpConnection)
    except Exception as err:
        print(f"Unable to establish connection to  {es_endpoint} due to {err}")
        sys.exit(1)
    pricing_table = {}
    management_chain_per_user = {}
    json_output = []
    output = {}
    days_to_ingest = 3  # You can adjust this as needed if you want to replay some data. Default to last 3 days
    last_day_to_ingest = datetime.datetime.now()
    date_to_check = [last_day_to_ingest - datetime.timedelta(days=x) for x in range(days_to_ingest)]

    # Update EBS rate for your region
    # EBS Formulas: https://aws.amazon.com/ebs/pricing/
    # Estimated cost provided by SOCA are esimates only. Refer to Cost Explorer for exact data

    ebs_gp3_storage = 0.08  # $ per gb per month
    ebs_io1_storage = 0.125  # $ per gb per month
    provisionied_io = 0.065  # IOPS per month
    fsx_lustre = 0.000194  # GB per hour

    for day in date_to_check:
        scheduler_log_format = day.strftime('%Y%m%d')
        response = read_file(f"{accounting_log_path}{scheduler_log_format}")
        try:
            for line in response.splitlines():
                try:
                    data = (line.rstrip()).split(';')
                    if data.__len__() != 4:
                        pass
                    else:
                        timestamp = data[0]
                        job_state = data[1]
                        job_id = data[2].split('.')[0]
                        job_data = data[3]
                        if job_id in output.keys():
                            output[job_id].append({'utc_date': timestamp,
                                                   'job_state': job_state,
                                                   'job_id': job_id,
                                                   'job_data': job_data})
                        else:
                            output[job_id] = [{'utc_date': timestamp,
                                               'job_state': job_state,
                                               'job_id': job_id,
                                               'job_data': job_data}]
                except Exception as e:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    print (exc_type, fname, exc_tb.tb_lineno, line)
                    exit(1)

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print (exc_type, fname, exc_tb.tb_lineno, line)
            exit(1)
            # logger.error('Error while parsing logs ' + pbs_accounting_log_date + ' : ' + str((exc_type, fname, exc_tb.tb_lineno)))

    for job_id, values in output.items():
        try:
            for data in values:
                try:
                    if data['job_state'].lower() == 'e':
                        ignore = False
                        if 'Resource_List.instance_type' not in data['job_data']:
                            # job not done
                            ignore = True
                        else:
                            queue = re.search(r'queue=(\w+)', data['job_data']).group(1)

                        if ignore is False:
                            used_resources = re.findall('(\w+)=([^\s]+)', data['job_data'])

                            if used_resources:
                                job_info = {'job_id': job_id}
                                for res in used_resources:
                                    resource_name = res[0]
                                    resource_value = res[1]
                                    if resource_name == 'select':
                                        mpiprocs = re.search(r'mpiprocs=(\d+)', resource_value)
                                        if mpiprocs:
                                            job_info['mpiprocs'] = int(re.search(r'mpiprocs=(\d+)', resource_value).group(1))

                                    if 'ppn' in resource_value:
                                        ppn = re.search(r'ppn=(\d+)', resource_value)
                                        if ppn:
                                            job_info['ppn'] = int(re.search(r'ppn=(\d+)', resource_value).group(1))

                                    job_info[resource_name] = int(resource_value) if resource_value.isdigit() is True else resource_value
                                # Adding custom field to index
                                job_info['soca_cluster_id'] = cluster_id
                                job_info['simulation_time_seconds'] = job_info['end'] - job_info['start']
                                job_info['simulation_time_minutes'] = float(job_info['simulation_time_seconds'] / 60)
                                job_info['simulation_time_hours'] = float(job_info['simulation_time_minutes'] / 60)
                                job_info['simulation_time_days'] = float(job_info['simulation_time_hours'] / 24)
                                job_info['mem_kb'] = int(job_info['mem'].replace('kb', ''))
                                job_info['vmem_kb'] = int(job_info['vmem'].replace('kb', ''))
                                job_info['qtime_iso'] = (datetime.datetime.fromtimestamp(job_info['qtime'], tz).isoformat())
                                job_info['etime_iso'] = (datetime.datetime.fromtimestamp(job_info['etime'], tz).isoformat())
                                job_info['ctime_iso'] = (datetime.datetime.fromtimestamp(job_info['ctime'], tz).isoformat())
                                job_info['start_iso'] = (datetime.datetime.fromtimestamp(job_info['start'], tz).isoformat())
                                job_info['end_iso'] = (datetime.datetime.fromtimestamp(job_info['end'], tz).isoformat())
                                job_info['job_uuid'] = base64.b64encode(f"{job_id}_{cluster_id}_{job_info['end_iso']}".encode("utf-8")).decode("utf-8")

                                # Calculate price of the simulation
                                # ESTIMATE ONLY. Refer to AWS Cost Explorer for exact data

                                # Note 1: This calculate the price of the simulation based on run time only.
                                # It does not include the time for EC2 to be launched and configured, so I artificially added a 5 minutes penalty (average time for an EC2 instance to be provisioned)
                                EC2_BOOT_DELAY = 300
                                simulation_time_seconds_with_penalty = job_info['simulation_time_seconds'] + EC2_BOOT_DELAY
                                job_info['estimated_price_storage_scratch_iops'] = 0
                                job_info['estimated_price_storage_root_size'] = 0  # alwayson
                                job_info['estimated_price_storage_scratch_size'] = 0
                                job_info['estimated_price_fsx_lustre'] = 0

                                if 'root_size' in job_info.keys():
                                    job_info['estimated_price_storage_root_size'] = ((int(job_info['root_size']) * ebs_gp3_storage * simulation_time_seconds_with_penalty) / (86400 * 30)) * job_info['nodect']

                                if 'scratch_size' in job_info.keys():
                                    if 'scratch_iops' in job_info.keys():
                                        job_info['estimated_price_storage_scratch_size'] = ((int(job_info['scratch_size']) * ebs_io1_storage * simulation_time_seconds_with_penalty) / (86400 * 30)) * job_info['nodect']
                                        job_info['estimated_price_storage_scratch_iops'] = ((int(job_info['scratch_iops']) * provisionied_io * simulation_time_seconds_with_penalty) / (86400 * 30)) * job_info['nodect']
                                    else:
                                        job_info['estimated_price_storage_scratch_size'] = ((int(job_info['scratch_size']) * ebs_gp3_storage * simulation_time_seconds_with_penalty) / (86400 * 30)) * job_info['nodect']

                                if 'fsx_lustre_bucket' in job_info.keys():
                                    if job_info['fsx_lustre_bucket'] != 'false':
                                        if 'fsx_lustre_size' in job_info.keys():
                                            job_info['estimated_price_fsx_lustre'] = job_info['fsx_lustre_size'] * fsx_lustre * (simulation_time_seconds_with_penalty / 3600)
                                        else:
                                            # default lustre size
                                            job_info['estimated_price_fsx_lustre'] = 1200 * fsx_lustre * (simulation_time_seconds_with_penalty / 3600)

                                if job_info['instance_type'] not in pricing_table.keys():
                                    pricing_table[job_info['instance_type']] = get_aws_pricing(job_info['instance_type'])

                                job_info['estimated_price_ec2_ondemand'] = simulation_time_seconds_with_penalty * (pricing_table[job_info['instance_type']]['ondemand'] / 3600) * job_info['nodect']
                                reserved_hourly_rate = pricing_table[job_info['instance_type']]['reserved'] / 750
                                job_info['estimated_price_ec2_reserved'] = simulation_time_seconds_with_penalty * (reserved_hourly_rate / 3600) * job_info['nodect']

                                job_info['estimated_price_ondemand'] = job_info['estimated_price_ec2_ondemand'] + job_info['estimated_price_storage_root_size'] + job_info['estimated_price_storage_scratch_size'] + job_info['estimated_price_storage_scratch_iops'] + job_info['estimated_price_fsx_lustre']
                                job_info['estimated_price_reserved'] = job_info['estimated_price_ec2_reserved'] + job_info['estimated_price_storage_root_size'] + job_info['estimated_price_storage_scratch_size'] + job_info['estimated_price_storage_scratch_iops'] + job_info['estimated_price_fsx_lustre']

                                json_output.append(job_info)
                except Exception as e:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    print(f"Error with {data} for job id {job_id} - {exc_type} - {fname} - { exc_tb.tb_lineno}")
                    exit(1)

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(f"Fatal error:  {exc_type} - {fname} - {exc_tb.tb_lineno}")
            exit(1)

    for entry in json_output:
        if es_entry_exist(f"{entry['job_uuid']}", es_index_name) is False:
            if es_index_new_item(json.dumps(entry), es_index_name) is False:
                print(f"Error while indexing {entry}")
                exit(1)
            else:
                print(f"Indexed {entry}")
        else:
            #Already Indexed
            pass

