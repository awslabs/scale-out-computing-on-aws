from __future__ import division

import ast
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


def get_aligo_configuration():
    '''
    Return general configuration parameter
    '''
    secretsmanager_client = boto3.client('secretsmanager')
    configuration_secret_name = os.environ['SOCA_CONFIGURATION']
    response = secretsmanager_client.get_secret_value(SecretId=configuration_secret_name)
    return json.loads(response['SecretString'])


def get_aws_pricing(ec2_instance_type):

    pricing = {}
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


def es_entry_exist(job_id):
    # Make sure the entry has not already been update within the last 100 days. This handle case where customers update their SOCA and reset the scheduler count
    json_to_push = {
        "query": {
            "bool": {
                "must": [
                    {"match": {"job_id": job_id},
                     }],
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
        response = es.search(index="jobs",
                         scroll='2m',
                         size=1000,
                         body=json_to_push)
    except NotFoundError:
        print("First entry, Index doest not exist but will be created automaticall.y")
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


def es_index_new_item(body):
    index = "jobs"
    doc_type = "item"
    add = es.index(index=index,
                   doc_type=doc_type,
                   body=body)

    if add['result'] == 'created':
        return True
    else:
        return False


def read_file(filename):
    print('Opening ' +filename)
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
    aligo_configuration = get_aligo_configuration()

    # Pricing API is only available us-east-1
    client = boto3.client('pricing', region_name='us-east-1')
    accounting_log_path='/var/spool/pbs/server_priv/accounting/'
    # Change PyTZ as needed
    tz = pytz.timezone('America/Los_Angeles')
    session = boto3.Session()
    credentials = session.get_credentials()
    awsauth = AWS4Auth(credentials.access_key, credentials.secret_key, session.region_name, 'es', session_token=credentials.token)
    es_endpoint = 'https://' + aligo_configuration['ESDomainEndpoint']
    es = Elasticsearch([es_endpoint], port=443,
                       http_auth=awsauth,
                       use_ssl=True,
                       verify_certs=True,
                       connection_class=RequestsHttpConnection)

    pricing_table = {}
    management_chain_per_user = {}
    json_output = []
    output = {}

    # DAY_TO_INGEST = 2 --> Check today & yesterday logs. You can adjust this as needed
    DAY_TO_INGEST = 2
    FROM = datetime.datetime.now()
    date_to_check = [FROM - datetime.timedelta(days=x) for x in range(DAY_TO_INGEST)]

    for day in date_to_check:
        scheduler_log_format = day.strftime('%Y%m%d')
        response = read_file(accounting_log_path+scheduler_log_format)
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
                                                   'job_data': job_data
                                                   })


                        else:
                            output[job_id] = [{'utc_date': timestamp,
                                               'job_state': job_state,
                                               'job_id': job_id,
                                               'job_data': job_data
                                               }]
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
                                tmp = {'job_id': job_id}
                                for res in used_resources:
                                    resource_name = res[0]
                                    resource_value = res[1]
                                    if resource_name == 'select':
                                        mpiprocs = re.search(r'mpiprocs=(\d+)', resource_value)
                                        if mpiprocs:
                                            tmp['mpiprocs'] = int(re.search(r'mpiprocs=(\d+)', resource_value).group(1))

                                    if 'ppn' in resource_value:
                                        ppn = re.search(r'ppn=(\d+)', resource_value)
                                        if ppn:
                                            tmp['ppn'] = int(re.search(r'ppn=(\d+)', resource_value).group(1))

                                    tmp[resource_name] = int(resource_value) if resource_value.isdigit() is True else resource_value


                                # Adding custom field to index
                                tmp['simulation_time_seconds'] = tmp['end'] - tmp['start']
                                tmp['simulation_time_minutes'] = float(tmp['simulation_time_seconds'] / 60)
                                tmp['simulation_time_hours'] = float(tmp['simulation_time_minutes'] / 60)
                                tmp['simulation_time_days'] = float(tmp['simulation_time_hours'] / 24)

                                tmp['mem_kb'] = int(tmp['mem'].replace('kb', ''))
                                tmp['vmem_kb'] = int(tmp['vmem'].replace('kb', ''))

                                tmp['qtime_iso'] = (datetime.datetime.fromtimestamp(tmp['qtime'], tz).isoformat())
                                tmp['etime_iso'] = (datetime.datetime.fromtimestamp(tmp['etime'], tz).isoformat())
                                tmp['ctime_iso'] = (datetime.datetime.fromtimestamp(tmp['ctime'], tz).isoformat())
                                tmp['start_iso'] = (datetime.datetime.fromtimestamp(tmp['start'], tz).isoformat())
                                tmp['end_iso'] = (datetime.datetime.fromtimestamp(tmp['end'], tz).isoformat())

                                # Calculate price of the simulation
                                # ESTIMATE ONLY. Refer to AWS Cost Explorer for exact data
                                
                                # Update EBS rate for your region
                                # EBS Formulas: https://aws.amazon.com/ebs/pricing/
                                ebs_gp3_storage = 0.08  # $ per gb per month
                                ebs_io1_storage = 0.125  # $ per gb per month
                                provisionied_io = 0.065  # IOPS per month
                                fsx_lustre = 0.000194 # GB per hour
                                # Note 1: This calculate the price of the simulation based on run time only.
                                # It does not include the time for EC2 to be launched and configured, so I artificially added a 5 minutes penalty (average time for an EC2 instance to be provisioned)
                                EC2_BOOT_DELAY = 300
                                simulation_time_seconds_with_penalty = tmp['simulation_time_seconds'] + EC2_BOOT_DELAY
                                tmp['estimated_price_storage_scratch_iops'] = 0
                                tmp['estimated_price_storage_root_size'] = 0  # alwayson
                                tmp['estimated_price_storage_scratch_size'] = 0
                                tmp['estimated_price_fsx_lustre'] = 0

                                if 'root_size' in tmp.keys():
                                    tmp['estimated_price_storage_root_size'] = ((int(tmp['root_size']) * ebs_gp3_storage * simulation_time_seconds_with_penalty) / (86400 * 30)) * tmp['nodect']

                                if 'scratch_size' in tmp.keys():
                                    if 'scratch_iops' in tmp.keys():
                                        tmp['estimated_price_storage_scratch_size'] = ((int(tmp['scratch_size']) * ebs_io1_storage * simulation_time_seconds_with_penalty) / (86400 * 30)) * tmp['nodect']
                                        tmp['estimated_price_storage_scratch_iops'] = ((int(tmp['scratch_iops']) * provisionied_io * simulation_time_seconds_with_penalty) / (86400 * 30)) * tmp['nodect']
                                    else:
                                        tmp['estimated_price_storage_scratch_size'] = ((int(tmp['scratch_size']) * ebs_gp3_storage * simulation_time_seconds_with_penalty) / (86400 * 30)) * tmp['nodect']

                                if 'fsx_lustre_bucket' in tmp.keys():
                                    if tmp['fsx_lustre_bucket'] != 'false':
                                        if 'fsx_lustre_size' in tmp.keys():
                                            tmp['estimated_price_fsx_lustre'] = tmp['fsx_lustre_size'] * fsx_lustre * (simulation_time_seconds_with_penalty / 3600)
                                        else:
                                            # default lustre size
                                            tmp['estimated_price_fsx_lustre'] = 1200 * fsx_lustre * (simulation_time_seconds_with_penalty / 3600)

                                if tmp['instance_type'] not in pricing_table.keys():
                                    pricing_table[tmp['instance_type']] = get_aws_pricing(tmp['instance_type'])

                                tmp['estimated_price_ec2_ondemand'] = simulation_time_seconds_with_penalty * (pricing_table[tmp['instance_type']]['ondemand'] / 3600) * tmp['nodect']
                                reserved_hourly_rate = pricing_table[tmp['instance_type']]['reserved'] / 750
                                tmp['estimated_price_ec2_reserved'] = simulation_time_seconds_with_penalty * (reserved_hourly_rate / 3600) * tmp['nodect']

                                tmp['estimated_price_ondemand'] = tmp['estimated_price_ec2_ondemand'] + tmp['estimated_price_storage_root_size'] + tmp['estimated_price_storage_scratch_size'] + tmp['estimated_price_storage_scratch_iops'] + tmp['estimated_price_fsx_lustre']
                                tmp['estimated_price_reserved'] = tmp['estimated_price_ec2_reserved'] + tmp['estimated_price_storage_root_size'] + tmp['estimated_price_storage_scratch_size'] + tmp['estimated_price_storage_scratch_iops'] + tmp['estimated_price_fsx_lustre']

                            json_output.append(tmp)
                except Exception as e:
                    print("===========")
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    print('Error with ' + str(data))
                    print ((exc_type, fname, exc_tb.tb_lineno))
                    print('Job id: ' + str(job_id))
                    print("===========")
                    exit(1)


        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print('Error')
            print ((exc_type, fname, exc_tb.tb_lineno))
            #print e
            #print "Entry error:"
            #print str(data)
            #logger.error('Error while indexing job  ' + str(output[job_id]) + ' : ' + str((exc_type, fname, exc_tb.tb_lineno)))
            exit(1)

    for entry in json_output:
        if es_entry_exist(entry['job_id']) is False:
            if es_index_new_item(json.dumps(entry)) is False:
                print('Error while indexing ' + str(entry))
                exit(1)
            else:
                print('Indexed '+str(entry))

        else:
            #print 'Already Indexed' + str(entry)
            pass

