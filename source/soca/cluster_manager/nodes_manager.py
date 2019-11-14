import boto3
import subprocess
import json
import sys
import os
sys.path.append(os.path.dirname(__file__))
import configuration
from ast import literal_eval

def run_command(cmd, type):
    try:
        if type == "check_output":
            command = subprocess.check_output(cmd)
            return literal_eval(command.decode('utf-8'))
        elif type == "call":
            command = subprocess.call(cmd)
            return command
        else:
            print("Command not Defined")
            exit(1)

    except subprocess.CalledProcessError as e:
        return ""


def get_all_compute_instances(cluster_id):
    token = True
    next_token = ''
    job_stack = {}
    while token is True:
        # ATTENTION /!\
        # CHANGING THIS FILTER COULD POSSIBLE BRING DOWN OTHER EC2 INSTANCES IN YOUR AWS ACCOUNT
        response = ec2_client.describe_instances(
            Filters=[
                {
                    'Name': 'instance-state-name',
                    'Values': [
                        'running',
                    ]
                },
                {
                    'Name': 'tag:soca:NodeType',
                    'Values': ['soca-compute-node']
                },
                {
                    'Name': 'tag:soca:KeepForever',
                    'Values': ['true', 'false']
                },
                {
                    'Name': 'tag:soca:ClusterId',
                    'Values': [cluster_id]
                },

            ],
            MaxResults=1000,
            NextToken=next_token,
        )

        try:
            next_token = response['NextToken']
        except KeyError:
            token = False

        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_type = instance['InstanceType']
                subnet_id = instance['SubnetId']
                availability_zone = instance['Placement']['AvailabilityZone']
                job_id = [x['Value'] for x in instance['Tags'] if x['Key'] == 'soca:JobId']
                job_queue = [x['Value'] for x in instance['Tags'] if x['Key'] == 'soca:JobQueue'][0]
                keep_forever = [x['Value'] for x in instance['Tags'] if x['Key'] == 'soca:KeepForever'][0]
                cloudformation_stack = [x['Value'] for x in instance['Tags'] if x['Key'] == 'aws:cloudformation:stack-name'][0]
                private_dns = instance['PrivateDnsName'].split('.')[0]

                if not job_id:
                    job_id = 'do_not_delete'
                else:
                    job_id = job_id[0]

                if job_id in job_stack.keys():
                    job_stack[job_id]['instances'].append(private_dns)
                else:
                    job_stack[job_id] = {'stack_name': cloudformation_stack,
                                         'keep_forever': keep_forever,
                                         'instances': [private_dns],
                                         'job_queue': job_queue,
                                         'job_id': job_id,
                                         'instance_type': instance_type,
                                         'availability_zone': availability_zone,
                                         'subnet_id': subnet_id}

    return job_stack


def get_scheduler_jobs_in_queue():
    qstat_args = ' -f -F json'
    check_current_jobs = (run_command((sbins['qstat'] + qstat_args).split(), "check_output"))
    if 'Jobs' in check_current_jobs.keys():
        job_ids = [job.split('.')[0] for job in check_current_jobs['Jobs'].keys()]
        return job_ids
    else:
        return []


def get_scheduler_all_nodes():
    pbsnodes_args = ' -a -F json'
    pbs_hosts = []
    pbs_hosts_down = []
    try:
        pbsnodes_output = (run_command((sbins['pbsnodes'] + pbsnodes_args).split(), "check_output"))
        if 'nodes' in pbsnodes_output.keys():
            for hostname, data in pbsnodes_output['nodes'].items():
                if not 'jobs' in data.keys():
                    if not 'job-exclusive' in str(data['state']):
                        if 'down' in str(data['state']):
                            pbs_hosts_down.append(hostname)
                pbs_hosts.append(hostname)
    except AttributeError as e:
        # Case when scheduler does not have any valid host
        pass
    except Exception as e:
        print(e)

    return {'pbs_hosts': pbs_hosts,
            'pbs_hosts_down': pbs_hosts_down}


def delete_stack(stack_to_delete):
    for stack_name in stack_to_delete:
        print('Deleting ' + stack_name)
        cloudformation_client.delete_stack(StackName=stack_name)


def delete_hosts(hosts):
    for host in hosts:
        cmd = [sbins['qmgr'], "-c", "delete node " + host]
        try:
            print('Running ' + str(cmd))
            run_command(cmd, "call")
        except Exception as e:
            print('Error trying to run ' + str(cmd) + ' Error: ' + str(e))


def add_hosts(hosts, compute_instances):
    for host in hosts:
        host_queue = [v['job_queue'] for k,v in compute_instances.items() if host in v['instances']]
        host_job_id = [v['job_id'] for k,v in compute_instances.items() if host in v['instances']]
        host_instance_type = [v['instance_type'] for k,v in compute_instances.items() if host in v['instances']]
        host_subnet_id = [v['subnet_id'] for k,v in compute_instances.items() if host in v['instances']]
        host_az = [v['availability_zone'] for k, v in compute_instances.items() if host in v['instances']]
        cmds = [[sbins['qmgr'], "-c", "create node " + host + "  queue=" + host_queue[0]],
               [sbins['qmgr'], "-c", "set node " + host + " resources_available.compute_node=job" + host_job_id[0] + ",resources_available.instance_type=" + host_instance_type[0] +  ",resources_available.availability_zone=" + host_az[0] +  ",resources_available.subnet_id=" + host_subnet_id[0]]]
        for cmd in cmds:
            try:
                print('Running ' + str(cmd))
                run_command(cmd, "call")
            except Exception as e:
                print('Error trying to run ' + str(cmd) + ' Error: ' +str(e))


if __name__ == "__main__":
    aligo_configuration = configuration.get_aligo_configuration()
    ec2_client = boto3.client('ec2')
    cloudformation_client = boto3.client('cloudformation')

    sbins = {'qstat': '/opt/pbs/bin/qstat',
             'qmgr': '/opt/pbs/bin/qmgr',
             'pbsnodes': '/opt/pbs/bin/pbsnodes'
             }

    # 1 - get all running EC2 instances
    compute_instances = get_all_compute_instances(aligo_configuration['ClusterId'])
    # Get all current instances private DNS
    current_ec2_compute_nodes_dns = [item for sublist in [v['instances'] for k, v in compute_instances.items()] for item in sublist]

    # 2 - get a list of all job ids in the queue
    scheduler_jobs_in_queue = get_scheduler_jobs_in_queue()

    # 3 - Get all pbsnodes

    all_nodes = get_scheduler_all_nodes()
    pbs_nodes = all_nodes['pbs_hosts']
    pbs_nodes_down = all_nodes['pbs_hosts_down']
    cloudformation_stack_to_delete = []

    compute_nodes_to_delete = []
    for job_id, stack_data in compute_instances.items():
        if stack_data['keep_forever'] == 'false':
            if job_id not in scheduler_jobs_in_queue:
                print(job_id + ' NOT IN QUEUE. CAN KILL')
                cloudformation_stack_to_delete.append(stack_data['stack_name'])
                for host in stack_data['instances']:
                    compute_nodes_to_delete.append(host)

    if cloudformation_stack_to_delete.__len__() > 0:
        delete_stack(cloudformation_stack_to_delete)
        delete_hosts(compute_nodes_to_delete)

    # Now clean any hosts on pbs_nodes IN DOWN STATE, not serving jobs and not in  current_ec2_compute_nodes_dns (mostly KeepForever instance we  previously deleted)
    legacy_host_to_delete = list(set(pbs_nodes_down) - set(current_ec2_compute_nodes_dns))

    if legacy_host_to_delete.__len__() > 0:
        print('need to qmgr delete legacy ')
        print(legacy_host_to_delete)
        delete_hosts(legacy_host_to_delete)

    compute_nodes_to_add = list((set(current_ec2_compute_nodes_dns) - set(pbs_nodes)) - set(compute_nodes_to_delete))

    if compute_nodes_to_add.__len__() > 0:
        print('need to qmgr add ' +str(compute_nodes_to_add))
        add_hosts(compute_nodes_to_add, compute_instances)