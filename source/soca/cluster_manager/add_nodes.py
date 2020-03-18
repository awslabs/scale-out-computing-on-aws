import argparse
import ast
import os
import random
import re
import sys
import uuid

import boto3

sys.path.append(os.path.dirname(__file__))
import configuration
from botocore import exceptions
import cloudformation_builder

cloudformation = boto3.client('cloudformation')
s3 = boto3.client('s3')
ec2 = boto3.client('ec2')
aligo_configuration = configuration.get_aligo_configuration()


def can_launch_capacity(instance_type, count, image_id,subnet_id):
    instance_to_test = instance_type.split('+')
    for instance in instance_to_test:
        try:
            ec2.run_instances(
                ImageId=image_id,
                InstanceType=instance,
                SubnetId=subnet_id,
                MaxCount=int(count),
                MinCount=int(count),
                DryRun=True)

        except Exception as e:
            if e.response['Error'].get('Code') == 'DryRunOperation':
                return True
            else:
                print('Dry Run Failed, capacity ' + instance + ' can not be added: ' + str(e), 'error')
                return False


def check_config(**kwargs):
    error = False
    # Convert str to bool when possible
    for k, v in kwargs.items():
        if str(v).lower() in ['true', 'yes', 'y', 'on']:
            kwargs[k] = True
        if str(v).lower() in ['false', 'no', 'n', 'off']:
            kwargs[k] = False

     ## Must convert true,True into bool() and false/False
    if kwargs['job_id'] is None and kwargs['keep_forever'] is None:
        error = return_message('--job_id or --keep_forever must be specified')

    # Ensure jobId is not None when using keep_forever
    if kwargs['job_id'] is None and kwargs['keep_forever'] is not None:
        kwargs['job_id'] = kwargs['stack_uuid']

    # Ensure anonymous metric is either True or False.
    if kwargs['anonymous_metrics'] not in [True, False]:
        kwargs['anonymous_metrics'] = True

    if not isinstance(int(kwargs['desired_capacity']), int):
        return_message('Desired Capacity must be an int')

    if not 'tags' in kwargs.keys() or kwargs['tags'] is None:
        kwargs['tags'] = {}
    else:
        try:
            kwargs['tags'] = ast.literal_eval(kwargs['tags'])
            if not isinstance(kwargs['tags'], dict):
                error = return_message('Tags must be a valid dictionary')
        except ValueError:
            error = return_message('Tags must be a valid dictionary')

    # FSx Management
    kwargs['fsx_lustre_configuration'] = {
        'fsx_lustre': kwargs['fsx_lustre'],
        's3_backend': False,
        'existing_fsx': False,
        'import_path': False,
        'export_path': False,
        'deployment_type': 'SCRATCH_1',  # limited to scratch1 for now
        'per_unit_throughput': 200,  # will be used in future release
        'capacity': 1200
    }

    if kwargs['fsx_lustre'] is not False:
        if kwargs['fsx_lustre'] is not True:
            # when fsx_lustre is set to True, only create a FSx without S3 backend
            if kwargs['fsx_lustre'].startswith("fs-"):
                kwargs['fsx_lustre_configuration']['existing_fsx'] = kwargs['fsx_lustre']
            else:
                if kwargs['fsx_lustre'].startswith("s3://"):
                    kwargs['fsx_lustre_configuration']['s3_backend'] = kwargs['fsx_lustre']
                else:
                    kwargs['fsx_lustre_configuration']['s3_backend'] = "s3://" + kwargs['fsx_lustre']

                # Verify if SOCA has permissions to access S3 backend
                try:
                    s3.get_bucket_acl(Bucket=kwargs['fsx_lustre'].split('s3://')[-1])
                except exceptions.ClientError:
                    error = return_message('SOCA does not have access to this bucket (' + kwargs['fsx_lustre_bucket'] + '). Refer to the documentation to update IAM policy.')

                # Verify if user specified custom Import/Export path.
                # Syntax is fsx_lustre=<bucket>+<export_path>+<import_path>
                check_user_specified_path = kwargs['fsx_lustre'].split('+')
                if check_user_specified_path.__len__() == 1:
                    pass
                elif check_user_specified_path.__len__() == 2:
                    # import path default to bucket root if not specified
                    kwargs['fsx_lustre_configuration']['export_path'] = check_user_specified_path[1]
                    kwargs['fsx_lustre_configuration']['import_path'] = kwargs['fsx_lustre_configuration']['s3_backend']
                elif check_user_specified_path.__len__() == 3:
                    # When customers specified both import and export path
                    kwargs['fsx_lustre_configuration']['export_path'] = check_user_specified_path[1]
                    kwargs['fsx_lustre_configuration']['import_path'] = check_user_specified_path[2]
                else:
                    error = return_message('Error setting up Import/Export path: ' + kwargs['fsx_lustre'] + '). Syntax is <bucket_name>+<export_path>+<import_path>. If import_path is not specified it defaults to bucket root level')

        if kwargs['fsx_lustre_size'] is not False:
            fsx_lustre_capacity_allowed = [1200, 2400, 3600, 7200, 10800]
            if int(kwargs['fsx_lustre_size']) not in fsx_lustre_capacity_allowed:
                error = return_message('fsx_lustre_size must be: ' + ','.join(str(x) for x in fsx_lustre_capacity_allowed))
            else:
                kwargs['fsx_lustre_configuration']['capacity'] = kwargs['fsx_lustre_size']

    soca_private_subnets = [aligo_configuration['PrivateSubnet1'],
                            aligo_configuration['PrivateSubnet2'],
                            aligo_configuration['PrivateSubnet3']]

    if kwargs['subnet_id'] is False:
        kwargs['subnet_id'] = [random.choice(soca_private_subnets)]
    else:
        kwargs['subnet_id'] = kwargs['subnet_id'].split('+')
        for subnet in kwargs['subnet_id']:
            if subnet not in soca_private_subnets:
                error = return_message('Incorrect subnet_id. Must be one of ' + ','.join(soca_private_subnets))

    # Handle placement group logic
    if 'placement_group' not in kwargs.keys():
        pg_user_defined = False
        # Default PG to True if not present
        kwargs['placement_group'] = True
    else:
        pg_user_defined = True
        if kwargs['placement_group'] not in [True, False]:
            kwargs['placement_group'] = False
            error = return_message('Incorrect placement_group. Must be True or False')

    if int(kwargs['desired_capacity']) > 1:
        if kwargs['subnet_id'].__len__() > 1 and pg_user_defined is True and kwargs['placement_group'] is True:
            # more than 1 subnet specified but placement group is also configured, default to the first subnet and enable PG
            kwargs['subnet_id'] = [kwargs['subnet_id'][0]]
        else:
            if kwargs['subnet_id'].__len__() > 1 and pg_user_defined is False:
                kwargs['placement_group'] = False
    else:
        if int(kwargs['desired_capacity']) == 1:
            kwargs['placement_group'] = False
        else:
            # default to user specified value
            pass


    if kwargs['subnet_id'].__len__() > 1:
        if kwargs['placement_group'] is True:
            # if placement group is True and more than 1 subnet is defined, force default to 1 subnet
            kwargs['subnet_id'] = [kwargs['subnet_id'][0]]

    cpus_count_pattern = re.search(r'[.](\d+)', kwargs['instance_type'])
    if cpus_count_pattern:
        kwargs['core_count'] = int(cpus_count_pattern.group(1)) * 2
    else:
        if 'xlarge' in kwargs['instance_type']:
            kwargs['core_count'] = 2
        else:
            kwargs['core_count'] = 1


    # Validate Spot Allocation Strategy
    if kwargs['spot_allocation_strategy'] is not False:
        spot_allocation_strategy_allowed = ['lowest-price', 'capacity-optimized']
        if kwargs['spot_allocation_strategy'] not in spot_allocation_strategy_allowed:
            error = return_message('spot_allocation_strategy_allowed (' + str(kwargs['spot_allocation_strategy']) + ') must be one of the following value: ' + ','.join(spot_allocation_strategy_allowed))

    # Validate Spot Allocation Percentage
    if kwargs['spot_allocation_count'] is not False:
        if isinstance(kwargs['spot_allocation_count'], int):
            if int(kwargs['spot_allocation_count']) > kwargs['desired_capacity']:
                error = return_message('spot_allocation_count (' + str(kwargs['spot_allocation_count']) + ') must be an lower or equal to the number of nodes provisioned for this simulation (' + str(kwargs['desired_capacity']) + ')')
        else:
            error = return_message('spot_allocation_count (' + str(kwargs['spot_allocation_count']) + ') must be an integer')

    # Validate ht_support
    if kwargs['ht_support'] is None:
        kwargs['ht_support'] = False
    else:
        if kwargs['ht_support'] not in [True, False]:
            error = return_message('ht_support (' + str(kwargs['ht_support']) + ') must be either True or False')

    # Validate Base OS
    if kwargs['base_os'] is not False:
        base_os_allowed = ['rhel7', 'centos7', 'amazonlinux2']
        if kwargs['base_os'] not in base_os_allowed:
            error = return_message('base_os (' + str(kwargs['base_os']) + ') must be one of the following value: ' + ','.join(base_os_allowed))
    else:
        kwargs['base_os'] = aligo_configuration['BaseOS']

    # Validate Spot Price
    if kwargs['spot_price'] is not False:
        if kwargs['spot_price'] == 'auto' or isinstance(kwargs['spot_price'], float):
            pass
        else:
            error = return_message('spot_price must be either "auto" or a float value"')

    # Validate EFA
    if kwargs['efa_support'] not in [True, False]:
        kwargs['efa_support'] = False
    else:
        if kwargs['efa_support'] is True:
            if 'n' not in kwargs['instance_type']:
                error = return_message('You have requested EFA support but your instance type does not support EFA: ' + kwargs['instance_type'])

    # Validate Keep EBS
    if kwargs['keep_ebs'] not in [True, False]:
        kwargs['keep_ebs'] = False

    if error is not False:
        return error
    else:
        return kwargs


def return_message(message, success=False):
    return {'success': success,
            'message': message}


def main(**kwargs):
    try:
        # Create default value for optional parameters if needed
        optional_job_parameters = {'anonymous_metrics': aligo_configuration["DefaultMetricCollection"],
                                   'base_os': False,
                                   'efa_support': False,
                                   'fsx_lustre': False,
                                   'fsx_lustre_size': False,
                                   'ht_support': False,
                                   'keep_ebs': False,
                                   'root_size': 10,
                                   'scratch_size': 0,
                                   'spot_allocation_count': False,
                                   'spot_allocation_strategy': 'lowest-price',
                                   'spot_price': False,
                                   'subnet_id': False,
                                   'scratch_iops': 0,
                                   'stack_uuid': str(uuid.uuid4())
                                   }

        for k, v in optional_job_parameters.items():
            if k not in kwargs.keys():
                kwargs[k] = v

        required_job_parameters = []
        # Validate Job parameters
        try:
            params = check_config(**kwargs)
        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return return_message('Unable to verify parameters ' + str(e) + ': error:' + str(exc_type) + ' ' + str(fname) + ' ' + str(exc_tb.tb_lineno) + ' ' + str(kwargs))

        # If error is detected, return error message to be logged on the queue.log files
        if 'message' in params.keys():
            return params

        # Force Tag if they don't exist. DO NOT DELETE them or host won't be able to be registered by nodes_manager.py
        tags = params['tags']

        if params['keep_forever'] is True:
            cfn_stack_name = aligo_configuration['ClusterId'] + '-keepforever-' + params['queue'] + '-' + params['stack_uuid']
            tags['soca:KeepForever'] = 'true'
        else:
            cfn_stack_name = aligo_configuration['ClusterId'] + '-job-' + str(params['job_id'])
            tags['soca:KeepForever'] = 'false'

        if 'soca:NodeType' not in tags.keys():
            tags['soca:NodeType'] = 'soca-compute-node'

        if 'soca:ClusterId' not in tags.keys():
            tags['soca:ClusterId'] = aligo_configuration['ClusterId']

        if 'soca:JobId' not in tags.keys():
            tags['soca:JobId'] = params['job_id']

        if 'Name' not in tags.keys():
            tags['Name'] = cfn_stack_name.replace('_', '-')

        # List Parameters, retrieve values and set Default value if needed
        parameters_list = {
            'BaseOS': {
                'Key': 'base_os',
                'Default': aligo_configuration['BaseOS'],
            },
            'ClusterId': {
                'Key': None,
                'Default': aligo_configuration['ClusterId'],
            },
            'ComputeNodeInstanceProfileArn': {
                'Key': None,
                'Default': aligo_configuration['ComputeNodeInstanceProfileArn'],
            },
            'CoreCount': {
                'Key': 'core_count',
                'Default': None,
            },
            'DesiredCapacity': {
                'Key': 'desired_capacity',
                'Default': None,
            },
            'Efa': {
                'Key': 'efa_support',
                'Default': False,
            },
            'EFSAppsDns': {
                'Key': None,
                'Default': aligo_configuration['EFSAppsDns'],
            },
            'EFSDataDns': {
                'Key': None,
                'Default': aligo_configuration['EFSDataDns'],
            },
            'FSxLustreConfiguration': {
                'Key': 'fsx_lustre_configuration',
                'Default': False
            },
            'ImageId': {
                'Key': 'instance_ami',
                'Default': aligo_configuration['CustomAMI']
            },
            'InstanceType': {
                'Key': 'instance_type',
                'Default': None
            },
            'JobId': {
                'Key': 'job_id',
                'Default': None
            },
            'JobName': {
                'Key': 'job_name',
                'Default': None
            },
            'JobOwner': {
                'Key': 'job_owner',
                'Default': None
            },
            'JobProject': {
                'Key': 'job_project',
                'Default': None
            },
            'JobQueue': {
                'Key': 'queue',
                'Default': None
            },
            'KeepEbs': {
                'Key': 'keep_ebs',
                'Default': False
            },
            'KeepForever': {
                'Key': 'keep_forever',
                'Default': False
            },
            'MetricCollectionAnonymous': {
                'Key': 'anonymous_metrics',
                'Default': aligo_configuration["DefaultMetricCollection"]
            },

            'PlacementGroup': {
                'Key': 'placement_group',
                'Default': True
            },
            'RootSize': {
                'Key': 'root_size',
                'Default': 10
            },
            'S3Bucket': {
                'Key': None,
                'Default': aligo_configuration['S3Bucket']
            },
            'S3InstallFolder': {
                'Key': None,
                'Default': aligo_configuration['S3InstallFolder']
            },
            'SchedulerPrivateDnsName': {
                'Key': None,
                'Default': aligo_configuration['SchedulerPrivateDnsName']
            },
            'ScratchSize': {
                'Key': 'scratch_size',
                'Default': 0
            },
            'SecurityGroupId': {
                'Key': None,
                'Default': aligo_configuration['ComputeNodeSecurityGroup']
            },
            'SchedulerHostname': {
                'Key': None,
                'Default': aligo_configuration['SchedulerPrivateDnsName']
            },
            'SolutionMetricLambda': {
                'Key': None,
                'Default': aligo_configuration['SolutionMetricLambda']
            },
            'SpotAllocationCount': {
                'Key': 'spot_allocation_count',
                'Default': False
            },
            'SpotAllocationStrategy': {
                'Key': 'spot_allocation_strategy',
                'Default': 'lowest-price'
            },
            'SpotPrice': {
                'Key': 'spot_price',
                'Default': False
            },
            'SSHKeyPair': {
                'Key': None,
                'Default': aligo_configuration['SSHKeyPair']
            },
            'StackUUID': {
                'Key': None,
                'Default': params['stack_uuid']
            },
            'SubnetId': {
                'Key': 'subnet_id',
                'Default': None
            },
            'ThreadsPerCore': {
                'Key': 'ht_support',
                'Default': False
            },
            'Version': {
                'Key': None,
                'Default': aligo_configuration['Version']
            },
            'VolumeTypeIops': {
                'Key': 'scratch_iops',
                'Default': 0
            },
        }

        cfn_stack_parameters = {}
        for k, v in parameters_list.items():
            if v['Key'] is not None:
                if v['Key'] not in params.keys():
                    cfn_stack_parameters[k] = v['Default']
                else:
                    cfn_stack_parameters[k] = params[v['Key']]
            else:
                if v['Default'] is None:
                    error = return_message('Unable to detect value for ' + k)
                    return error
                else:
                    cfn_stack_parameters[k] = v['Default']

        cfn_stack_body = cloudformation_builder.main(**cfn_stack_parameters)
        if cfn_stack_body['success'] is False:
            return return_message(cfn_stack_body['output'])
        cfn_stack_tags = [{'Key': str(k), 'Value': str(v)} for k, v in tags.items() if v]

        # Dry Run
        can_launch = can_launch_capacity(cfn_stack_parameters['InstanceType'],
                                         cfn_stack_parameters['DesiredCapacity'],
                                         cfn_stack_parameters['ImageId'],
                                         cfn_stack_parameters['SubnetId'][0])

        if can_launch is True:
            try:
                cloudformation.create_stack(
                    StackName=cfn_stack_name,
                    TemplateBody=cfn_stack_body['output'],
                    Tags=cfn_stack_tags)

                return {'success': True,
                        'stack_name': cfn_stack_name,
                        'compute_node': 'job'+str(params['job_id'])
                        }

            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                return return_message(str(e) + ': error:' + str(exc_type) + ' ' + str(fname) + ' ' + str(exc_tb.tb_lineno) + ' ' + str(kwargs))

        else:
            return return_message('Dry Run failed: ' + str(can_launch))
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        return return_message(str(e) + ': error:' + str(exc_type) + ' ' + str(fname) + ' ' + str(exc_tb.tb_lineno) + ' ' + str(kwargs))

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    # Required
    parser.add_argument('--desired_capacity', nargs='?', required=True, help="Number of EC2 instances to deploy")
    parser.add_argument('--instance_type', nargs='?', required=True, help="Instance type you want to deploy")
    parser.add_argument('--job_name', nargs='?', required=True, help="Job Name for which the capacity is being provisioned")
    parser.add_argument('--job_owner', nargs='?', required=True, help="Job Owner for which the capacity is being provisioned")
    parser.add_argument('--queue', nargs='?', required=True, help="Queue to map the capacity")

    # Const
    parser.add_argument('--efa_support', default=False, help="Support for EFA")
    parser.add_argument('--ht_support', default=False, help="Enable Hyper Threading")
    parser.add_argument('--keep_forever', default=False, help="Whether or not capacity will stay forever")

    # Optional
    parser.add_argument('--base_os', default=False, help="Specify custom Base OK")
    parser.add_argument('--fsx_lustre', default=False, help="Mount existing FSx by providing the DNS")
    parser.add_argument('--fsx_lustre_size', default=False, help="Specify size of your FSx")
    parser.add_argument('--instance_ami', required=True, nargs='?', help="AMI to use")
    parser.add_argument('--job_id', nargs='?', help="Job ID for which the capacity is being provisioned")
    parser.add_argument('--job_project', nargs='?', default=False, help="Job Owner for which the capacity is being provisioned")
    parser.add_argument('--placement_group', default=True, help="Enable or disable placement group")
    parser.add_argument('--root_size', default=10, nargs='?', help="Size of Root partition in GB")
    parser.add_argument('--scratch_iops', default=0, nargs='?', help="Size of /scratch in GB")
    parser.add_argument('--scratch_size', default=0, nargs='?', help="Size of /scratch in GB")
    parser.add_argument('--spot_allocation_count', default=False, nargs='?', help="When using mixed OD and SPOT, choose %% of SPOT")
    parser.add_argument('--spot_allocation_strategy', default=False, nargs='?', help="lowest-cost or capacity-optimized")
    parser.add_argument('--spot_price', nargs='?', default=False, help="Spot Price")
    parser.add_argument('--keep_ebs', action='store_const', const=True, default=False, help="Do not delete EBS disk")
    parser.add_argument('--subnet_id', default=False, help='Launch capacity in a special subnet')
    parser.add_argument('--tags', nargs='?', help="Tags, format must be {'Key':'Value'}")

    arg = parser.parse_args()
    launch = main(**dict(arg._get_kwargs()))
    if launch['success'] is True:
        if (arg.keep_forever).lower() == 'true':
            print("""
            IMPORTANT:
            You specified --keep-forever flag. This instance will be running 24/7 until you MANUALLY terminate the Cloudformation Stack  
            """)
    else:
        print('Error: ' + str(launch))
