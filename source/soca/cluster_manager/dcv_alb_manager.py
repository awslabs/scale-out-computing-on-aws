'''
This Script Manage ALB rules for DCV hosts
'''

import os
import random
import sys

import boto3

sys.path.append(os.path.dirname(__file__))
import configuration


def get_ec2_graphical_instances(cluster_id):
    instance_list = {}
    token = True
    next_token = ''
    while token is True:
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
                    'Values': ['dcv']
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
                private_dns = instance['PrivateDnsName'].split('.')[0]
                instance_list[private_dns] = {'private_dns': private_dns,
                                              'alb_rule': '/'+private_dns+'/*',
                                              'instance_id': instance['InstanceId']
                                              }

    return instance_list


def register_instance_to_target_group(target_group_arn, instance_id):
    print('Registering EC2 instance ' + instance_id + ' to TG '+ target_group_arn)
    register_ec2 = elbv2_client.register_targets(
        TargetGroupArn=target_group_arn,
        Targets=[
            {
                'Id': instance_id,
            },
        ])

    if register_ec2['ResponseMetadata']['HTTPStatusCode'] == 200:
        return True
    else:
        return False

def create_new_target_group(instance_dns, vpc_id, instance_id,cluster_id):
    print('Creating new target group for ' + instance_dns)
    new_target_group = elbv2_client.create_target_group(
        Name='soca-'+instance_dns,
        Protocol='HTTPS',
        Port=8443,
        VpcId=vpc_id,
        HealthCheckProtocol='HTTPS',
        HealthCheckPort='8443',
        HealthCheckEnabled=True,
        HealthCheckPath='/' + instance_dns + '/',
        HealthCheckIntervalSeconds=30,
        HealthCheckTimeoutSeconds=5,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
        Matcher={
            'HttpCode': '200'
        },
        TargetType='instance'
    )
    if new_target_group['ResponseMetadata']['HTTPStatusCode'] == 200:
        elbv2_client.add_tags(
            ResourceArns=[
                new_target_group['TargetGroups'][0]['TargetGroupArn'],
            ],
            Tags=[
                {
                    'Key': 'soca:ClusterId',
                    'Value': cluster_id
                },
            ]
        )
        return new_target_group['TargetGroups'][0]['TargetGroupArn']
    else:
        return False


def create_new_alb_rule(instance_dns, target_group_arn, current_priority_rules, listener_arn):
    min_priority = 1
    max_priority = 100  # adjust this value if your AWS account allow more than 100 rules per alb
    priority = random.randint(min_priority, max_priority)
    print('Checking if priority ' + str(priority) + ' is available')
    #print("List of rules already taken" + str(current_priority_rules))
    while priority in current_priority_rules:
        priority = random.randint(min_priority, max_priority)
    print("Available priority for this rule: " + str(priority))
    new_target_group = elbv2_client.create_rule(ListenerArn=listener_arn,
                             Priority=int(priority),
                             Conditions=[
                                {
                                    'Field': 'path-pattern',
                                    'Values': ['/' + instance_dns + '/*']
                             }],
                             Actions=[
                                {
                                    'Type': 'forward',
                                    'TargetGroupArn': target_group_arn
                            }]
    )

    print(new_target_group)


def get_current_listener_rules(listener_arn):
    rules = {}
    priority_taken = []
    for rule in elbv2_client.describe_rules(ListenerArn=listener_arn)['Rules']:
        if rule['Priority'] != 'default':
            priority_taken.append(int(rule['Priority']))
            for condition in rule['Conditions']:
                condition_list = []
                for value in condition['Values']:
                    condition_list.append(value)

                rules[rule['RuleArn']] = condition_list

    return {'rules': rules,
            'priority_taken': priority_taken }


def get_current_target_groups(alb_arn):
    target_groups = {}
    for tg in elbv2_client.describe_target_groups(PageSize=400)['TargetGroups']:
        if not tg['LoadBalancerArns']:
            pass
        else:
            if tg['LoadBalancerArns'][0] == alb_arn:
                target_groups[tg['TargetGroupName']] = tg['TargetGroupArn']
    return target_groups


def delete_target_groups(target_group_arn):
    print('Deleting target group: ' + target_group_arn)
    elbv2_client.delete_target_group(TargetGroupArn=target_group_arn)


def delete_rule(rule_arn):
    print('Deleting ELB rule ' + rule_arn)
    elbv2_client.delete_rule(RuleArn=rule_arn)


def return_alb_listener(alb_arn):
    get_listener_arn = False
    for listener in elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)['Listeners']:
        if listener['Port'] == 443:
            get_listener_arn = listener['ListenerArn']
    return get_listener_arn


if __name__ == "__main__":
    aligo_configuration = configuration.get_aligo_configuration()
    cluster_id = aligo_configuration['ClusterId']
    vpc_id = aligo_configuration['VpcId']
    alb_arn = aligo_configuration['LoadBalancerArn']
    elbv2_client = boto3.client('elbv2')
    ec2_client = boto3.client('ec2')
    dcv_queues = ['desktop']

    listener_arn = return_alb_listener(alb_arn)
    graphical_instances = get_ec2_graphical_instances(cluster_id)
    current_target_groups = get_current_target_groups(alb_arn)
    alb_listener_rules = get_current_listener_rules(listener_arn)
    alb_rules = alb_listener_rules['rules']
    alb_rules_dns = []
    for entry in alb_rules.values():
        alb_rules_dns.append(entry[0])
    alb_priority_taken = alb_listener_rules['priority_taken']

    # First, let's add any new instance to ALB. Create TG/Rules if needed
    print('Checking if new DCV hosts need to be added  ...')
    for instance_dns, instance_data in graphical_instances.items():
        if instance_data['alb_rule'] in alb_rules_dns:
            print(instance_dns + ' already registered to the load balancer. Nothing to do')
        else:
            print(instance_dns + ' not in load balancer. Adding new entry ... ')
            if instance_dns not in current_target_groups.keys():
                print('Target Group does not exist, creating Target Group first ...')
                new_tg = create_new_target_group(instance_dns, vpc_id, instance_data['instance_id'],cluster_id)
                if new_tg is not False:
                    new_registration = register_instance_to_target_group(new_tg, instance_data['instance_id'])
                    if new_registration is not False:
                        create_new_alb_rule(instance_dns, new_tg, alb_priority_taken, listener_arn)

            else:
                print('Target Group already exist')
                new_tg = current_target_groups[instance_dns]
                if new_tg is not False:
                    new_registration = register_instance_to_target_group(new_tg, instance_data['instance_id'])
                    if new_registration is not False:
                        create_new_alb_rule(instance_dns, new_tg, alb_priority_taken, listener_arn)

    print('Check Complete')
    # Then, let's do some cleaning
    print('Cleaning old rules start ...')
    for current_rule in alb_rules_dns:
        # transform /ip-180-0-172-39/* in ip-180-0-172-39
        instance_dns = current_rule.replace('/', '').replace('*', '')
        if instance_dns not in graphical_instances.keys():
            print(current_rule + ' is pointing to an EC2 resource which does not exist anymore')
            for rule_arn, rule_path in alb_rules.items():
                try:
                    if current_rule in rule_path:
                        delete_rule(rule_arn)
                        tg_arn_to_delete = current_target_groups["soca-" + instance_dns]
                        delete_target_groups(tg_arn_to_delete)
                except Exception as err:
                    # handle case where TG is already deleted
                    print(err)
                    pass
    print('Cleaning complete')