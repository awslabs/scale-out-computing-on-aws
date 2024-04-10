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

import os
import random
import sys
import boto3

sys.path.append(os.path.dirname(__file__))
import configuration


def get_ec2_dcv_instances(cluster_id: str):
    _instance_list = {}

    print(f"Determining DCV instances for cluster_id: {cluster_id}")
    _ec2_paginator = ec2_client.get_paginator("describe_instances")
    _ec2_iterator = _ec2_paginator.paginate(
        Filters=[
            {
                "Name": "instance-state-name",
                "Values": [
                    "running",
                ],
            },
            {
                "Name": "tag:soca:NodeType",
                "Values": ["dcv"]
            },
            {
                "Name": "tag:soca:ClusterId",
                "Values": [cluster_id]
            },
        ],
    )

    for _page in _ec2_iterator:
        for _reservation in _page.get("Reservations", {}):
            for _instance in _reservation.get("Instances", {}):
                _private_dns = _instance.get("PrivateDnsName", "unknown.unknown").split(".")[0]
                if _private_dns:
                    _instance_list[_private_dns] = {
                        "private_dns": _private_dns,
                        "alb_rule": f"/{_private_dns}/*",
                        "instance_id": _instance["InstanceId"],
                    }
                else:
                    print(f"Error: private_dns is empty for instance {_instance['InstanceId']}")

    return _instance_list


def register_instance_to_target_group(target_group_arn: str, instance_id: str) -> bool:
    print(f"Registering EC2 instance {instance_id} to TG {target_group_arn}")
    register_ec2 = elbv2_client.register_targets(
        TargetGroupArn=target_group_arn,
        Targets=[
            {
                "Id": instance_id,
            },
        ],
    )

    if register_ec2["ResponseMetadata"]["HTTPStatusCode"] == 200:
        print(f"EC2 instance {instance_id} registered to TG {target_group_arn}")
        return True
    else:
        print(f"Error: EC2 instance {instance_id} not registered to TG {target_group_arn}")
        print(register_ec2)
        return False


def create_new_target_group(instance_dns: str, vpc_id: str, instance_id: str, cluster_id: str):
    print(f"Creating new target group for {instance_dns}")
    new_target_group = elbv2_client.create_target_group(
        Name=f"soca-{instance_dns}",
        Protocol="HTTPS",
        Port=8443,
        VpcId=vpc_id,
        HealthCheckProtocol="HTTPS",
        HealthCheckPort="8443",
        HealthCheckEnabled=True,
        HealthCheckPath=f"/{instance_dns}/",
        HealthCheckIntervalSeconds=30,
        HealthCheckTimeoutSeconds=5,
        HealthyThresholdCount=2,
        UnhealthyThresholdCount=2,
        Matcher={
            "HttpCode": "200"
        },
        TargetType="instance",
    )
    if new_target_group["ResponseMetadata"]["HTTPStatusCode"] == 200:
        elbv2_client.add_tags(
            ResourceArns=[
                new_target_group["TargetGroups"][0]["TargetGroupArn"],
            ],
            Tags=[
                {"Key": "soca:ClusterId", "Value": cluster_id},
            ],
        )
        return new_target_group["TargetGroups"][0]["TargetGroupArn"]
    else:
        return False


def create_new_alb_rule(
    instance_dns: str, target_group_arn: str, current_priority_rules, listener_arn: str
):
    #
    min_priority = 10_000

    # adjust this value if your AWS account allow more than 100 rules per alb
    # TODO - Check the existing rules and determine a spot to insert
    max_priority = 40_000
    _priority_spacing = 10

    priority = random.randint(min_priority, max_priority)
    print(f"Checking if priority {priority} is available")
    # print("List of rules already taken" + str(current_priority_rules))
    while priority in current_priority_rules:
        priority = random.randint(min_priority, max_priority)
    print("Available priority for this rule: " + str(priority))
    new_target_group = elbv2_client.create_rule(
        ListenerArn=listener_arn,
        Priority=int(priority),
        Conditions=[
            {
                "Field": "path-pattern",
                "Values": [
                    f"/{instance_dns}/*"
                ]
            }
        ],
        Actions=[
            {
                "Type": "forward",
                "TargetGroupArn": target_group_arn
            }
        ],
    )

    print(new_target_group)


def get_current_listener_rules(listener_arn: str):
    rules = {}
    priority_taken = []
    for rule in elbv2_client.describe_rules(ListenerArn=listener_arn)["Rules"]:
        if rule["Priority"] != "default" and rule["Priority"] != "1":
            priority_taken.append(int(rule["Priority"]))
            for condition in rule["Conditions"]:
                condition_list = []
                for value in condition["Values"]:
                    condition_list.append(value)

                rules[rule["RuleArn"]] = condition_list

    return {"rules": rules, "priority_taken": priority_taken}


def get_current_target_groups(alb_arn: str):
    _target_groups = {}
    print(f"Getting current target groups for ELB {alb_arn}")

    elb_paginator = elbv2_client.get_paginator("describe_target_groups")
    elb_iterator = elb_paginator.paginate(LoadBalancerArn=alb_arn)

    for _page in elb_iterator:
        for _tg in _page.get("TargetGroups", {}):
            if _tg:
                # print(f"Found target group {_tg['TargetGroupName']}")
                _target_groups[_tg["TargetGroupName"]] = _tg["TargetGroupArn"]

    return _target_groups


def delete_target_groups(target_group_arn: str):
    print(f"Deleting target group: {target_group_arn}")
    elbv2_client.delete_target_group(TargetGroupArn=target_group_arn)
    # TODO - error checking
    # TODO - return values


def delete_rule(rule_arn: str):
    print(f"Deleting ELB rule {rule_arn}")
    elbv2_client.delete_rule(RuleArn=rule_arn)


def return_alb_listener(alb_arn: str):
    get_listener_arn = False
    for listener in elbv2_client.describe_listeners(LoadBalancerArn=alb_arn)[
        "Listeners"
    ]:
        if listener["Port"] == 443:
            get_listener_arn = listener["ListenerArn"]
    return get_listener_arn


if __name__ == "__main__":
    soca_configuration = configuration.get_soca_configuration()
    cluster_id = soca_configuration.get("ClusterId")
    vpc_id = soca_configuration.get("VpcId")
    alb_arn = soca_configuration.get("LoadBalancerArn")
    #
    # TODO - make sure our cluster_id, vpc_id, alb_arn are correct before client init

    elbv2_client = boto3.client("elbv2", config=configuration.boto_extra_config())
    ec2_client = boto3.client("ec2", config=configuration.boto_extra_config())

    listener_arn = return_alb_listener(alb_arn)
    dcv_instances = get_ec2_dcv_instances(cluster_id)
    current_target_groups = get_current_target_groups(alb_arn)
    alb_listener_rules = get_current_listener_rules(listener_arn)

    alb_rules = alb_listener_rules["rules"]
    alb_rules_dns = []
    for entry in alb_rules.values():
        alb_rules_dns.append(entry[0])
    alb_priority_taken = alb_listener_rules["priority_taken"]

    # First, let's add any new instance to ALB. Create TG/Rules if needed
    print("Checking if new DCV hosts need to be added  ...")
    for instance_dns, instance_data in dcv_instances.items():
        if instance_data["alb_rule"] in alb_rules_dns:
            print(
                instance_dns + " already registered to the load balancer. Nothing to do"
            )
        else:
            print(instance_dns + " not in load balancer. Adding new entry ... ")
            if instance_dns not in current_target_groups.keys():
                print("Target Group does not exist, creating Target Group first ...")
                new_tg = create_new_target_group(
                    instance_dns, vpc_id, instance_data["instance_id"], cluster_id
                )
                if new_tg is not False:
                    new_registration = register_instance_to_target_group(
                        new_tg, instance_data["instance_id"]
                    )
                    if new_registration is not False:
                        create_new_alb_rule(
                            instance_dns, new_tg, alb_priority_taken, listener_arn
                        )

            else:
                print("Target Group already exist")
                new_tg = current_target_groups[instance_dns]
                if new_tg is not False:
                    new_registration = register_instance_to_target_group(
                        new_tg, instance_data["instance_id"]
                    )
                    if new_registration is not False:
                        create_new_alb_rule(
                            instance_dns, new_tg, alb_priority_taken, listener_arn
                        )

    print("Check Complete")
    # Then, let's do some cleaning
    print("Cleaning old rules start ...")
    for current_rule in alb_rules_dns:
        # transform /ip-180-0-172-39/* in ip-180-0-172-39
        instance_dns = current_rule.replace("/", "").replace("*", "")
        if instance_dns not in dcv_instances.keys():
            print(
                current_rule
                + " is pointing to an EC2 resource which does not exist anymore"
            )
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
    print("Cleaning complete")
