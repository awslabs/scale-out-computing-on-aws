#!/usr/bin/env python3

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

"""
Do not trigger cdk deploy manually. Instead run ./soca_installer.sh.
All variables will be retrieved dynamically
"""

import cdk_construct_user_customization
from aws_cdk import core
import boto3
import os
import datetime
from aws_cdk import (
    aws_directoryservice as ds,
    aws_efs as efs,
    aws_ec2 as ec2,
    aws_elasticsearch as elasticsearch,
    aws_elasticloadbalancingv2 as elbv2,
    aws_events as events,
    aws_fsx as fsx,
    aws_lambda as aws_lambda,
    aws_logs as logs,
    aws_iam as iam,
    aws_backup as backup,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_sns as sns,
    aws_secretsmanager as secretsmanager,
    aws_route53resolver as route53resolver,
    core as cdk)
import json
import sys
import yaml
import base64
import ast
from yaml.scanner import ScannerError
import random
import string
from types import SimpleNamespace


def get_install_properties():
    config_file_path = f"{os.path.dirname(os.path.realpath(__file__))}/../../default_config.yml"
    try:
        config_parameters = yaml.load(open(config_file_path, 'r'), Loader=yaml.FullLoader) # nosec
    except ScannerError as err:
        print(f"{config_file_path} is not a valid YAML file. Verify syntax, {err}")
        sys.exit(1)
    except FileNotFoundError:
        print(f"{config_file_path} not found")
        sys.exit(1)
    if config_parameters:
        return config_parameters
    else:
        sys.exit("No parameters were specified.")


class SOCAInstall(cdk.Stack):
    def __init__(self, scope: cdk.Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)

        # Init SOCA resources
        self.soca_resources = {
            "acm_certificate_lambda_role": None,
            "alb": None,
            "backup_role": None,
            "compute_node_instance_profile": None,
            "compute_node_role": None,
            "compute_node_sg": None,
            "directory_service": None,
            "ami_id": user_specified_variables.custom_ami if user_specified_variables.custom_ami else install_props.RegionMap.__dict__[user_specified_variables.region].__dict__[user_specified_variables.base_os],
            "es_custom_resource": None,
            "es_domain": None,
            "fs_apps": None,
            "fs_apps_lambda_role": None,
            "fs_data": None,
            "get_es_private_ip_lambda_role": None,
            "nat_gateway_ips": [],
            "reset_ds_password_lambda_role": None,
            "reset_ds_lambda": None,
            "scheduler_eip": None,
            "scheduler_instance": None,
            "scheduler_role": None,
            "scheduler_sg": None,
            "spot_fleet_role": None,
            "solution_metrics_lambda_role": None,
            "soca_config": None,
            "vpc": None}

        # Create SOCA environment
        self.generic_resources()
        self.network()  # Create Network environment
        self.security_groups()  # Create Security Groups
        self.iam_roles()  # Create IAM roles and policies for primary roles needed to deploy resources
        if install_props.Config.network.use_vpc_endpoints:
            print("Creating vpc endpoints")
            self.create_vpc_endpoints()
        self.storage()  # Create Storage backend
        if install_props.Config.directoryservice.provider == "activedirectory" and not user_specified_variables.directory_service_id:
            self.directoryservice()  # Create Directory Service
        self.analytics()  # Create ElasticSearch domain
        self.scheduler()  # Configure the Scheduler
        self.viewer()  # Configure the DCV Load Balancer
        self.secretsmanager()  # Store SOCA config on Secret Manager
        self.backups()  # Configure AWS Backup & Restore

        # User customization (Post Configuration)
        cdk_construct_user_customization.main(self, self.soca_resources)

    def generic_resources(self):

        # Tag EC2 resources that don't support tagging in cloudformation
        self.tag_ec2_resource_lambda = aws_lambda.Function(
            self, f"{user_specified_variables.cluster_id}-TagEC2ResourceLambda",
            function_name=f"{user_specified_variables.cluster_id}-TagEC2Resource",
            description="Tag EC2 resource that doesn't support tagging in CloudFormation",
            memory_size=128,
            runtime=aws_lambda.Runtime.PYTHON_3_7,
            timeout=core.Duration.minutes(1),
            log_retention=logs.RetentionDays.INFINITE,
            handler="TagEC2ResourceLambda.lambda_handler",
            code=aws_lambda.Code.asset("../functions/TagEC2ResourceLambda"))

        self.tag_ec2_resource_lambda.add_to_role_policy(
            statement=iam.PolicyStatement(
                effect=iam.Effect.ALLOW,
                actions=["ec2:CreateTags"],
                resources=['*']
            )
        )

    def network(self):
        """
        Create a VPC with 3 public and 3 private subnets.
        To save IP space, public subnets have a smaller range compared to private subnets (where we deploy compute node)

        Example: vpc_cidr: 10.0.0.0/17 --> vpc_cidr_prefix_bits = 17
        public_subnet_mask_prefix_bits = 4
        private_subnet_mask_prefix_bits = 2
        public_subnet_mask = 17 + 4 = 21
        Added condition to reduce size of public_subnet_mask to a maximum of /26
        private_SubnetMask = 17 + 2 = 19
        """
        if not user_specified_variables.vpc_id:
            vpc_cidr_prefix_bits = user_specified_variables.vpc_cidr.split("/")[1]
            public_subnet_mask_prefix_bits = 4
            private_subnet_mask_prefix_bits = 2
            public_subnet_mask = int(vpc_cidr_prefix_bits) + int(public_subnet_mask_prefix_bits)
            if public_subnet_mask < 26:
                public_subnet_mask = 26
            private_subnet_mask = int(vpc_cidr_prefix_bits) + int(private_subnet_mask_prefix_bits)

            vpc_params = {
                'cidr': user_specified_variables.vpc_cidr,
                'nat_gateways': int(install_props.Config.network.nat_gateways),
                'enable_dns_support': True,
                'enable_dns_hostnames': True,
                'max_azs': int(install_props.Config.network.max_azs),
                'subnet_configuration': [
                    ec2.SubnetConfiguration(cidr_mask=public_subnet_mask, name="Public",
                                            subnet_type=ec2.SubnetType.PUBLIC),
                    ec2.SubnetConfiguration(cidr_mask=private_subnet_mask, name="Private",
                                            subnet_type=ec2.SubnetType.PRIVATE)
                ]
            }
            if install_props.Config.network.vpc_flow_logs:
                vpc_params['flow_logs'] = [ec2.FlowLogOptions()]
            self.soca_resources["vpc"] = ec2.Vpc(self, "SOCAVpc", **vpc_params)
            core.Tags.of(self.soca_resources["vpc"]).add("Name", f"{user_specified_variables.cluster_id}-VPC")
        else:
            # Use existing VPC
            public_subnet_ids = []
            private_subnet_ids = []
            # Note: syntax is ["subnet1,az1","subnet2,az2" ....]
            for pub_subnet in user_specified_variables.public_subnets:
                public_subnet_ids.append(pub_subnet.split(",")[0])
            for priv_subnet in user_specified_variables.private_subnets:
                private_subnet_ids.append(priv_subnet.split(",")[0])

            self.soca_resources["vpc"] = ec2.Vpc.from_vpc_attributes(self, user_specified_variables.cluster_id,
                                                                     vpc_cidr_block=user_specified_variables.vpc_cidr,
                                                                     availability_zones=user_specified_variables.vpc_azs.split(","),
                                                                     vpc_id=user_specified_variables.vpc_id,
                                                                     public_subnet_ids=public_subnet_ids,
                                                                     private_subnet_ids=private_subnet_ids)

        # Retrieve all NAT Gateways associated to the public subnets.
        for subnet_info in self.soca_resources["vpc"].public_subnets:
            nat_eip_for_subnet = subnet_info.node.try_find_child("EIP")
            if nat_eip_for_subnet:
                self.soca_resources["nat_gateway_ips"].append(nat_eip_for_subnet)

        # Create the EIP associated that will be associated to the scheduler
        if install_props.Config.entry_points_subnets.lower() == "public":
            self.soca_resources["scheduler_eip"] = ec2.CfnEIP(self, "SchedulerEIP", instance_id=None)

    def security_groups(self):
        """
        Create two security groups (or re-use existing ones), one for the compute nodes and one for the scheduler
        """
        if not user_specified_variables.compute_node_sg:
            self.soca_resources["compute_node_sg"] = ec2.SecurityGroup(self, "ComputeNodeSG", vpc=self.soca_resources["vpc"], allow_all_outbound=False, description="Security Group used for all compute nodes")
            # We do not use `security_group_name` as it's not recommended in case you plan to do UPDATE_TEMPLATE in the future. We assign a Name tag instead
            core.Tags.of(self.soca_resources["compute_node_sg"]).add("Name", f"{user_specified_variables.cluster_id}-ComputeNodeSG")
        else:
            self.soca_resources["compute_node_sg"] = ec2.SecurityGroup.from_security_group_id(self, "ComputeNodeSG", security_group_id=user_specified_variables.compute_node_sg)

        if not user_specified_variables.scheduler_sg:
            self.soca_resources["scheduler_sg"] = ec2.SecurityGroup(self, "SchedulerSG", vpc=self.soca_resources["vpc"], allow_all_outbound=False, description="Security Group used for the scheduler host and ELB")
            # We do not use `security_group_name` as it's not recommended in case you plan to do UPDATE_TEMPLATE in the future. We assign a Name tag instead
            core.Tags.of(self.soca_resources["scheduler_sg"]).add("Name", f"{user_specified_variables.cluster_id}-SchedulerSG")
        else:
            self.soca_resources["scheduler_sg"] = ec2.SecurityGroup.from_security_group_id(self, "SchedulerSG", security_group_id=user_specified_variables.scheduler_sg)

        if not user_specified_variables.vpc_endpoint_sg:
            self.soca_resources["vpc_endpoint_sg"] = ec2.SecurityGroup(self, "VpcEndpointSG", vpc=self.soca_resources["vpc"], allow_all_outbound=False, description="VpcEndpoint")
            # We do not use `security_group_name` as it's not recommended in case you plan to do UPDATE_TEMPLATE in the future
            # Instead we simply assign a Name tag
            core.Tags.of(self.soca_resources["vpc_endpoint_sg"]).add("Name", f"{user_specified_variables.cluster_id}-VpcEndpointSG")
        else:
            self.soca_resources["vpc_endpoint_sg"] = ec2.SecurityGroup.from_security_group_id(self, "VpcEndpointSG", security_group_id=user_specified_variables.vpc_endpoint_sg, allow_all_outbound=False)

        # Add rules. Ignore if already exist (in case you re-use existing SGs)
        # Ingress
        self.soca_resources["compute_node_sg"].add_ingress_rule(ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block), ec2.Port.tcp_range(0, 65535), description="VPC - allow all TCP traffic from VPC to compute nodes")
        self.soca_resources["compute_node_sg"].add_ingress_rule(self.soca_resources["scheduler_sg"], ec2.Port.tcp_range(0, 65535), description="SchedulerSG - allow all tcp traffic from scheduler to compute")
        self.soca_resources["compute_node_sg"].add_ingress_rule(self.soca_resources["compute_node_sg"], ec2.Port.all_traffic(), description="ComputeNodeSG - allow all traffic between compute nodes and EFA")
        #Egress
        self.soca_resources["compute_node_sg"].add_egress_rule(self.soca_resources["compute_node_sg"], ec2.Port.all_traffic(), description="ComputeNodeSG - allow all traffic between compute nodes and EFA")
        self.soca_resources["compute_node_sg"].add_egress_rule(ec2.Peer.ipv4("0.0.0.0/0"), ec2.Port.tcp_range(0, 65535), description="Allow all egress")

        # Ingress
        self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block), ec2.Port.tcp_range(0, 65535), description="Allow all TCP traffic from VPC to scheduler")
        self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.ipv4(user_specified_variables.client_ip), ec2.Port.tcp(22), description="Allow SSH access from customer IP to scheduler")
        self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.ipv4(user_specified_variables.client_ip), ec2.Port.tcp(443), description="Allow HTTPS access from customer IP to scheduler")
        self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.ipv4(user_specified_variables.client_ip), ec2.Port.tcp(80), description="Allow HTTP access from customer IP to scheduler")
        if user_specified_variables.prefix_list_id:
            self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.prefix_list(user_specified_variables.prefix_list_id), ec2.Port.tcp(22), description="Allow SSH access from customer IPs to scheduler")
            self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.prefix_list(user_specified_variables.prefix_list_id), ec2.Port.tcp(443), description="Allow HTTPS access from customer IPs to scheduler")
            self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.prefix_list(user_specified_variables.prefix_list_id), ec2.Port.tcp(80), description="Allow HTTP access from customer IPs to scheduler")
        self.soca_resources["scheduler_sg"].add_ingress_rule(self.soca_resources["compute_node_sg"], ec2.Port.tcp_range(0, 65535), description="Allow all traffic from compute nodes to scheduler")
        self.soca_resources["scheduler_sg"].add_ingress_rule(self.soca_resources["scheduler_sg"], ec2.Port.tcp(8443), description="Allow ELB healthcheck to communicate with the UI")
        if install_props.Config.entry_points_subnets.lower() == "public":
            self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.ipv4(f"{self.soca_resources['scheduler_eip'].ref}/32"), ec2.Port.tcp(443), description=f"Allow HTTPS traffic from Scheduler to ELB to validate DCV sessions")

        for nat_eip in self.soca_resources["nat_gateway_ips"]:
            self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.ipv4(f"{nat_eip.ref}/32"), ec2.Port.tcp(443), description=f"Allow NAT EIP to communicate to ELB/Scheduler")

        # Egress
        self.soca_resources["scheduler_sg"].add_egress_rule(ec2.Peer.ipv4("0.0.0.0/0"), ec2.Port.tcp_range(0, 65535), description="Allow all Egress TCP traffic for Scheduler SG")

        # Special rules are needed when using AWS Directory Services
        if install_props.Config.directoryservice.provider == "activedirectory":
            self.soca_resources["compute_node_sg"].add_ingress_rule(ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block), ec2.Port.udp_range(0, 1024), description="Allow all UDP traffic from VPC to compute. Required for Directory Service")
            self.soca_resources["compute_node_sg"].add_egress_rule(ec2.Peer.ipv4("0.0.0.0/0"), ec2.Port.udp_range(0, 1024), description="Allow all Egress UDP traffic for ComputeNode SG. Required for Directory Service")
            self.soca_resources["scheduler_sg"].add_ingress_rule(ec2.Peer.ipv4(self.soca_resources["vpc"].vpc_cidr_block), ec2.Port.udp_range(0, 1024), description="Allow all UDP traffic from VPC to scheduler. Required for Directory Service")
            self.soca_resources["scheduler_sg"].add_egress_rule(ec2.Peer.ipv4("0.0.0.0/0"), ec2.Port.udp_range(0, 1024), description="Allow all Egress UDP traffic for Scheduler SG. Required for Directory Service")

    def create_vpc_endpoints(self):
        """
        Create VPC Endpoints for accessing AWS services.
        """
        self.vpc_gateway_endpoints = {}
        self.vpc_interface_endpoints = {}

        # If using an existing VPC first import any existing vpc endpoints
        if user_specified_variables.vpc_id:
            ec2_client = boto3.client("ec2", region_name=user_specified_variables.region)
            filters = [{"Name": "vpc-id", "Values": [user_specified_variables.vpc_id]}]
            existing_security_groups = {}
            for page in ec2_client.get_paginator('describe_vpc_endpoints').paginate(Filters=filters):
                for vpc_endpoint in page["VpcEndpoints"]:
                    service_name = vpc_endpoint['ServiceName']
                    short_service_name = service_name.split('.')[-1]
                    resource_name = short_service_name + "VpcEndpoint"
                    security_groups = []
                    for group in vpc_endpoint['Groups']:
                        group_id = group['GroupId']
                        security_group = existing_security_groups.get(group_id, None)
                        if not security_group:
                            group_name = group['GroupName']
                            security_group = ec2.SecurityGroup.from_security_group_id(self, group_name, group_id)
                            existing_security_groups[group_id] = security_group
                        security_groups.append(security_group)
                    print(f"Importing resource {resource_name} for {service_name} {short_service_name}")
                    if vpc_endpoint['VpcEndpointType'] == 'Gateway':
                        self.vpc_gateway_endpoints[short_service_name] = ec2.GatewayVpcEndpoint.from_gateway_vpc_endpoint_id(
                            self, resource_name,
                            gateway_vpc_endpoint_id = vpc_endpoint['VpcEndpointId']
                        )
                    elif vpc_endpoint['VpcEndpointType'] == 'Interface':
                        self.vpc_interface_endpoints[short_service_name] = ec2.InterfaceVpcEndpoint.from_interface_vpc_endpoint_attributes(
                            self, resource_name,
                            vpc_endpoint_id = vpc_endpoint['VpcEndpointId'],
                            security_groups = security_groups,
                            port = 443
                        )

        for short_service_name in install_props.Config.network.vpc_gateway_endpoints:
            endpoint_service = ec2.GatewayVpcEndpointAwsService(short_service_name)
            if short_service_name in self.vpc_gateway_endpoints:
                continue
            resource_name = f"{short_service_name}VpcEndpoint"
            print(f"Creating resource {resource_name} for {short_service_name}")
            self.vpc_gateway_endpoints[short_service_name] = self.soca_resources["vpc"].add_gateway_endpoint(
                resource_name,
                service = endpoint_service
            )
            core.CustomResource(
                self, f"{short_service_name}VPCEndpointTags",
                service_token=self.tag_ec2_resource_lambda.function_arn,
                properties={
                    "ResourceId": self.vpc_gateway_endpoints[short_service_name].vpc_endpoint_id,
                    "Tags": [
                        {"Key": "Name", "Value": f"{user_specified_variables.cluster_id}-{short_service_name}-VpcEndpoint"},
                        {"Key": 'soca:ClusterId', "Value": user_specified_variables.cluster_id}
                    ]
                }
            )

        for short_service_name in install_props.Config.network.vpc_interface_endpoints:
            endpoint_service = ec2.InterfaceVpcEndpointAwsService(short_service_name)
            if short_service_name in self.vpc_interface_endpoints:
                continue
            resource_name = f"{short_service_name}VpcEndpoint"
            print(f"Creating resource {resource_name} for {short_service_name}")
            self.vpc_interface_endpoints[short_service_name] = ec2.InterfaceVpcEndpoint(
                self, resource_name,
                vpc = self.soca_resources['vpc'],
                service = endpoint_service,
                private_dns_enabled = True,
                security_groups = [self.soca_resources["vpc_endpoint_sg"]]
            )

            core.CustomResource(
                self, f"{short_service_name}VPCEndpointTags",
                service_token=self.tag_ec2_resource_lambda.function_arn,
                properties={
                    "ResourceId": self.vpc_interface_endpoints[short_service_name].vpc_endpoint_id,
                    "Tags": [
                        {"Key": "Name", "Value": f"{user_specified_variables.cluster_id}-{short_service_name}-VpcEndpoint"},
                        {"Key": 'soca:ClusterId', "Value": user_specified_variables.cluster_id}
                    ]
                }
            )

        for short_service_name, vpc_endpoint in self.vpc_interface_endpoints.items():
            # Ingress
            vpc_endpoint.connections.allow_from(self.soca_resources["compute_node_sg"], ec2.Port.tcp(443), "ComputeNodeSG to VpcEndpointSG - allow https traffic to vpc endpoints")
            vpc_endpoint.connections.allow_from(self.soca_resources["scheduler_sg"], ec2.Port.tcp(443), "SchedulerSG to VpcEndpointSG - allow https traffic to vpc endpoints")

    def iam_roles(self):
        """
        Configure IAM roles & policies for the various resources
        """
        # Specify if customers want to re-use existing IAM role for scheduler/compute nodes/spotfleet
        if user_specified_variables.scheduler_role_name:
            use_existing_roles = True
        else:
            use_existing_roles = False

        # Create IAM roles
        self.soca_resources["backup_role"] = iam.Role(self, 'BackupRole', description="IAM role to manage AWS Backup & Restore jobs", assumed_by=iam.ServicePrincipal(principals_suffix["backup"]))
        self.soca_resources["acm_certificate_lambda_role"] = iam.Role(self, 'ACMCertificateLambdaRole', description="IAM role assigned to the ACMCertificate Lambda function", assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]))
        self.soca_resources["solution_metrics_lambda_role"] = iam.Role(self, 'SolutionMetricsLambdaRole', description="IAM role assigned to the SolutionMetrics Lambda function", assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]))

        # Create Role for EFS Throughput Lambda function only when deploying a new EFS for /apps
        if not user_specified_variables.fs_apps_provider or user_specified_variables.fs_apps_provider == "efs":
            self.soca_resources["fs_apps_lambda_role"] = iam.Role(self, 'EFSAppsLambdaRole', description="IAM role assigned to the EFSApps Lambda function", assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]))

        # CreateRole for GetESPrivateIPLambdaRole when creating a new ElasticSearch
        if not user_specified_variables.es_endpoint:
            self.soca_resources["get_es_private_ip_lambda_role"] = iam.Role(self, 'GetESPrivateIPLambdaRole', description="IAM role assigned to the EFSApps Lambda function", assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]))

        if use_existing_roles is False:
            # Create Scheduler/ComputeNode/SpotFleet roles if not specified by the user
            self.soca_resources["scheduler_role"] = iam.Role(self, "SchedulerRole", description="IAM role assigned to the scheduler host", assumed_by=iam.CompositePrincipal(iam.ServicePrincipal(principals_suffix["ssm"]), iam.ServicePrincipal(principals_suffix["ec2"])))
            self.soca_resources["compute_node_role"] = iam.Role(self, "ComputeNodeRole", description="IAM role assigned to the compute nodes", assumed_by=iam.CompositePrincipal(iam.ServicePrincipal(principals_suffix["ssm"]), iam.ServicePrincipal(principals_suffix["ec2"])))
            self.soca_resources["spot_fleet_role"] = iam.Role(self, "SpotFleetRole", description="IAM role to manage SpotFleet requests", assumed_by=iam.ServicePrincipal(principals_suffix["spotfleet"]))
            self.soca_resources["compute_node_instance_profile"] = iam.CfnInstanceProfile(self, "ComputeNodeInstanceProfile", roles=[self.soca_resources["compute_node_role"].role_name])
        else:
            # Reference existing Scheduler/ComputeNode/SpotFleet roles
            self.soca_resources["scheduler_role"] = iam.Role.from_role_arn(self, "SchedulerRole", role_arn=user_specified_variables.scheduler_role_arn)
            self.soca_resources["compute_node_role"] = iam.Role.from_role_arn(self, "ComputeNodeRole", role_arn=user_specified_variables.compute_node_role_arn)
            self.soca_resources["spot_fleet_role"] = iam.Role.from_role_arn(self, "SpotFleetRole", role_arn=user_specified_variables.spotfleet_role_arn)
            self.soca_resources["compute_node_instance_profile"] = iam.CfnInstanceProfile(self, "ComputeNodeInstanceProfile", roles=[user_specified_variables.compute_node_role_name])

        # Add SSM Managed Policy
        self.soca_resources["scheduler_role"].add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))
        self.soca_resources["compute_node_role"].add_managed_policy(iam.ManagedPolicy.from_aws_managed_policy_name("AmazonSSMManagedInstanceCore"))

        # Generate IAM inline policies
        policy_substitutes = {"%%AWS_ACCOUNT_ID%%": core.Aws.ACCOUNT_ID,
                              "%%AWS_PARTITION%%": core.Aws.PARTITION,
                              "%%AWS_URL_SUFFIX%%": core.Aws.URL_SUFFIX,
                              "%%AWS_REGION%%": core.Aws.REGION,
                              "%%BUCKET%%": user_specified_variables.bucket,
                              "%%COMPUTE_NODE_ROLE_ARN%%": self.soca_resources["compute_node_role"].role_arn if not user_specified_variables.compute_node_role_arn else user_specified_variables.compute_node_role_arn,
                              "%%SCHEDULER_ROLE_ARN%%": self.soca_resources["scheduler_role"].role_arn if not user_specified_variables.scheduler_role_arn else user_specified_variables.scheduler_role_arn,
                              "%%SPOTFLEET_ROLE_ARN%%": self.soca_resources["spot_fleet_role"].role_arn if not user_specified_variables.spotfleet_role_arn else user_specified_variables.spotfleet_role_arn,
                              "%%VPC_ID%%": self.soca_resources["vpc"].vpc_id,
                              "%%CLUSTER_ID%%": user_specified_variables.cluster_id}

        policy_templates = {"ACMCertificateLambdaPolicy": {"template": "../policies/ACMCertificateLambda.json", "attach_to_role": "acm_certificate_lambda_role"},
                            "BackupPolicy": {"template": "../policies/Backup.json", "attach_to_role": "backup_role"},
                            "SolutionMetricsLambdaPolicy": {"template": "../policies/SolutionMetricsLambda.json", "attach_to_role": "solution_metrics_lambda_role"}}

        if not user_specified_variables.es_endpoint:
            policy_templates["GetESPrivateIPLambdaPolicy"] = {"template": "../policies/GetESPrivateIPLambda.json", "attach_to_role": "get_es_private_ip_lambda_role"}

        if use_existing_roles is False:
            policy_templates["ComputeNodePolicy"] = {"template": "../policies/ComputeNode.json", "attach_to_role": "compute_node_role"}
            policy_templates["SchedulerPolicy"] = {"template": "../policies/Scheduler.json", "attach_to_role": "scheduler_role"}
            policy_templates["SpotFleetPolicy"] = {"template": "../policies/SpotFleet.json", "attach_to_role": "spot_fleet_role"}
        else:
            # Append required policies if IAM specified by user have not been generated by SOCA
            if user_specified_variables.scheduler_role_from_previous_soca_deployment:
                policy_templates["SchedulerPolicyNewCluster"] = {"template": "../policies/SchedulerAppendToExistingRole.json", "attach_to_role": "scheduler_role"}
            else:
                policy_templates["SchedulerPolicyNewCluster"] = {"template": "../policies/Scheduler.json", "attach_to_role": "scheduler_role"}

            if not user_specified_variables.compute_node_role_from_previous_soca_deployment:
                policy_templates["ComputeNodePolicy"] = {"template": "../policies/ComputeNode.json", "attach_to_role": "compute_node_role"}

            if not user_specified_variables.spotfleet_role_from_previous_soca_deployment:
                policy_templates["SpotFleetPolicy"] = {"template": "../policies/SpotFleet.json", "attach_to_role": "spot_fleet_role"}

        if not user_specified_variables.fs_apps:
            policy_templates["EFSAppsLambdaPolicy"] = {"template": "../policies/EFSAppsLambda.json", "attach_to_role": "fs_apps_lambda_role"}

        # Create additional IAM Role/Policy if we use Active Directory. This role is used by ResetDsLambda
        if install_props.Config.directoryservice.provider == "activedirectory":
            self.soca_resources["reset_ds_password_lambda_role"] = iam.Role(self, 'ResetDsLambdaLambdaRole', assumed_by=iam.ServicePrincipal(principals_suffix["lambda"]))
            policy_templates["ResetDSPasswordPolicy"] = {"template": "../policies/ResetDSPassword.json", "attach_to_role": "reset_ds_password_lambda_role"}

        # Create all policies and attach them to their respective role
        for policy_name, policy_data in policy_templates.items():
            with open(policy_data["template"]) as json_file:
                policy_content = json_file.read()

            for k, v in policy_substitutes.items():
                policy_content = policy_content.replace(k, v)

            self.soca_resources[policy_data["attach_to_role"]].attach_inline_policy(iam.Policy(self, f"{user_specified_variables.cluster_id}-{policy_name}", document=iam.PolicyDocument.from_json(json.loads(policy_content))))

    def directoryservice(self):
        """
        Deploy an AWS Manage AD Directory Service
        """
        if not user_specified_variables.vpc_id:
            launch_subnets = [self.soca_resources["vpc"].private_subnets[0].subnet_id,
                              self.soca_resources["vpc"].private_subnets[1].subnet_id]
        else:
            launch_subnets = [user_specified_variables.private_subnets[0].split(",")[0],
                              user_specified_variables.private_subnets[1].split(",")[0]]

        # Create a new AWS Directory Service Managed AD
        if not user_specified_variables.directory_service_id:
            self.soca_resources["ds_domain_admin"] = "Admin"
            self.soca_resources["ds_domain_admin_password"] = f"{random.choice(string.ascii_lowercase)}{random.choice(string.digits)}{random.choice(string.ascii_uppercase)}{''.join(random.choice(string.ascii_lowercase + string.digits + string.ascii_uppercase) for i in range(20))}"
            self.soca_resources["directory_service"] = ds.CfnMicrosoftAD(self, "DSManagedAD", name=install_props.Config.directoryservice.activedirectory.name,
                                                                         edition=install_props.Config.directoryservice.activedirectory.edition,
                                                                         short_name=install_props.Config.directoryservice.activedirectory.short_name,  # NETBIOS
                                                                         password=self.soca_resources["ds_domain_admin_password"],
                                                                         vpc_settings=ds.CfnMicrosoftAD.VpcSettingsProperty(subnet_ids=launch_subnets, vpc_id=self.soca_resources["vpc"].vpc_id))

            # Create DNS Forwarder. Requests sent to AD will be forwarded to AD DNS
            # Other requests will remain the same. Do not create custom DHCP Option Set otherwise resources such as FSx or EFS won't resolve
            resolver = route53resolver.CfnResolverEndpoint(self, "ADRoute53OutboundResolver", direction="OUTBOUND",
                                                           name=user_specified_variables.cluster_id,
                                                           ip_addresses=[
                                                               route53resolver.CfnResolverEndpoint.IpAddressRequestProperty(subnet_id=launch_subnets[0]),
                                                               route53resolver.CfnResolverEndpoint.IpAddressRequestProperty(subnet_id=launch_subnets[1])],
                                                           security_group_ids=[self.soca_resources["scheduler_sg"].security_group_id,
                                                                               self.soca_resources["compute_node_sg"].security_group_id])
            resolver_rule = route53resolver.CfnResolverRule(self, "ADRoute53OutboundResolverRule",
                                                            name=user_specified_variables.cluster_id,
                                                            domain_name=install_props.Config.directoryservice.activedirectory.name,
                                                            rule_type="FORWARD",
                                                            resolver_endpoint_id=resolver.attr_resolver_endpoint_id,
                                                            target_ips=[
                                                                route53resolver.CfnResolverRule.TargetAddressProperty(ip=core.Fn.select(0, self.soca_resources["directory_service"].attr_dns_ip_addresses), port="53"),
                                                                route53resolver.CfnResolverRule.TargetAddressProperty(ip=core.Fn.select(1, self.soca_resources["directory_service"].attr_dns_ip_addresses), port="53")])

            route53resolver.CfnResolverRuleAssociation(self, "ADRoute53ResolverRuleAssociation",
                                                       resolver_rule_id=resolver_rule.attr_resolver_rule_id,
                                                       vpc_id=self.soca_resources["vpc"].vpc_id)

    def storage(self):
        """
        Create two EFS or FSx for Lustre file systems that will be mounted as /apps and /data
        aws_efs.FileSystem is experimental and we cannot add multiple SG (as of April 2021).
        Because of that we have to use CfnFilesystem
        """

        if install_props.Config.storage.apps.provider == "efs" and not user_specified_variables.fs_apps:
            self.soca_resources["fs_apps"] = efs.CfnFileSystem(self, "EFSApps", encrypted=install_props.Config.storage.apps.efs.encrypted, kms_key_id=None if install_props.Config.storage.apps.kms_key_id is False else install_props.Config.storage.apps.kms_key_id,
                                                               throughput_mode=install_props.Config.storage.apps.efs.throughput_mode,
                                                               file_system_tags=[
                                                                  efs.CfnFileSystem.ElasticFileSystemTagProperty(key="soca:BackupPlan", value=user_specified_variables.cluster_id),
                                                                  efs.CfnFileSystem.ElasticFileSystemTagProperty(key="Name", value=f"{user_specified_variables.cluster_id}-Apps")],
                                                               performance_mode=install_props.Config.storage.apps.efs.performance_mode)

            if install_props.Config.storage.apps.efs.deletion_policy.upper() == "RETAIN":
                self.soca_resources["fs_apps"].cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

        if install_props.Config.storage.data.provider == "efs" and not user_specified_variables.fs_data:
            self.soca_resources["fs_data"] = efs.CfnFileSystem(self, "EFSData", encrypted=install_props.Config.storage.data.efs.encrypted, kms_key_id=None if install_props.Config.storage.data.kms_key_id is False else install_props.Config.storage.data.kms_key_id,
                                                               throughput_mode=install_props.Config.storage.data.efs.throughput_mode,
                                                               file_system_tags=[
                                                                  efs.CfnFileSystem.ElasticFileSystemTagProperty(key="soca:BackupPlan", value=user_specified_variables.cluster_id),
                                                                  efs.CfnFileSystem.ElasticFileSystemTagProperty(key="Name", value=f"{user_specified_variables.cluster_id}-Data")],
                                                               lifecycle_policies=[efs.CfnFileSystem.LifecyclePolicyProperty(transition_to_ia=install_props.Config.storage.data.efs.transition_to_ia)],
                                                               performance_mode=install_props.Config.storage.data.efs.performance_mode)
            if install_props.Config.storage.data.efs.deletion_policy.upper() == "RETAIN":
                self.soca_resources["fs_data"].cfn_options.deletion_policy = cdk.CfnDeletionPolicy.RETAIN

        # Create the mount targets for /data
        if install_props.Config.storage.data.provider == "efs" and not user_specified_variables.fs_data:
            for i in range(len(self.soca_resources["vpc"].select_subnets(subnet_type=ec2.SubnetType.PRIVATE).subnet_ids)):
                efs.CfnMountTarget(self, f"EFSDataMountTarget{i+1}", file_system_id=self.soca_resources["fs_data"].ref,
                                   security_groups=[self.soca_resources["compute_node_sg"].security_group_id, self.soca_resources["scheduler_sg"].security_group_id],
                                   subnet_id=self.soca_resources["vpc"].select_subnets(subnet_type=ec2.SubnetType.PRIVATE).subnets[i].subnet_id)

        # Create the mount targets for /apps
        if install_props.Config.storage.apps.provider == "efs" and not user_specified_variables.fs_apps:
            for i in range(len(self.soca_resources["vpc"].select_subnets(subnet_type=ec2.SubnetType.PRIVATE).subnet_ids)):
                efs.CfnMountTarget(self, f"EFSAppsMountTarget{i+1}", file_system_id=self.soca_resources["fs_apps"].ref,
                                   security_groups=[self.soca_resources["compute_node_sg"].security_group_id, self.soca_resources["scheduler_sg"].security_group_id],
                                   subnet_id=self.soca_resources["vpc"].select_subnets(subnet_type=ec2.SubnetType.PRIVATE).subnets[i].subnet_id)

            # Create CloudWatch/SNS alarm for SNS EFS. This will check BurstCreditBalance and increase allocated throughput to support temporary burst activity if needed
            sns_efs_topic = sns.Topic(self, "SNSEFSTopic", display_name=f"{user_specified_variables.cluster_id}-EFSAlarm-SNS", topic_name=f"{user_specified_variables.cluster_id}-EFSAlarm-SNS")
            sns_efs_topic.add_to_resource_policy(iam.PolicyStatement(effect=iam.Effect.ALLOW, actions=["sns:Publish"],
                                                                     resources=[sns_efs_topic.topic_arn], principals=[iam.ServicePrincipal(principals_suffix["cloudwatch"])],
                                                                     conditions={"ArnLike": {"aws:SourceArn": f"arn:{core.Aws.PARTITION}:*:*:{core.Aws.ACCOUNT_ID}:*"}}))

            efs_apps_cw_alarm_low = cloudwatch.Alarm(self, "EFSAppsCWAlarmLowThreshold",
                                                     metric=cloudwatch.Metric(metric_name="BurstCreditBalance",
                                                     namespace="AWS/EFS", dimensions=dict(FileSystemId=self.soca_resources["fs_apps"].ref)),
                                                     comparison_operator=cloudwatch.ComparisonOperator.LESS_THAN_OR_EQUAL_TO_THRESHOLD,
                                                     evaluation_periods=10, period=core.Duration.minutes(1), statistic="Average", threshold=10000000)

            efs_apps_cw_alarm_high = cloudwatch.Alarm(self, "EFSAppsCWAlarmHighThreshold",
                                                      metric=cloudwatch.Metric(metric_name="BurstCreditBalance",
                                                      namespace="AWS/EFS", dimensions=dict(FileSystemId=self.soca_resources["fs_apps"].ref)),
                                                      comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
                                                      evaluation_periods=10, period=core.Duration.minutes(1), statistic="Average", threshold=2000000000000)
            efs_apps_cw_alarm_low.add_alarm_action(cw_actions.SnsAction(sns_efs_topic))
            efs_apps_cw_alarm_high.add_alarm_action(cw_actions.SnsAction(sns_efs_topic))

            efs_apps_throughput_lambda = aws_lambda.Function(self, f"{user_specified_variables.cluster_id}-EFSAppsLambda",
                                                             function_name=f"{user_specified_variables.cluster_id}-EFSThroughput",
                                                             description="Check EFS BurstCreditBalance and update ThroughputMode when needed",
                                                             memory_size=128, role=self.soca_resources["fs_apps_lambda_role"],
                                                             timeout=core.Duration.minutes(3),
                                                             runtime=aws_lambda.Runtime.PYTHON_3_7,
                                                             log_retention=logs.RetentionDays.INFINITE,
                                                             handler="EFSThroughputLambda.lambda_handler",
                                                             code=aws_lambda.Code.asset("../functions/EFSThroughputLambda"))
            efs_apps_throughput_lambda.add_environment("EFSBurstCreditLowThreshold", "10000000")
            efs_apps_throughput_lambda.add_environment("EFSBurstCreditHighThreshold", "2000000000000")
            efs_apps_throughput_lambda.add_permission("InvokePermission", principal=iam.ServicePrincipal(principals_suffix["sns"]), action="lambda:InvokeFunction")

            sns.Subscription(self, f"{user_specified_variables.cluster_id}-SNSEFSSubscription", protocol=sns.SubscriptionProtocol.LAMBDA, endpoint=efs_apps_throughput_lambda.function_arn, topic=sns_efs_topic)

        if install_props.Config.storage.data.provider == "fsx_lustre" and not user_specified_variables.fs_data:
            if install_props.Config.storage.data.fsx_lustre.storage_type == "SSD":
                if install_props.Config.storage.data.fsx_lustre.deployment_type == "PERSISTENT_1":
                    lustre_configuration = fsx.CfnFileSystem.LustreConfigurationProperty(
                        per_unit_storage_throughput=install_props.Config.storage.data.fsx_lustre.per_unit_storage_throughput,
                        deployment_type=install_props.Config.storage.data.fsx_lustre.deployment_type)
                else:
                    lustre_configuration = fsx.CfnFileSystem.LustreConfigurationProperty(
                        deployment_type=install_props.Config.storage.data.fsx_lustre.deployment_type)
            else:
                lustre_configuration = fsx.CfnFileSystem.LustreConfigurationProperty(
                    deployment_type=install_props.Config.storage.data.fsx_lustre.deployment_type,
                    per_unit_storage_throughput=install_props.Config.storage.data.fsx_lustre.per_unit_storage_throughput,
                    drive_cache_type=install_props.Config.storage.data.fsx_lustre.drive_cache_type),

            self.soca_resources["fs_data"] = fsx.CfnFileSystem(self, "FSxLustreData", file_system_type="LUSTRE",
                    subnet_ids=[self.soca_resources["vpc"].select_subnets(subnet_type=ec2.SubnetType.PRIVATE).subnets[0].subnet_id],
                    lustre_configuration=lustre_configuration,
                    security_group_ids=[self.soca_resources["compute_node_sg"].security_group_id],
                    storage_capacity=install_props.Config.storage.data.fsx_lustre.storage_capacity,
                    storage_type=install_props.Config.storage.data.fsx_lustre.storage_type,
                    kms_key_id=None if install_props.Config.storage.data.kms_key_id is False else install_props.Config.storage.data.kms_key_id)

            core.Tags.of(self.soca_resources["fs_data"]).add("Name", f"{user_specified_variables.cluster_id}-Data")

        if install_props.Config.storage.apps.provider == "fsx_lustre" and not user_specified_variables.fs_apps:
            if install_props.Config.storage.apps.fsx_lustre.storage_type == "SSD":
                if install_props.Config.storage.apps.fsx_lustre.deployment_type == "PERSISTENT_1":
                    lustre_configuration=fsx.CfnFileSystem.LustreConfigurationProperty(
                        per_unit_storage_throughput=install_props.Config.storage.apps.fsx_lustre.per_unit_storage_throughput,
                        deployment_type=install_props.Config.storage.apps.fsx_lustre.deployment_type)
                else:
                    lustre_configuration=fsx.CfnFileSystem.LustreConfigurationProperty(
                        deployment_type=install_props.Config.storage.apps.fsx_lustre.deployment_type)
            else:
                lustre_configuration=fsx.CfnFileSystem.LustreConfigurationProperty(
                    deployment_type=install_props.Config.storage.apps.fsx_lustre.deployment_type,
                    per_unit_storage_throughput=install_props.Config.storage.apps.fsx_lustre.per_unit_storage_throughput,
                    drive_cache_type=install_props.Config.storage.apps.fsx_lustre.drive_cache_type),

            self.soca_resources["fs_apps"] = fsx.CfnFileSystem(self, "FSxLustreApps", file_system_type="LUSTRE",
                    subnet_ids=[self.soca_resources["vpc"].select_subnets(subnet_type=ec2.SubnetType.PRIVATE).subnets[0].subnet_id],
                    lustre_configuration=lustre_configuration,
                    security_group_ids=[self.soca_resources["compute_node_sg"].security_group_id],
                    storage_capacity=install_props.Config.storage.apps.fsx_lustre.storage_capacity,
                    storage_type=install_props.Config.storage.apps.fsx_lustre.storage_type,
                    kms_key_id=None if install_props.Config.storage.apps.kms_key_id is False else install_props.Config.storage.apps.kms_key_id)

            core.Tags.of(self.soca_resources["fs_apps"]).add("Name", f"{user_specified_variables.cluster_id}-Apps")

    def scheduler(self):
        """
        Create the Scheduler EC2 instance, configure user data and assign EIP
        """

        # Create Lambda to reset AD DS password when using AD
        if install_props.Config.directoryservice.provider == "activedirectory":
            self.soca_resources["reset_ds_lambda"] = aws_lambda.Function(self, f"{user_specified_variables.cluster_id}-ResetDsLambdaFunction",
                                                  function_name=f"{user_specified_variables.cluster_id}-ResetDsLambdaFunction-{''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(20))}",
                                                  description="Lambda to reset AD DS password",
                                                  memory_size=128, role=self.soca_resources["reset_ds_password_lambda_role"],
                                                  timeout=core.Duration.minutes(3),
                                                  runtime=aws_lambda.Runtime.PYTHON_3_7,
                                                  log_retention=logs.RetentionDays.INFINITE,
                                                  handler="ResetDSPassword.lambda_handler",
                                                  code=aws_lambda.Code.asset("../functions/ResetDSPassword"))

        # Generate EC2 User Data
        user_data_substitutes = {"%%AWS_ACCOUNT_ID%%": core.Aws.ACCOUNT_ID,
                                 "%%AWS_PARTITION%%": core.Aws.PARTITION,
                                 "%%CLUSTER_ID%%": user_specified_variables.cluster_id,
                                 "%%S3_BUCKET%%": user_specified_variables.bucket,
                                 "%%AWS_REGION%%": core.Aws.REGION,
                                 "%%SOCA_VERSION%%": "2.7.0",
                                 "%%COMPUTE_NODE_ARN%%": self.soca_resources["compute_node_role"].role_arn,
                                 "%%FS_DATA_PROVIDER%%": install_props.Config.storage.data.provider if not user_specified_variables.fs_data_provider else user_specified_variables.fs_data_provider,
                                 "%%FS_APPS_PROVIDER%%": install_props.Config.storage.apps.provider if not user_specified_variables.fs_apps_provider else user_specified_variables.fs_apps_provider,
                                 "%%FS_DATA_DNS%%": f"{self.soca_resources['fs_data'].ref}.{endpoints_suffix[install_props.Config.storage.data.provider]}" if not user_specified_variables.fs_data else f"{user_specified_variables.fs_data}.{endpoints_suffix[install_props.Config.storage.data.provider]}",
                                 "%%FS_APPS_DNS%%": f"{self.soca_resources['fs_apps'].ref}.{endpoints_suffix[install_props.Config.storage.apps.provider]}" if not user_specified_variables.fs_apps else f"{user_specified_variables.fs_apps}.{endpoints_suffix[install_props.Config.storage.apps.provider]}",
                                 "%%VPC_ID%%": self.soca_resources["vpc"].vpc_id,
                                 "%%BASE_OS%%": user_specified_variables.base_os,
                                 "%%LDAP_USERNAME%%": user_specified_variables.ldap_user,
                                 "%%LDAP_PASSWORD%%": user_specified_variables.ldap_password,
                                 "%%SOCA_INSTALL_AMI%%": self.soca_resources["ami_id"],
                                 "%%RESET_PASSWORD_DS_LAMBDA%%": "false" if not self.soca_resources["reset_ds_lambda"] else self.soca_resources["reset_ds_lambda"].function_arn,
                                 "%%SOCA_AUTH_PROVIDER%%": install_props.Config.directoryservice.provider,
                                 "%%SOCA_LDAP_BASE%%": "false" if install_props.Config.directoryservice.provider == "activedirectory" else f"dc={',dc='.join(install_props.Config.directoryservice.openldap.name.split('.'))}".lower()}

        with open("../user_data/Scheduler.sh") as plain_user_data:
            user_data = plain_user_data.read()

        for k, v in user_data_substitutes.items():
            user_data = user_data.replace(k, v)

        # Choose subnet where to deploy the scheduler
        if not user_specified_variables.vpc_id:
            if install_props.Config.entry_points_subnets.lower() == "public":
                vpc_subnets = ec2.SubnetSelection(subnets=[self.soca_resources["vpc"].public_subnets[0]])
            else:
                vpc_subnets = ec2.SubnetSelection(subnets=[self.soca_resources["vpc"].private_subnets[0]])
        else:
            if install_props.Config.entry_points_subnets.lower() == "public":
                subnet_info = user_specified_variables.public_subnets[0].split(",")
            else:
                subnet_info = user_specified_variables.private_subnets[0].split(",")
            launch_subnet = ec2.Subnet.from_subnet_attributes(self, "SubnetToUse",
                                                              availability_zone=subnet_info[1],
                                                              subnet_id=subnet_info[0])
            vpc_subnets = ec2.SubnetSelection(subnets=[launch_subnet])

        # Create the Scheduler Instance
        self.soca_resources["scheduler_instance"] = ec2.Instance(self, "SchedulerInstance",
                                                                 availability_zone=vpc_subnets.availability_zones,
                                                                 machine_image=ec2.MachineImage.generic_linux({
                                                                       user_specified_variables.region: self.soca_resources["ami_id"]}),
                                                                 instance_type=ec2.InstanceType(str(install_props.Config.scheduler.instance_type)),
                                                                 key_name=user_specified_variables.ssh_keypair,
                                                                 vpc=self.soca_resources["vpc"],
                                                                 block_devices=[ec2.BlockDevice(
                                                                       device_name="/dev/xvda" if user_specified_variables.base_os == "amazonlinux2" else "/dev/sda1",
                                                                       volume=ec2.BlockDeviceVolume(
                                                                           ebs_device=ec2.EbsDeviceProps(
                                                                               volume_size=int(install_props.Config.scheduler.volume_size),
                                                                               volume_type=ec2.EbsDeviceVolumeType.GP3))
                                                                 )],
                                                                 role=self.soca_resources["scheduler_role"],
                                                                 security_group=self.soca_resources["scheduler_sg"],
                                                                 vpc_subnets=vpc_subnets,
                                                                 user_data=ec2.UserData.custom(user_data))

        core.Tags.of(self.soca_resources["scheduler_instance"]).add("Name", f"{user_specified_variables.cluster_id}-Scheduler")
        core.Tags.of(self.soca_resources["scheduler_instance"]).add("soca:BackupPlan", f"{user_specified_variables.cluster_id}")

        # Ensure Filesystem are already up and running before creating the scheduler instance
        if not user_specified_variables.fs_apps:
            self.soca_resources["scheduler_instance"].node.add_dependency(self.soca_resources["fs_apps"])
        if not user_specified_variables.fs_data:
            self.soca_resources["scheduler_instance"].node.add_dependency(self.soca_resources["fs_data"])

        ssh_user = "centos" if user_specified_variables.base_os == "centos7" else "ec2-user"

        if install_props.Config.entry_points_subnets.lower() == "public":
            # Associate the EIP to the scheduler instance
            ec2.CfnEIPAssociation(self, "AssignEIPToScheduler",
                                  eip=self.soca_resources["scheduler_eip"].ref,
                                  instance_id=self.soca_resources["scheduler_instance"].instance_id)
            core.CfnOutput(self, "SchedulerIP", value=self.soca_resources["scheduler_eip"].ref)
            core.CfnOutput(self, "ConnectionString", value=f"ssh -i {user_specified_variables.ssh_keypair} {ssh_user}@{self.soca_resources['scheduler_eip'].ref}")

        else:
            core.CfnOutput(self, "SchedulerIP", value=self.soca_resources["scheduler_instance"].instance_private_ip)
            core.CfnOutput(self, "ConnectionString", value=f"ssh -i {user_specified_variables.ssh_keypair} {ssh_user}@{self.soca_resources['scheduler_instance'].instance_private_ip}")

    def secretsmanager(self):
        """
        Store SOCA configuration in a Secret Manager's Secret.
        Scheduler/Compute Nodes have the permission to read the secret
        """
        solution_metrics_lambda = aws_lambda.Function(self,
                                                      f"{user_specified_variables.cluster_id}-SolutionMetricsLambda",
                                                      function_name=f"{user_specified_variables.cluster_id}-Metrics",
                                                      description="Send SOCA anonymous Metrics to AWS",
                                                      memory_size=128, role=self.soca_resources["solution_metrics_lambda_role"],
                                                      timeout=core.Duration.minutes(3),
                                                      runtime=aws_lambda.Runtime.PYTHON_3_7,
                                                      log_retention=logs.RetentionDays.INFINITE,
                                                      handler="SolutionMetricsLambda.lambda_handler",
                                                      code=aws_lambda.Code.asset("../functions/SolutionMetricsLambda"))
        public_subnets = []
        private_subnets = []
        for pub_sub in self.soca_resources["vpc"].public_subnets:
            public_subnets.append(pub_sub.subnet_id)

        for priv_sub in self.soca_resources["vpc"].private_subnets:
            private_subnets.append(priv_sub.subnet_id)

        secret = {"VpcId": self.soca_resources["vpc"].vpc_id,
                  "PublicSubnets": public_subnets,
                  "PrivateSubnets": private_subnets,
                  "SchedulerPrivateIP": self.soca_resources["scheduler_instance"].instance_private_ip,
                  "SchedulerPrivateDnsName": self.soca_resources["scheduler_instance"].instance_private_dns_name,
                  "SchedulerInstanceId": self.soca_resources["scheduler_instance"].instance_id,
                  "SchedulerSecurityGroup": self.soca_resources["scheduler_sg"].security_group_id,
                  "ComputeNodeSecurityGroup": self.soca_resources["compute_node_sg"].security_group_id,
                  "SchedulerIAMRoleArn": self.soca_resources["scheduler_role"].role_arn,
                  "SpotFleetIAMRoleArn": self.soca_resources["spot_fleet_role"].role_arn,
                  "SchedulerIAMRole": self.soca_resources["scheduler_role"].role_name,
                  "ComputeNodeIAMRoleArn": self.soca_resources["compute_node_role"].role_arn,
                  "ComputeNodeIAMRole": self.soca_resources["compute_node_role"].role_name,
                  "ComputeNodeInstanceProfileArn": f"arn:{core.Aws.PARTITION}:iam::{core.Aws.ACCOUNT_ID}:instance-profile/{self.soca_resources['compute_node_instance_profile'].ref}",
                  "ClusterId": user_specified_variables.cluster_id,
                  "Version": install_props.Config.version,
                  "S3Bucket": user_specified_variables.bucket,
                  "SSHKeyPair": user_specified_variables.ssh_keypair,
                  "CustomAMI": self.soca_resources["ami_id"],
                  "LoadBalancerDNSName": self.soca_resources["alb"].load_balancer_dns_name,
                  "LoadBalancerArn": self.soca_resources["alb"].load_balancer_arn,
                  "BaseOS": user_specified_variables.base_os,
                  "S3InstallFolder": user_specified_variables.cluster_id,
                  "SchedulerIP": self.soca_resources["scheduler_eip"].ref if install_props.Config.entry_points_subnets.lower() == "public" else self.soca_resources["scheduler_instance"].instance_private_ip,
                  "SolutionMetricsLambda": solution_metrics_lambda.function_arn,
                  "DefaultMetricCollection": "true",
                  "AuthProvider": install_props.Config.directoryservice.provider,
                  "FileSystemDataProvider": install_props.Config.storage.data.provider if not user_specified_variables.fs_data_provider else user_specified_variables.fs_data_provider,
                  "FileSystemData": f"{self.soca_resources['fs_data'].ref}.{endpoints_suffix[install_props.Config.storage.data.provider]}" if not user_specified_variables.fs_data else f"{user_specified_variables.fs_data}.{endpoints_suffix[install_props.Config.storage.data.provider]}",
                  "FileSystemAppsProvider": install_props.Config.storage.apps.provider if not user_specified_variables.fs_apps_provider else user_specified_variables.fs_apps_provider,
                  "FileSystemApps": f"{self.soca_resources['fs_apps'].ref}.{endpoints_suffix[install_props.Config.storage.apps.provider]}" if not user_specified_variables.fs_apps else f"{user_specified_variables.fs_apps}.{endpoints_suffix[install_props.Config.storage.apps.provider]}"
                  }

        # ES configuration
        if not user_specified_variables.es_endpoint:
            secret["ESDomainEndpoint"] = self.soca_resources["es_domain"].domain_endpoint
        else:
            secret["ESDomainEndpoint"] = user_specified_variables.es_endpoint

        # LDAP configuration
        if not user_specified_variables.ldap_host:
            secret["ExistingLDAP"] = False
        else:
            secret["ExistingLDAP"] = user_specified_variables.ldap_host

        if not user_specified_variables.directory_service_id:
            if install_props.Config.directoryservice.provider == "activedirectory":
                secret["DSDirectoryId"] = self.soca_resources["directory_service"].ref
                secret["DSDomainName"] = install_props.Config.directoryservice.activedirectory.name
                secret["DSDomainBase"] = f"dc={',dc='.join(secret['DSDomainName'].split('.'))}".lower()
                secret["DSDomainNetbios"] = install_props.Config.directoryservice.activedirectory.short_name.upper()
                secret["DSDomainAdminUsername"] = self.soca_resources["ds_domain_admin"]
                secret["DSDomainAdminPassword"] = self.soca_resources["ds_domain_admin_password"]
                secret["DSServiceAccountUsername"] = "false"
                secret["DSServiceAccountPassword"] = "false"
                secret["DSResetLambdaFunctionArn"] = self.soca_resources["reset_ds_lambda"].function_arn
            else:
                # OpenLDAP
                secret["LdapName"] = install_props.Config.directoryservice.openldap.name
                secret["LdapBase"] = f"dc={',dc='.join(secret['LdapName'].split('.'))}".lower()
                secret["LdapHost"] = self.soca_resources["scheduler_instance"].instance_private_dns_name
        else:
            secret["DSDirectoryId"] = user_specified_variables.directory_service_id
            secret["DSDomainName"] = user_specified_variables.directory_service_name
            secret["DSDomainBase"] = f"dc={',dc='.join(secret['DSDomainName'].split('.'))}".lower()
            secret["DSDomainNetbios"] = user_specified_variables.directory_service_shortname.upper()
            secret["DSDomainAdminUsername"] = user_specified_variables.directory_service_user
            secret["DSDomainAdminPassword"] = user_specified_variables.directory_service_user_password
            secret["DSServiceAccountUsername"] = "false"
            secret["DSServiceAccountPassword"] = "false"

        self.soca_resources["soca_config"] = secretsmanager.CfnSecret(self, "SOCASecretManagerSecret",
                                                                      description=f"Store SOCA configuration for cluster {user_specified_variables.cluster_id}",
                                                                      kms_key_id=None if install_props.Config.secretsmanager.kms_key_id is False else install_props.Config.secretsmanager.kms_key_id,
                                                                      name=user_specified_variables.cluster_id,
                                                                      secret_string=json.dumps(secret))

        # Create IAM policy and attach it to both Scheduler and Compute Nodes group
        secret_manager_statement = iam.PolicyStatement(actions=["secretsmanager:GetSecretValue"], effect=iam.Effect.ALLOW, resources=[self.soca_resources["soca_config"].ref])
        self.soca_resources["scheduler_role"].attach_inline_policy(iam.Policy(self, "AttachSecretManagerPolicyToScheduler", statements=[secret_manager_statement]))
        self.soca_resources["compute_node_role"].attach_inline_policy(iam.Policy(self, "AttachSecretManagerPolicyToComputeNode", statements=[secret_manager_statement]))

    def analytics(self):
        """
        Create one ElasticSearch cluster. This will be used as jobs & hosts analytics tool
        """

        sanitized_domain = user_specified_variables.cluster_id.lower()
        if not user_specified_variables.es_endpoint:
            if install_props.Config.elasticsearch.data_nodes == 1:
                es_subnets = [ec2.SubnetSelection(subnets=[self.soca_resources["vpc"].private_subnets[0]])]
                es_zone_awareness = elasticsearch.ZoneAwarenessConfig(enabled=False)
            elif install_props.Config.elasticsearch.data_nodes == 2:
                es_subnets = [ec2.SubnetSelection(subnets=[self.soca_resources["vpc"].private_subnets[0], self.soca_resources["vpc"].private_subnets[1]])]
                es_zone_awareness = elasticsearch.ZoneAwarenessConfig(availability_zone_count=2, enabled=True)
            else:
                es_subnets = [ec2.SubnetSelection(subnets=[self.soca_resources["vpc"].private_subnets[0], self.soca_resources["vpc"].private_subnets[1], self.soca_resources["vpc"].private_subnets[2]])]
                es_zone_awareness = elasticsearch.ZoneAwarenessConfig(availability_zone_count=3, enabled=True)

            self.soca_resources["es_domain"] = elasticsearch.Domain(self, "ElasticSearch", domain_name=sanitized_domain, enforce_https=True,
                                                                    node_to_node_encryption=True,
                                                                    version=elasticsearch.ElasticsearchVersion.V7_9,
                                                  encryption_at_rest=elasticsearch.EncryptionAtRestOptions(enabled=True),
                                                  ebs=elasticsearch.EbsOptions(volume_size=install_props.Config.elasticsearch.ebs_volume_size,
                                                                               volume_type=ec2.EbsDeviceVolumeType.GP2),
                                                  capacity=elasticsearch.CapacityConfig(
                                                      data_node_instance_type=install_props.Config.elasticsearch.data_node_instance_type,
                                                      data_nodes=install_props.Config.elasticsearch.data_nodes),
                                                  automated_snapshot_start_hour=0,
                                                  removal_policy=core.RemovalPolicy.RETAIN if install_props.Config.elasticsearch.deletion_policy.upper() == "RETAIN" else core.RemovalPolicy.DESTROY,
                                                  access_policies=[iam.PolicyStatement(
                                                      principals=[iam.AnyPrincipal()],
                                                      actions=["es:ESHttp*"],
                                                      resources=[
                                                          f"arn:{core.Aws.PARTITION}:es:{core.Aws.REGION}:{core.Aws.ACCOUNT_ID}:domain/{sanitized_domain}/*"])
                                                  ],
                                                  advanced_options={"rest.action.multi.allow_explicit_index": "true"},
                                                  security_groups=[self.soca_resources["compute_node_sg"]],
                                                  zone_awareness=es_zone_awareness,
                                                  vpc=self.soca_resources["vpc"],
                                                  vpc_subnets=es_subnets
                                                  )
            if user_specified_variables.create_es_service_role:
                service_linked_role = iam.CfnServiceLinkedRole(self, "ESServiceLinkedRole",
                                                               aws_service_name=f"es.{core.Aws.URL_SUFFIX}",
                                                               description="Role for ES to access resources in the VPC")
                self.soca_resources["es_domain"].node.add_dependency(service_linked_role)

            # Retrieve ES Private VPC IPs to interact with SOCA analytics scripts
            get_es_private_ip_lambda = aws_lambda.Function(self, f"{user_specified_variables.cluster_id}-GetESPrivateIPLambda",
                                                           function_name=f"{user_specified_variables.cluster_id}-GetESPrivateIP",
                                                           description="Get ES private ip addresses",
                                                           memory_size=128, role=self.soca_resources["get_es_private_ip_lambda_role"],
                                                           runtime=aws_lambda.Runtime.PYTHON_3_7,
                                                           timeout=core.Duration.minutes(3),
                                                           log_retention=logs.RetentionDays.INFINITE,
                                                           handler="GetESPrivateIPLambda.lambda_handler",
                                                           code=aws_lambda.Code.asset("../functions/GetESPrivateIPLambda"))

            self.soca_resources["es_custom_resource"] = core.CustomResource(self, "ESCustomResource", service_token=get_es_private_ip_lambda.function_arn, properties={"ClusterId": sanitized_domain})
            self.soca_resources["es_custom_resource"].node.add_dependency(self.soca_resources["es_domain"])
            self.soca_resources["es_custom_resource"].node.add_dependency(self.soca_resources["get_es_private_ip_lambda_role"])

    def backups(self):
        """
        Deploy AWS Backup vault. Scheduler EC2 instance and both EFS will be backup on a daily basis
        """
        vault = backup.BackupVault(self, "SOCABackupVault",
                                   backup_vault_name=f"{user_specified_variables.cluster_id}-BackupVault",
                                   removal_policy=core.RemovalPolicy.DESTROY)  # removal policy won't apply if backup vault is not empty
        plan = backup.BackupPlan(self, "SOCABackupPlan",
                                 backup_plan_name=f"{user_specified_variables.cluster_id}-BackupPlan",
                                 backup_plan_rules=[backup.BackupPlanRule(backup_vault=vault,
                                                                          start_window=core.Duration.minutes(60),
                                                                          delete_after=core.Duration.days(int(install_props.Config.backups.delete_after)),
                                                                          schedule_expression=events.Schedule.expression("cron(0 5 * * ? *)"))])
        # Backup EFS/EC2 resources with special tag: soca:BackupPlan, value: Current Cluster ID
        backup.BackupSelection(self, "SOCABackupSelection", backup_plan=plan, role=self.soca_resources["backup_role"],
                               backup_selection_name=f"{user_specified_variables.cluster_id}-BackupSelection",
                               resources=[backup.BackupResource(tag_condition=backup.TagCondition(key="soca:BackupPlan",
                                                                                                  value=user_specified_variables.cluster_id,
                                                                                                  operation=backup.TagOperation.STRING_EQUALS))])

    def viewer(self):

        # Create the ALB. It's used to forward HTTP/S traffic to DCV hosts, Web UI and ES

        self.soca_resources["alb"] = elbv2.ApplicationLoadBalancer(self, f"{user_specified_variables.cluster_id}-ELBv2Viewer",
                                                                   load_balancer_name=f"{user_specified_variables.cluster_id}-viewer",
                                                                   security_group=self.soca_resources["scheduler_sg"],
                                                                   http2_enabled=True,
                                                                   vpc=self.soca_resources["vpc"],
                                                                   internet_facing=True if install_props.Config.entry_points_subnets.lower() == "public" else False)
        # HTTP listener simply forward to HTTPS
        self.soca_resources["alb"].add_listener("HTTPListener", port=80, open=False, protocol=elbv2.ApplicationProtocol.HTTP,
                                                default_action=elbv2.ListenerAction(
                                                    action_json=elbv2.CfnListener.ActionProperty(
                                                        type="redirect",
                                                        redirect_config=elbv2.CfnListener.RedirectConfigProperty(
                                                            host="#{host}",
                                                            path="/#{path}",
                                                            port="443",
                                                            protocol="HTTPS",
                                                            query="#{query}",
                                                            status_code="HTTP_301"))))

        # Create self-signed certificate (if needed) for HTTPS listener (via AWS Lambda)
        create_acm_certificate_lambda = aws_lambda.Function(self, f"{user_specified_variables.cluster_id}-ACMCertificateLambda",
                                                            function_name=f"{user_specified_variables.cluster_id}-CreateACMCertificate",
                                                            description="Create first self-signed certificate for ALB",
                                                            memory_size=128, role=self.soca_resources["acm_certificate_lambda_role"],
                                                            runtime=aws_lambda.Runtime.PYTHON_3_7,
                                                            timeout=core.Duration.minutes(1),
                                                            log_retention=logs.RetentionDays.INFINITE,
                                                            handler="CreateELBSSLCertificate.generate_cert",
                                                            code=aws_lambda.Code.asset("../functions/CreateELBSSLCertificate"))

        cert_custom_resource = core.CustomResource(self, "RetrieveACMCertificate",
                                                   service_token=create_acm_certificate_lambda.function_arn,
                                                   properties={"LoadBalancerDNSName": self.soca_resources["alb"].load_balancer_dns_name,
                                                               "ClusterId": user_specified_variables.cluster_id})

        cert_custom_resource.node.add_dependency(create_acm_certificate_lambda)
        cert_custom_resource.node.add_dependency(self.soca_resources["acm_certificate_lambda_role"])

        soca_webui_target_group = elbv2.CfnTargetGroup(self, f"{user_specified_variables.cluster_id}-SOCAWebUITargetGroup", port=8443, protocol="HTTPS", target_type="instance", vpc_id=self.soca_resources["vpc"].vpc_id,
                                                       name=f"{user_specified_variables.cluster_id}-WebUI",
                                                       targets=[elbv2.CfnTargetGroup.TargetDescriptionProperty(id=self.soca_resources["scheduler_instance"].instance_id)],
                                                       health_check_path="/ping")

        https_listener = elbv2.CfnListener(self, "HTTPSListener", port=443, ssl_policy="ELBSecurityPolicy-2016-08",
                                           load_balancer_arn=self.soca_resources["alb"].load_balancer_arn, protocol="HTTPS",
                                           certificates=[elbv2.CfnListener.CertificateProperty(certificate_arn=cert_custom_resource.get_att_string('ACMCertificateArn'))],
                                           default_actions=[elbv2.CfnListener.ActionProperty(
                                               type="forward", target_group_arn=soca_webui_target_group.ref)])

        https_listener.node.add_dependency(cert_custom_resource)

        if not user_specified_variables.es_endpoint:
            # Create the target group for Elastic Search
            es_targets = []
            for i in range(0, install_props.Config.elasticsearch.data_nodes * 3):
                es_targets.append(elbv2.CfnTargetGroup.TargetDescriptionProperty(id=core.Fn.select(i, core.Fn.split(",", self.soca_resources["es_custom_resource"].get_att_string('IpAddresses')))))

            es_target_group = elbv2.CfnTargetGroup(self, f"{user_specified_variables.cluster_id}-ESTargetGroup", port=443,
                                                   protocol="HTTPS", target_type="ip", vpc_id=self.soca_resources["vpc"].vpc_id,
                                                   name=f"{user_specified_variables.cluster_id}-ES",
                                                   targets=es_targets, health_check_path="/")

            es_target_group.node.add_dependency(self.soca_resources["es_custom_resource"])
            es_load_balancer_listener_rule = elbv2.CfnListenerRule(self, f"{user_specified_variables.cluster_id}-ESLoadBalancerListenerRule",
                                                                   listener_arn=https_listener.ref,
                                                                   actions=[elbv2.CfnListenerRule.ActionProperty(type="forward", target_group_arn=es_target_group.ref)],
                                                                   conditions=[elbv2.CfnListenerRule.RuleConditionProperty(field="path-pattern",
                                                                   path_pattern_config=elbv2.CfnListenerRule.PathPatternConfigProperty(values=["/_plugin/kibana/*"]))],
                                                                   priority=1)

            es_load_balancer_listener_rule.node.add_dependency(https_listener)
            es_load_balancer_listener_rule.node.add_dependency(es_target_group)

        if not user_specified_variables.es_endpoint:
            core.CfnOutput(self, "AnalyticsDashboard", value=f"https://{self.soca_resources['alb'].load_balancer_dns_name}/_plugin/kibana/")
        else:
            core.CfnOutput(self, "AnalyticsDashboard", value=f"https://{user_specified_variables.es_endpoint}/_plugin/kibana/")

        core.CfnOutput(self, "WebUserInterface", value=f"https://{self.soca_resources['alb'].load_balancer_dns_name}/")


if __name__ == "__main__":
    app = core.App()

    # User specified variables, queryable as Python Object
    install_props = json.loads(json.dumps(get_install_properties()), object_hook=lambda d: SimpleNamespace(**d))
    user_specified_variables = json.loads(json.dumps({
        "bucket": app.node.try_get_context("bucket"),
        "region": app.node.try_get_context("region"),
        "base_os": app.node.try_get_context("base_os"),
        "ldap_user": app.node.try_get_context("ldap_user"),
        "ldap_password": base64.b64decode(app.node.try_get_context("ldap_password")).decode("utf-8"),
        "ssh_keypair": app.node.try_get_context("ssh_keypair"),
        "client_ip": app.node.try_get_context("client_ip"),
        "prefix_list_id": app.node.try_get_context("prefix_list_id"),
        "custom_ami": app.node.try_get_context("custom_ami"),
        "cluster_id": app.node.try_get_context("cluster_id"),
        "vpc_cidr": app.node.try_get_context("vpc_cidr"),
        "create_es_service_role": False if app.node.try_get_context("create_es_service_role") == "False" else True,
        "vpc_azs": app.node.try_get_context("vpc_azs"),
        "vpc_id": app.node.try_get_context("vpc_id"),
        "public_subnets": app.node.try_get_context("public_subnets") if app.node.try_get_context("public_subnets") is None else ast.literal_eval(base64.b64decode(app.node.try_get_context("public_subnets")).decode("utf-8")),
        "private_subnets": app.node.try_get_context("private_subnets") if app.node.try_get_context("private_subnets") is None else ast.literal_eval(base64.b64decode(app.node.try_get_context("private_subnets")).decode("utf-8")),
        "fs_apps_provider": app.node.try_get_context("fs_apps_provider"),
        "fs_apps": app.node.try_get_context("fs_apps"),
        "fs_data_provider": app.node.try_get_context("fs_data_provider"),
        "fs_data": app.node.try_get_context("fs_data"),
        "compute_node_sg": app.node.try_get_context("compute_node_sg"),
        "scheduler_sg": app.node.try_get_context("scheduler_sg"),
        "vpc_endpoint_sg": app.node.try_get_context("vpc_endpoint_sg"),
        "compute_node_role": app.node.try_get_context("compute_node_role"),
        "scheduler_role": app.node.try_get_context("scheduler_role"),
        "directory_service_user": app.node.try_get_context("directory_service_user"),
        "directory_service_user_password": app.node.try_get_context("directory_service_user_password"),
        "directory_service_shortname": app.node.try_get_context("directory_service_shortname"),
        "directory_service_name": app.node.try_get_context("directory_service_name"),
        "directory_service_id": app.node.try_get_context("directory_service_id"),
        "directory_service_ds_dns": app.node.try_get_context("directory_service_dns"),
        "es_endpoint": app.node.try_get_context("es_endpoint"),
        "ldap_host": app.node.try_get_context("ldap_host"),
        "compute_node_role_name": app.node.try_get_context("compute_node_role_name"),
        "compute_node_role_arn": app.node.try_get_context("compute_node_role_arn"),
        "compute_node_role_from_previous_soca_deployment": app.node.try_get_context("compute_node_role_from_previous_soca_deployment"),
        "scheduler_role_name": app.node.try_get_context("scheduler_role_name"),
        "scheduler_role_arn": app.node.try_get_context("scheduler_role_arn"),
        "scheduler_role_from_previous_soca_deployment": app.node.try_get_context("scheduler_role_from_previous_soca_deployment"),
        "spotfleet_role_name": app.node.try_get_context("spotfleet_role_name"),
        "spotfleet_role_arn": app.node.try_get_context("spotfleet_role_arn"),
        "spotfleet_role_from_previous_soca_deployment": app.node.try_get_context("spotfleet_role_from_previous_soca_deployment"),
    }), object_hook=lambda d: SimpleNamespace(**d))

    # List of AWS endpoints & principals suffix
    endpoints_suffix = {"fsx_lustre": f"fsx.{core.Aws.REGION}.{core.Aws.URL_SUFFIX}",
                        "efs": f"efs.{core.Aws.REGION}.{core.Aws.URL_SUFFIX}"}

    principals_suffix = {"backup": f"backup.{core.Aws.URL_SUFFIX}",
                         "cloudwatch": f"cloudwatch.{core.Aws.URL_SUFFIX}",
                         "ec2": f"ec2.{core.Aws.URL_SUFFIX}",
                         "lambda": f"lambda.{core.Aws.URL_SUFFIX}",
                         "sns": f"sns.{core.Aws.URL_SUFFIX}",
                         "spotfleet": f"spotfleet.{core.Aws.URL_SUFFIX}",
                         "ssm": f"ssm.{core.Aws.URL_SUFFIX}"}

    # Apply default tag to all taggable resources
    core.Tags.of(app).add("soca:ClusterId", user_specified_variables.cluster_id)
    core.Tags.of(app).add("soca:CreatedOn", str(datetime.datetime.utcnow()))
    core.Tags.of(app).add("soca:CreatedFrom", user_specified_variables.client_ip)
    core.Tags.of(app).add("soca:Version", install_props.Config.version)


    # Launch Cfn generation
    cdk_env = core.Environment(account=os.environ["CDK_DEFAULT_ACCOUNT"],
                               region=user_specified_variables.region if user_specified_variables.region else os.environ['CDK_DEFAULT_REGION'])

    install = SOCAInstall(app, user_specified_variables.cluster_id, env=cdk_env,
                          description=f"SOCA cluster version {install_props.Config.version}",
                          termination_protection=install_props.Config.termination_protection)
    app.synth()