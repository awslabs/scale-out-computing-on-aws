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

import sys
import os

installer_path = "/".join(os.path.dirname(os.path.abspath(__file__)).split("/")[:-3])
sys.path.append(installer_path)
from installer.resources.src.prompt import get_input as get_input
import os

try:
    import boto3
    from colored import fg, bg, attr
    import ipaddress

except ImportError:
    print(
        "boto3 extension is required. Run 'pip install boto3 ipaddress' and try again"
    )
    sys.exit(1)


class FindExistingResource:
    def __init__(self, region, client_ip):
        self.region = region
        self.client_ip = client_ip
        session = boto3.Session(region_name=self.region)
        self.ec2 = session.client("ec2")
        self.efs = session.client("efs")
        self.fsx = session.client("fsx")
        self.ds = session.client("ds")
        self.es = session.client("es")
        self.iam = session.client("iam")
        self.install_parameters = {}

    def find_vpc(self):
        try:
            print(
                f"\n====== What {fg('misty_rose_3')}VPC{attr('reset')} in {self.region} do you want to use? ======\n"
            )
            vpcs_by_name = {}
            vpc_paginator = self.ec2.get_paginator("describe_vpcs")
            vpc_iterator = vpc_paginator.paginate(
                Filters=[
                    {
                        "Name": "state",
                        "Values": ["available"],
                    },
                ]
            )

            for page in vpc_iterator:
                for vpc in page["Vpcs"]:
                    resource_name = False
                    if "Tags" in vpc.keys():
                        for tag in vpc["Tags"]:
                            if tag["Key"] == "Name":
                                resource_name = tag["Value"]
                    # WARNING - This will skip unnamed VPCs
                    if not resource_name:
                        continue
                    vpcs_by_name[resource_name] = vpc
            vpcs = {}
            count = 1
            for resource_name in sorted(vpcs_by_name):
                vpc = vpcs_by_name[resource_name]
                vpcs[count] = {
                    "id": vpc["VpcId"],
                    "description": f"{resource_name if resource_name else ''} {vpc['VpcId']} {vpc['CidrBlock']}",
                    "cidr": vpc["CidrBlock"],
                }
                count += 1
            [
                print("    {:2} > {}".format(key, value["description"]))
                for key, value in vpcs.items()
            ]
            allowed_choices = list(vpcs.keys())
            choice = get_input(
                f"Choose the VPC you want to use?", None, allowed_choices, int
            )
            return {"success": True, "message": vpcs[choice]}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def find_elasticsearch(self, vpc_id):
        try:
            print(
                f"\n====== What {fg('misty_rose_3')}OpenSearch / ElasticSearch cluster{attr('reset')} do you want to use? [region: {self.region}, vpc: {vpc_id}] ======\n"
            )
            es = {}
            count = 1
            # note: list_domain_names() does not seem to support pagination
            for es_cluster in self.es.list_domain_names()["DomainNames"]:
                es[count] = {
                    "name": es_cluster["DomainName"],
                    "engine": es_cluster.get("EngineType", "unknown-engine"),
                }
                count += 1
            [
                print("    {} > {} ({})".format(key, value["name"], value["engine"]))
                for key, value in es.items()
            ]
            allowed_choices = list(es.keys())
            choice = get_input(
                f"Choose the OpenSearch/ElasticSearch Cluster you want to use?",
                None,
                allowed_choices,
                int,
            )

            # note: describe_elasticsearch_domain() does not seem to support pagination
            domain_info = self.es.describe_elasticsearch_domain(
                DomainName=es[choice]["name"]
            )
            if domain_info["DomainStatus"]["VPCOptions"]["VPCId"] == vpc_id:
                for scope, endpoint in domain_info["DomainStatus"]["Endpoints"].items():
                    es[choice]["endpoint"] = endpoint

            return {"success": True, "message": es[choice]}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def find_directory_services(self, vpc_id):
        try:
            print(
                f"\n====== What {fg('misty_rose_3')}Directory Services (Microsoft AD){attr('reset')} do you want to use? [region: {self.region}, vpc: {vpc_id}] ======\n"
            )
            ds = {}

            count = 1

            ds_paginator = self.ds.get_paginator("describe_directories")
            ds_iterator = ds_paginator.paginate()
            for page in ds_iterator:
                for directory in page["DirectoryDescriptions"]:
                    # skip directories in flux
                    if directory.get("Stage", "unknown-stage").upper() not in {
                        "ACTIVE"
                    }:
                        continue

                    if directory["VpcSettings"]["VpcId"] == vpc_id:
                        ds[count] = {
                            "id": directory["DirectoryId"],
                            "name": directory["Name"],
                            "netbios": directory["ShortName"],
                            "dns": directory["DnsIpAddrs"],
                            "description": f"{directory['Name']} (Domain: {directory['ShortName']}, Id: {directory['DirectoryId']})",
                        }
                        count += 1
            [
                print("    {:2} > {}".format(key, value["description"]))
                for key, value in ds.items()
            ]
            allowed_choices = list(ds.keys())
            choice = get_input(
                f"Choose the directory you want to use?", None, allowed_choices, int
            )
            return {"success": True, "message": ds[choice]}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def get_subnets(self, vpc_id, environment, selected_subnets=None):
        if selected_subnets is None:
            selected_subnets = []
        try:
            if environment == "private":
                print(
                    f"\n====== Select {fg('misty_rose_3')}3 subnets to use for your compute nodes (private subnets preferably) {attr('reset')} ======\n"
                )
            else:
                print(
                    f"\n====== Select {fg('misty_rose_3')}3 subnets to use for the main Scheduler and Load Balancer (public subnets preferably) {attr('reset')} ======\n"
                )

            subnets_by_name = {}
            subnet_paginator = self.ec2.get_paginator("describe_subnets")
            subnet_iterator = subnet_paginator.paginate(
                Filters=[
                    {
                        "Name": "vpc-id",
                        "Values": [vpc_id],
                    },
                    {"Name": "ipv6-native", "Values": ["false"]},
                    {
                        "Name": "state",
                        "Values": ["available"],
                    },
                ]
            )
            for page in subnet_iterator:
                for subnet in page["Subnets"]:
                    resource_name = False
                    if "Tags" in subnet.keys():
                        for tag in subnet["Tags"]:
                            if tag["Key"] == "Name":
                                resource_name = tag["Value"]
                    # WARNING - This will skip unnamed subnets
                    if not resource_name:
                        continue
                    subnets_by_name[resource_name] = subnet
            subnets = {}
            count = 1

            for resource_name in sorted(subnets_by_name):
                subnet = subnets_by_name[resource_name]
                if (
                    f"{subnet['SubnetId']},{subnet['AvailabilityZone']}"
                    not in selected_subnets
                ):
                    outpost_arn = subnet.get("OutpostArn", False)
                    is_outpost = True if outpost_arn else False
                    outpost_str = f"Outpost" if is_outpost else ""
                    subnet_description = f"{resource_name if resource_name else ''} {subnet['CidrBlock']}, AZ: {subnet['AvailabilityZone']}/{subnet['AvailabilityZoneId']} {outpost_str}"
                    subnets[count] = {
                        "id": subnet["SubnetId"],
                        "availability_zone": subnet["AvailabilityZone"],
                        "availability_zone_id": subnet["AvailabilityZoneId"],
                        "is_outpost": is_outpost,
                        "description": subnet_description,
                    }
                    count += 1

            [
                print("    {:2} > {}".format(key, value["description"]))
                for key, value in subnets.items()
            ]

            selected_subnets_count = get_input(
                f"How many of these subnets do you want to use?",
                None,
                list(range(1, count)),
                int,
            )
            while selected_subnets_count < 2:
                print(
                    f"{fg('red')} You must use at least 2 subnets for high availability {attr('reset')}"
                )
                selected_subnets_count = get_input(
                    f"How many of these subnets do you want to use?",
                    None,
                    list(range(1, count)),
                    int,
                )

            selected_subnets = []
            while len(selected_subnets) != selected_subnets_count:
                allowed_choices = list(subnets.keys())
                if len(allowed_choices) == 0:
                    return {"success": False, "message": "Not enough subnets available"}
                choice = get_input(
                    f"Choose your subnet #{len(selected_subnets) + 1} ?",
                    None,
                    allowed_choices,
                    int,
                )
                selected_subnets.append(
                    f"{subnets[choice]['id']},{subnets[choice]['availability_zone']}"
                )
                del subnets[choice]
            return {"success": True, "message": selected_subnets}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def get_fs(self, environment, vpc_id, selected_fs=None):
        if selected_fs is None:
            selected_fs = []
        try:
            print(
                f"\n====== What {fg('misty_rose_3')}Filesystem{attr('reset')} do you want to use for {fg('misty_rose_3')}{environment}{attr('reset')}? [region: {self.region}, vpc: {vpc_id}]  ======\n"
            )
            filesystems = {}
            count = 1

            efs_paginator = self.efs.get_paginator("describe_file_systems")
            efs_iterator = efs_paginator.paginate()

            for page in efs_iterator:
                for filesystem in page["FileSystems"]:
                    # check for lifecycle
                    if filesystem.get("LifeCycleState", "unknown").upper() not in {
                        "AVAILABLE",
                        "UPDATING",
                    }:
                        continue

                    verified_vpc = False
                    for mount_target in self.efs.describe_mount_targets(
                        FileSystemId=filesystem["FileSystemId"]
                    )["MountTargets"]:
                        if mount_target["VpcId"] == vpc_id:
                            verified_vpc = True

                    if verified_vpc is True:
                        if filesystem["FileSystemId"] not in selected_fs:
                            filesystems[count] = {
                                "id": f"{filesystem['FileSystemId']}",
                                "fs_type": "efs",
                                "description": f"EFS: {filesystem['Name'] if 'Name' in filesystem.keys() else 'EFS: '} {filesystem['FileSystemId']}.efs.{self.region}.amazonaws.com",
                            }
                            count += 1

            efs_count = count - 1

            fsx_paginator = self.fsx.get_paginator("describe_file_systems")
            fsx_iterator = fsx_paginator.paginate()

            for page in fsx_iterator:
                for filesystem in page["FileSystems"]:
                    # Check for proper Lifecycle
                    if filesystem.get("Lifecycle", "unknown-lifecycle").upper() not in {
                        "AVAILABLE",
                        "UPDATING",
                    }:
                        continue

                    fsx_type = filesystem.get("FileSystemType", "unknown-type")

                    # TODO - Add more FSx support here
                    # if fsx_type.upper() not in {'WINDOWS', 'LUSTRE', 'ONTAP', 'OPENZFS'}:
                    if fsx_type.upper() not in {"LUSTRE"}:
                        continue

                    resource_name = False
                    if filesystem["VpcId"] == vpc_id:
                        if filesystem["FileSystemId"] not in selected_fs:
                            for tag in filesystem["Tags"]:
                                if tag["Key"] == "Name":
                                    resource_name = tag["Value"]
                            filesystems[count] = {
                                "id": f"{filesystem['FileSystemId']}",
                                "fs_type": "fsx_lustre",
                                "description": f"FSx/{fsx_type.upper()}: {resource_name if resource_name else f'FSx/{fsx_type.upper()}: '} {filesystem['FileSystemId']}.fsx.{self.region}.amazonaws.com",
                            }
                            count += 1

            [
                print("    {} > {}".format(key, value["description"]))
                for key, value in filesystems.items()
            ]
            allowed_choices = list(filesystems.keys())
            choice = get_input(
                f"Choose the filesystem to use for {environment}?",
                None,
                allowed_choices,
                int,
            )

            return {
                "success": True,
                "message": filesystems[choice]["id"],
                "provider": filesystems[choice]["fs_type"],
            }

        except Exception as err:
            return {"success": False, "message": str(err)}

    def get_security_groups(self, vpc_id, environment, scheduler_sg=None):
        if scheduler_sg is None:
            scheduler_sg = []
        try:
            print(
                f"\n====== Choose the {fg('misty_rose_3')}security group to use for the {environment.upper()}{attr('reset')} [region: {self.region}, vpc: {vpc_id}] ======\n"
            )
            sgs_by_name = {}
            sg_paginator = self.ec2.get_paginator("describe_security_groups")
            sg_iterator = sg_paginator.paginate()

            for page in sg_iterator:
                for sg in page["SecurityGroups"]:
                    resource_name = False
                    if "Tags" in sg.keys():
                        for tag in sg["Tags"]:
                            if tag["Key"] == "Name":
                                resource_name = tag["Value"]
                    if not resource_name:
                        continue
                    sgs_by_name[resource_name] = sg
            sgs = {}
            count = 1

            for resource_name in sorted(sgs_by_name):
                sg = sgs_by_name[resource_name]
                if sg["GroupId"] not in scheduler_sg:
                    sgs[count] = {
                        "id": f"{sg['GroupId']}",
                        "description": f"{resource_name if resource_name else ''} {sg['GroupId']} {sg['GroupName']}",
                    }
                    count += 1
            [
                print("    {:2} > {}".format(key, sgs[key]["description"]))
                for key in sorted(sgs)
            ]
            allowed_choices = list(sgs.keys())
            choice = get_input(
                f"What security group for you want to use for {environment.upper()}",
                None,
                allowed_choices,
                int,
            )
            return {"success": True, "message": sgs[choice]["id"]}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def get_iam_roles(self, environment, selected_roles=None):
        if selected_roles is None:
            selected_roles = []
        try:
            print(
                f"\n====== Choose the {fg('misty_rose_3')}IAM role to use for the {environment.upper()}{attr('reset')} ======\n"
            )
            roles = {}
            count = 1

            iam_paginator = self.iam.get_paginator("list_roles")
            iam_iterator = iam_paginator.paginate()
            for page in iam_iterator:
                for role in page["Roles"]:
                    if role["RoleName"] not in selected_roles:
                        roles[count] = {
                            "arn": f"{role['Arn']}",
                            "name": role["RoleName"],
                            "description": f"{role['RoleName']} - {role['Description'] if 'Description' in role.keys() else ''}",
                        }
                        count += 1

            [
                print("    {} > {}".format(key, value["description"]))
                for key, value in roles.items()
            ]
            allowed_choices = list(roles.keys())
            choice = get_input(
                f"What IAM Role for you want to use for {environment.upper()}",
                None,
                allowed_choices,
                int,
            )
            return {"success": True, "message": roles[choice]}

        except Exception as err:
            print(err)
            return {"success": False, "message": str(err)}

    def get_rules_for_security_group(self, sg_ids):
        try:
            rules = {}
            for sg_id in sg_ids:
                for page in self.ec2.get_paginator(
                    "describe_security_groups"
                ).paginate():
                    for sg in page["SecurityGroups"]:
                        sg_rules = []
                        if sg["GroupId"] != sg_id:
                            continue
                        if "IpPermissions" in sg.keys():
                            for permission in sg["IpPermissions"]:
                                if "FromPort" in permission.keys():
                                    from_port = permission["FromPort"]
                                    to_port = permission["ToPort"]
                                else:
                                    # IpProtocol = -1 -> All Traffic
                                    from_port = 0
                                    to_port = 65535

                                approved_ips = []

                                if permission["IpRanges"].__len__() > 0:
                                    for r in permission["IpRanges"]:
                                        if "CidrIp" in r.keys():
                                            approved_ips.append(r["CidrIp"])

                                if permission["UserIdGroupPairs"].__len__() > 0:
                                    for g in permission["UserIdGroupPairs"]:
                                        if "GroupId" in g.keys():
                                            approved_ips.append(g["GroupId"])

                                sg_rules.append(
                                    {
                                        "from_port": from_port,
                                        "to_port": to_port,
                                        "approved_ips": approved_ips,
                                        "type": "ingress",
                                    }
                                )
                                rules[sg_id] = sg_rules

                        if "IpPermissionsEgress" in sg.keys():
                            for permission in sg["IpPermissionsEgress"]:
                                if "FromPort" in permission.keys():
                                    from_port = permission["FromPort"]
                                    to_port = permission["ToPort"]
                                else:
                                    # IpProtocol = -1 -> All Traffic
                                    from_port = 0
                                    to_port = 65535

                                approved_ips = []

                                if permission["IpRanges"].__len__() > 0:
                                    for r in permission["IpRanges"]:
                                        if "CidrIp" in r.keys():
                                            approved_ips.append(r["CidrIp"])

                                if permission["UserIdGroupPairs"].__len__() > 0:
                                    for g in permission["UserIdGroupPairs"]:
                                        if "GroupId" in g.keys():
                                            approved_ips.append(g["GroupId"])

                                sg_rules.append(
                                    {
                                        "from_port": from_port,
                                        "to_port": to_port,
                                        "approved_ips": approved_ips,
                                        "type": "egress",
                                    }
                                )
                                rules[sg_id] = sg_rules

            return {"success": True, "message": rules}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def get_fs_security_groups(self, cfn_params):
        try:
            filesystems = {}
            efs_ids = []
            fsx_ids = []
            sgs = []

            for fs_mount in {"fs_apps", "fs_data"}:
                fs_mount_provider = cfn_params.get(
                    f"{fs_mount}_provider", "unknown-provider"
                )

                if fs_mount_provider.lower() == "efs":
                    efs_ids.append(cfn_params[fs_mount])
                elif fs_mount_provider.lower() == "fsx_lustre":
                    fsx_ids.append(cfn_params[fs_mount])
                else:
                    print(f"ERROR: Do not know about provider: {fs_mount_provider}")

            for efs_id in efs_ids:
                for mount in self.efs.describe_mount_targets(
                    FileSystemId=efs_id.split(".")[0]
                )["MountTargets"]:
                    for sg in self.efs.describe_mount_target_security_groups(
                        MountTargetId=mount["MountTargetId"]
                    )["SecurityGroups"]:
                        if sg not in sgs:
                            sgs.append(sg)

                filesystems[efs_id] = sgs

            for fsx_id in fsx_ids:
                for network_interface in self.fsx.describe_file_systems(
                    FileSystemIds=[fsx_id]
                )["FileSystems"][0]["NetworkInterfaceIds"]:
                    for groups in self.ec2.describe_network_interface_attribute(
                        Attribute="groupSet", NetworkInterfaceId=network_interface
                    )["Groups"]:
                        sg = groups["GroupId"]
                        if sg not in sgs:
                            sgs.append(sg)

                filesystems[fsx_id] = sgs

            return {"success": True, "message": filesystems}

        except Exception as err:
            return {"success": False, "message": str(err)}

    def validate_sg_rules(self, cfn_params, check_fs=True):
        try:
            # Begin Verify Security Group Rules
            print(
                f"\n====== Please wait a little as we {fg('misty_rose_3')}validate your security group rules {attr('reset')} ======\n"
            )
            security_groups = [
                cfn_params["scheduler_sg"],
                cfn_params["compute_node_sg"],
            ]
            if "vpc_endpoint_sg" in cfn_params:
                security_groups.append(cfn_params["vpc_endpoint_sg"])
            sg_rules = self.get_rules_for_security_group(security_groups)
            if check_fs is True:
                fs_sg = self.get_fs_security_groups(cfn_params)

            if sg_rules["success"] is True:
                scheduler_sg_rules = sg_rules["message"][cfn_params["scheduler_sg"]]
                compute_node_sg_rules = sg_rules["message"][
                    cfn_params["compute_node_sg"]
                ]
                vpc_endpoint_sg_rules = sg_rules["message"].get(
                    cfn_params.get("vpc_endpoint_sg", None), None
                )
            else:
                print(f"{fg('red')}Error: {sg_rules['message']} {attr('reset')}")
                sys.exit(1)

            errors = {}
            # status == True means that the check passed
            errors["SCHEDULER_SG_IN_COMPUTE"] = {
                "status": False,
                "error": f"Compute Node SG must allow all TCP traffic from Scheduler SG",
                "resolution": f"Add new rule on {cfn_params['compute_node_sg']} that allow TCP ports '0-65535' for {cfn_params['scheduler_sg']}",
            }
            errors["COMPUTE_SG_IN_SCHEDULER"] = {
                "status": False,
                "error": f"Scheduler SG must allow all TCP traffic from Compute Node SG",
                "resolution": f"Add a new rule on {cfn_params['scheduler_sg']} that allow TCP ports '0-65535' for {cfn_params['compute_node_sg']}",
            }
            errors["CLIENT_IP_HTTPS_IN_SCHEDULER"] = {
                "status": False,
                "error": f"Client IP must be allowed for port 443 (80 optional) on Scheduler SG",
                "resolution": f"Add two rules on {cfn_params['scheduler_sg']} that allow TCP ports 80 and 443 for {self.client_ip}",
            }
            errors["CLIENT_IP_SSH_IN_SCHEDULER"] = {
                "status": False,
                "error": f"Client IP must be allowed for port 22 (SSH) on Scheduler SG",
                "resolution": f"Add one rule on {cfn_params['scheduler_sg']} that allow TCP port 22 for {self.client_ip}",
            }
            errors["SCHEDULER_SG_EQUAL_COMPUTE"] = {
                "status": False,
                "error": "Scheduler SG and Compute SG must be different",
                "resolution": "You must choose two different security groups",
            }
            errors["COMPUTE_SG_EGRESS_EFA"] = {
                "status": False,
                "error": "Compute SG must reference egress traffic to itself for EFA",
                "resolution": f"Add a new (EGRESS) rule on {cfn_params['compute_node_sg']} that allow TCP ports '0-65535' for {cfn_params['compute_node_sg']}. Make sure you configure EGRESS rule and not INGRESS",
            }
            if "vpc_endpoint_sg" in cfn_params:
                errors["COMPUTE_EGRESS_TO_VPC_ENDPOINTS"] = {
                    "status": False,
                    "error": "Compute SG must allow port 443 egress to the vpc endpoints security group",
                    "resolution": f"Add a new (EGRESS) rule on {cfn_params['compute_node_sg']} that allows TCP port '443' for {cfn_params['vpc_endpoint_sg']}. Make sure you configure EGRESS rule and not INGRESS",
                }
                errors["VPC_ENDPOINTS_INGRESS_FROM_COMPUTE"] = {
                    "status": False,
                    "error": "vpc Endpoints SG must allow port 443 ingress from the Compute SG",
                    "resolution": f"Add a new (INGRESS) rule on {cfn_params['vpc_endpoint_sg']} that allows TCP port '443' from {cfn_params['compute_node_sg']}. Make sure you configure INGRESS rule and not EGRESS",
                }
                errors["SCHEDULER_EGRESS_TO_VPC_ENDPOINTS"] = {
                    "status": False,
                    "error": "Scheduler SG must allow port 443 egress to the vpc endpoints security group",
                    "resolution": f"Add a new (EGRESS) rule on {cfn_params['scheduler_sg']} that allows TCP port '443' for {cfn_params['vpc_endpoint_sg']}. Make sure you configure EGRESS rule and not INGRESS",
                }
                errors["VPC_ENDPOINTS_INGRESS_FROM_SCHEDULER"] = {
                    "status": False,
                    "error": "vpc Endpoints SG must allow port 443 ingress from the Scheduler SG",
                    "resolution": f"Add a new (INGRESS) rule on {cfn_params['vpc_endpoint_sg']} that allows TCP port '443' from {cfn_params['scheduler_sg']}. Make sure you configure INGRESS rule and not EGRESS",
                }

            if check_fs is True:
                errors["FS_APP_SG"] = {
                    "status": False,
                    "error": f"SG assigned to EFS App {cfn_params['fs_apps']} must allow Scheduler SG and Compute SG",
                    "resolution": f"Add {cfn_params['scheduler_sg']} and {cfn_params['compute_node_sg']} on your EFS Apps {cfn_params['fs_apps']}",
                }

                errors["FS_DATA_SG"] = {
                    "status": False,
                    "error": f"SG assigned to EFS App {cfn_params['fs_data']} must allow Scheduler SG and Compute SG",
                    "resolution": f"Add {cfn_params['scheduler_sg']} and {cfn_params['compute_node_sg']} on your EFS Data {cfn_params['fs_data']}",
                }

            # Verify Scheduler Rules
            for rules in scheduler_sg_rules:
                if rules["from_port"] == 0 and rules["to_port"] == 65535:
                    for rule in rules["approved_ips"]:
                        if cfn_params["compute_node_sg"] in rule:
                            errors["COMPUTE_SG_IN_SCHEDULER"]["status"] = True

                if rules["from_port"] == 443 or rules["from_port"] == 22:
                    for rule in rules["approved_ips"]:
                        client_ip_netmask = 32
                        if client_ip_netmask == "32":
                            if ipaddress.IPv4Address(
                                self.client_ip
                            ) in ipaddress.IPv4Network(rule):
                                if rules["from_port"] == 443:
                                    errors["CLIENT_IP_HTTPS_IN_SCHEDULER"][
                                        "status"
                                    ] = True
                                if rules["from_port"] == 22:
                                    errors["CLIENT_IP_SSH_IN_SCHEDULER"][
                                        "status"
                                    ] = True
                        else:
                            if self.client_ip in rule:
                                if rules["from_port"] == 443:
                                    errors["CLIENT_IP_HTTPS_IN_SCHEDULER"][
                                        "status"
                                    ] = True
                                if rules["from_port"] == 22:
                                    errors["CLIENT_IP_SSH_IN_SCHEDULER"][
                                        "status"
                                    ] = True
            # Verify Compute Node Rules
            for rules in compute_node_sg_rules:
                if rules["from_port"] == 0 and rules["to_port"] == 65535:
                    for rule in rules["approved_ips"]:
                        if cfn_params["scheduler_sg"] in rule:
                            errors["SCHEDULER_SG_IN_COMPUTE"]["status"] = True

                        if rules["type"] == "egress":
                            if cfn_params["compute_node_sg"] in rule:
                                errors["COMPUTE_SG_EGRESS_EFA"]["status"] = True
            # Verify VPC Endpoint Rules
            if "vpc_endpoint_sg" in cfn_params:
                for rule in compute_node_sg_rules:
                    # Make sure compute node allows egress to vpc endpoints
                    if rule["type"] != "egress":
                        continue
                    for approved_ip in rule["approved_ips"]:
                        if rule["from_port"] <= 443 <= rule["to_port"]:
                            if cfn_params["vpc_endpoint_sg"] in approved_ip:
                                errors["COMPUTE_EGRESS_TO_VPC_ENDPOINTS"][
                                    "status"
                                ] = True
                for rule in scheduler_sg_rules:
                    # Make sure scheduler allows egress to vpc endpoints
                    if rule["type"] != "egress":
                        continue
                    for approved_ip in rule["approved_ips"]:
                        if rule["from_port"] <= 443 <= rule["to_port"]:
                            if cfn_params["vpc_endpoint_sg"] in approved_ip:
                                errors["SCHEDULER_EGRESS_TO_VPC_ENDPOINTS"][
                                    "status"
                                ] = True
                for rule in vpc_endpoint_sg_rules:
                    # Make sure endpoints allow ingress from compute nodes and scheduler
                    if rule["type"] != "ingress":
                        continue
                    for approved_ip in rule["approved_ips"]:
                        if rule["from_port"] <= 443 <= rule["to_port"]:
                            if cfn_params["scheduler_sg"] in approved_ip:
                                errors["VPC_ENDPOINTS_INGRESS_FROM_SCHEDULER"][
                                    "status"
                                ] = True
                            if cfn_params["compute_node_sg"] in approved_ip:
                                errors["VPC_ENDPOINTS_INGRESS_FROM_COMPUTE"][
                                    "status"
                                ] = True

            if check_fs is True:
                if (
                    cfn_params["scheduler_sg"]
                    in fs_sg["message"][cfn_params["fs_apps"]]
                    and cfn_params["compute_node_sg"]
                    in fs_sg["message"][cfn_params["fs_apps"]]
                ):
                    errors["FS_APP_SG"]["status"] = True

                if (
                    cfn_params["scheduler_sg"]
                    in fs_sg["message"][cfn_params["fs_data"]]
                    and cfn_params["compute_node_sg"]
                    in fs_sg["message"][cfn_params["fs_data"]]
                ):
                    errors["FS_DATA_SG"]["status"] = True

            if cfn_params["scheduler_sg"] != cfn_params["compute_node_sg"]:
                errors["SCHEDULER_SG_EQUAL_COMPUTE"]["status"] = True

            sg_errors = {}

            confirm_sg_settings = False
            for error_id, error_info in errors.items():
                if error_info["status"] is False:
                    if check_fs is False and "EFS" in error_id:
                        pass
                    else:
                        print(
                            f"{fg('yellow')}ATTENTION!! {error_info['error']} {attr('reset')}\nHow to solve: {error_info['resolution']}\n"
                        )
                        sg_errors[error_info["error"]] = error_info["resolution"]
                        confirm_sg_settings = True

            if confirm_sg_settings:
                choice = get_input(
                    "Your security groups may not be configured correctly. Verify them and determine if the warnings listed above are false-positive.\n Do you still want to continue with the installation?",
                    None,
                    ["yes", "no"],
                    str,
                )
                if choice.lower() == "no":
                    sys.exit(1)
            else:
                print(
                    f"{fg('green')} Security Groups seem to be configured correctly{attr('reset')}"
                )

            return {"success": True, "message": ""}

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(f"{exc_type} {fname} {exc_tb.tb_lineno}")
            return {
                "success": False,
                "message": f"{exc_type} {fname} {exc_tb.tb_lineno}",
            }
