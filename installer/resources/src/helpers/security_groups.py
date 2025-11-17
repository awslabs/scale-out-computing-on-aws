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

from aws_cdk import aws_ec2 as ec2
from constructs import Construct


def create_security_groups(
    scope: Construct,
    construct_id: str,
    vpc: str,
    allow_all_outbound: bool = False,
    allow_all_ipv6_outbound: bool = False,
    description: str = "",
) -> ec2.SecurityGroup:
    return ec2.SecurityGroup(
        scope=scope,
        id=construct_id,
        vpc=vpc,
        allow_all_outbound=allow_all_outbound,
        allow_all_ipv6_outbound=allow_all_ipv6_outbound,
        description=description,
    )


def use_existing_security_group(
    scope: Construct, construct_id: str, security_group_id: str
) -> ec2.SecurityGroup:
    return ec2.SecurityGroup.from_security_group_id(
        scope=scope, id=construct_id, security_group_id=security_group_id
    )


def create_ingress_rule(
    security_group: ec2.SecurityGroup,
    peer: list | ec2.Peer,
    connection: ec2.Port,
    description: str,
):
    return security_group.add_ingress_rule(peer, connection, description)


def create_egress_rule(
    security_group: ec2.SecurityGroup,
    peer: ec2.Peer,
    connection: ec2.Port,
    description: str,
):
    return security_group.add_egress_rule(peer, connection, description)
