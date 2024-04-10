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

import config
from flask_restful import Resource, reqparse
from requests import get
import logging
from datetime import datetime
import read_secretmanager
from decorators import private_api
from flask import request
import re
import boto3
import uuid
import errors
import sys
import os
import random
from botocore.exceptions import ClientError
from models import db, LinuxDCVSessions, WindowsDCVSessions, AmiList
import dcv_cloudformation_builder

logger = logging.getLogger("api")
client_ec2 = boto3.client("ec2", config=config.boto_extra_config())
client_cfn = boto3.client("cloudformation", config=config.boto_extra_config())


def validate_ec2_image(image_id):
    image_exist = (
        AmiList.query.filter(AmiList.is_active == True, AmiList.ami_id == image_id)
        .filter(AmiList.ami_type != "windows")
        .first()
    )
    if image_exist:
        return True
    else:
        return False


def get_arch_for_instance_type(region: str, instancetype: str) -> str:
    _found_arch = None
    ec2_client = boto3.client("ec2", region_name=region)
    _resp = ec2_client.describe_instance_types(InstanceTypes=[instancetype])

    _instance_info = _resp.get("InstanceTypes", {})

    for _i in _instance_info:
        _instance_name = _i.get("InstanceType", None)
        # This shouldn't happen with an exact-match search
        if _instance_name != instancetype:
            continue

        _proc_info = _i.get("ProcessorInfo", {})
        if _proc_info:
            _arch = sorted(_proc_info.get("SupportedArchitectures", []))
            _found_arch = _arch[0]

    return _found_arch


def can_launch_instance(launch_parameters):
    try:
        if launch_parameters["base_os"] in {"amazonlinux2", "amazonlinux2023"}:
            _ebs_device_name = "/dev/xvda"
        else:
            _ebs_device_name = "/dev/sda1"

        client_ec2.run_instances(
            BlockDeviceMappings=[
                {
                    "DeviceName": _ebs_device_name,
                    "Ebs": {
                        "DeleteOnTermination": True,
                        "VolumeSize": launch_parameters["disk_size"],
                        "VolumeType": launch_parameters.get("VolumeType", "gp2"),
                        "Encrypted": True,
                    },
                },
            ],
            MaxCount=1,
            MinCount=1,
            SecurityGroupIds=[launch_parameters["security_group_id"]],
            InstanceType=launch_parameters["instance_type"],
            IamInstanceProfile={"Arn": launch_parameters["instance_profile"]},
            SubnetId=random.choice(launch_parameters["soca_private_subnets"])
            if not launch_parameters["subnet_id"]
            else launch_parameters["subnet_id"],
            Placement={"Tenancy": launch_parameters["tenancy"]},
            UserData=launch_parameters["user_data"],
            ImageId=launch_parameters["image_id"],
            DryRun=True,
            HibernationOptions={"Configured": launch_parameters["hibernate"]},
        )

    except ClientError as err:
        if err.response["Error"].get("Code") == "DryRunOperation":
            return True
        else:
            return f"Dry run failed. Unable to launch capacity due to: {err}"


def session_already_exist(session_number):
    user_sessions = {}
    get_desktops = get(
        config.Config.FLASK_ENDPOINT + "/api/dcv/desktops",
        headers={
            "X-SOCA-USER": request.headers.get("X-SOCA-USER"),
            "X-SOCA-TOKEN": request.headers.get("X-SOCA-TOKEN"),
        },
        params={
            "os": "linux",
            "is_active": "true",
            "session_number": str(session_number),
        },
        verify=False,
    )
    if get_desktops.status_code == 200:
        user_sessions = get_desktops.json()["message"]
        user_sessions = {
            int(k): v for k, v in user_sessions.items()
        }  # convert all keys (session number) back to integer

    if int(session_number) in user_sessions.keys():
        return True
    else:
        return False


class CreateLinuxDesktop(Resource):
    @private_api
    def post(self, session_number):
        """
        Create a new DCV desktop session (Linux)
        ---
        tags:
          - DCV

        parameters:
          - in: body
            name: body
            schema:
              required:
                - instance_type
                - disk_size
                - session_number
                - instance_ami
                - subnet_id
                - hibernate
              properties:
                instance_type:
                  type: string
                  description: Type of EC2 instance to provision
                disk_size:
                  type: string
                  description: EBS size to provision for root device
                session_number:
                  type: string
                  description: DCV Session Number
                session_name:
                  type: string
                  description: DCV Session Name
                instance_ami:
                  type: string
                  description: Custom AMI to use
                subnet_id:
                  type: string
                  description: Specify a subnet id to launch the EC2
                hibernate:
                  type: string
                  description: True/False.
                user:
                  type: string
                  description: owner of the session
                tenancy:
                  type: string
                  description: EC2 tenancy (default or dedicated)
        responses:
          200:
            description: Pair of user/token is valid
          401:
            description: Invalid user/token pair
        """

        parser = reqparse.RequestParser()
        parser.add_argument("instance_type", type=str, location="form")
        parser.add_argument("disk_size", type=str, location="form")
        parser.add_argument("session_name", type=str, location="form")
        parser.add_argument("instance_ami", type=str, location="form")
        parser.add_argument("subnet_id", type=str, location="form")
        parser.add_argument("hibernate", type=str, location="form")
        parser.add_argument("tenancy", type=str, location="form")
        args = parser.parse_args()
        logger.info(f"Received parameter for new Linux DCV session: {args}")

        if not args["subnet_id"]:
            args["subnet_id"] = False

        if session_number is None:
            return errors.all_errors(
                "CLIENT_MISSING_PARAMETER",
                "session_number not found in URL. Endpoint is /api/dcv/desktop/<session_number>/linux",
            )
        else:
            args["session_number"] = str(session_number)

        try:
            user = request.headers.get("X-SOCA-USER")
            if user is None:
                return errors.all_errors("X-SOCA-USER_MISSING")

            if not args["hibernate"]:
                args["hibernate"] = False
            elif args["hibernate"].lower() == "false":
                args["hibernate"] = False
            elif args["hibernate"].lower() == "true":
                args["hibernate"] = True
            else:
                return errors.all_errors(
                    "DCV_LAUNCH_ERROR", f"hibernate must be either true or false"
                )

            if args["instance_type"] is None:
                return errors.all_errors(
                    "CLIENT_MISSING_PARAMETER", "instance_type (str) is required."
                )

            args["disk_size"] = 40 if args["disk_size"] is None else args["disk_size"]
            try:
                args["disk_size"] = int(args["disk_size"])
            except ValueError:
                return errors.all_errors(
                    "DCV_LAUNCH_ERROR", f"disk_size must be an integer"
                )

            try:
                if int(args["session_number"]) > int(
                    config.Config.DCV_LINUX_SESSION_COUNT
                ):
                    return errors.all_errors(
                        "DCV_LAUNCH_ERROR",
                        f"session_number {args['session_number']} is greater than the max number of session allowed ({config.Config.DCV_LINUX_SESSION_COUNT}). Contact admin for increase.",
                    )
            except Exception as err:
                return errors.all_errors(
                    "DCV_LAUNCH_ERROR",
                    f"Session Number {args['session_number']} must be a number. Err: {err}",
                )

            session_uuid = str(uuid.uuid4())
            # TODO - should this be from the soca_configuration instead?
            region = os.environ["AWS_DEFAULT_REGION"]
            instance_type = args["instance_type"]

            _instance_architecture = get_arch_for_instance_type(region=region, instancetype=instance_type)

            soca_configuration = read_secretmanager.get_soca_configuration()
            instance_profile = soca_configuration["ComputeNodeInstanceProfileArn"]
            security_group_id = soca_configuration["ComputeNodeSecurityGroup"]

            if session_already_exist(args["session_number"]) is True:
                return errors.all_errors(
                    "DCV_LAUNCH_ERROR",
                    f"Session Number {args['session_number']} is already used by an active desktop. Terminate it first before being able to use the same number",
                )

            # sanitize session_name
            if args["session_name"] is None:
                session_name = "LinuxDesktop" + str(args["session_number"])
            else:
                session_name = re.sub(r"\W+", "", args["session_name"])[:255]
                if session_name == "":
                    # handle case when session name specified by user only contains invalid char
                    session_name = "LinuxDesktop" + str(args["session_number"])
            # Cleanup unwanted characters that can conflict in CloudFormation StackNames
            # TODO - move to common
            session_name = re.sub(
                pattern=r"[-_=]+",
                repl="",
                string=str(session_name)[:32]
            )[:32]

            logger.debug(f"Session name sanitized to: {session_name}")
            if args.get("instance_ami", None) is None:
                # TODO - Should the BaseOS be from the configuration or the job param?
                base_os = soca_configuration.get("BaseOS", "amazonlinux2")
                image_id = soca_configuration.get("CustomAMIMap", {}).get(_instance_architecture).get(base_os)
                if logger.isEnabledFor(logging.DEBUG):
                    logger.debug(f"ImageID (AMI) lookup result for {base_os}/{_instance_architecture} - {image_id}")

            else:
                if len(args["instance_ami"].split(",")) != 2:
                    return errors.all_errors(
                        "DCV_LAUNCH_ERROR",
                        f"Invalid format for instance_ami,base_os : {args['instance_ami']}",
                    )

                image_id = args["instance_ami"].split(",")[0]
                base_os = args["instance_ami"].split(",")[1]
                if not image_id.startswith("ami-"):
                    return errors.all_errors(
                        "DCV_LAUNCH_ERROR",
                        f"AMI {image_id} does not seems to be valid. Must start with ami-<id>",
                    )
                else:
                    if validate_ec2_image(image_id) is False:
                        return errors.all_errors(
                            "DCV_LAUNCH_ERROR",
                            f"AMI {image_id} does not seems to be registered on SOCA. Refer to https://awslabs.github.io/scale-out-computing-on-aws/web-interface/create-virtual-desktops-images/",
                        )

            user_data = (
                '''#!/bin/bash -x
            export PATH=$PATH:/usr/local/bin
            
            if [[ "'''
            + base_os
            + '''" =~ "centos" ]] || [[ "'''
            + base_os
            + '''" =~ "rhel" ]] || [[ "'''
            + base_os
            + '''" =~ "rocky" ]];
            then
                    yum install -y python3-pip
                    PIP=$(which pip3)
                    $PIP install awscli
                    yum install -y nfs-utils # enforce install of nfs-utils
            else
                 yum install -y python3-pip cronie
                 PIP=$(which pip3)
                 $PIP install awscli
            fi
            if [[ "'''
                + base_os
                + """" =~ "amazonlinux2" ]];
                then
                    /usr/sbin/update-motd --disable
                    rm -f /etc/update-motd.d/*

            fi
    
            IMDS_TOKEN=$(curl --silent -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
            GET_INSTANCE_TYPE=$(curl --silent -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/instance-type)
            echo export "SOCA_DCV_AUTHENTICATOR="https://"""
                + soca_configuration["SchedulerPrivateDnsName"]
                + """:"""
                + config.Config.FLASK_PORT
                + '''/api/dcv/authenticator"" >> /etc/environment
            echo export "SOCA_DCV_SESSION_ID="'''
                + str(session_uuid)
                + '''"" >> /etc/environment
            echo export "SOCA_CONFIGURATION="'''
                + str(soca_configuration["ClusterId"])
                + '''"" >> /etc/environment
            echo export "SOCA_DCV_OWNER="'''
                + user
                + '''"" >> /etc/environment
            echo export "SOCA_BASE_OS="'''
                + str(base_os)
                + '''"" >> /etc/environment
            echo export "SOCA_JOB_TYPE="dcv"" >> /etc/environment
            echo export "SOCA_INSTALL_BUCKET="'''
                + str(soca_configuration["S3Bucket"])
                + '''"" >> /etc/environment
            echo export "SOCA_FSX_LUSTRE_BUCKET="false"" >> /etc/environment
            echo export "SOCA_FSX_LUSTRE_DNS="false"" >> /etc/environment
            echo export "SOCA_INSTALL_BUCKET_FOLDER="'''
                + str(soca_configuration["S3InstallFolder"])
                + """"" >> /etc/environment
            echo export "SOCA_INSTANCE_TYPE=$GET_INSTANCE_TYPE" >> /etc/environment
            echo export "SOCA_HOST_SYSTEM_LOG="/apps/soca/"""
                + str(soca_configuration["ClusterId"])
                + """/cluster_node_bootstrap/logs/desktop/"""
                + user
                + """/"""
                + session_name
                + '''/$(hostname -s)"" >> /etc/environment
            echo export "AWS_DEFAULT_REGION="'''
                + region
                + '''"" >> /etc/environment
            echo export "SOCA_AUTH_PROVIDER="'''
                + str(soca_configuration["AuthProvider"]).lower()
                + '''"" >> /etc/environment
            echo export "AWS_STACK_ID=${AWS::StackName}" >> /etc/environment
            echo export "AWS_DEFAULT_REGION=${AWS::Region}" >> /etc/environment
            # Required for proper EBS tagging
            echo export "SOCA_JOB_ID="'''
                + str(session_name)
                + '''"" >> /etc/environment
            echo export "SOCA_JOB_OWNER="'''
                + user
                + '''"" >> /etc/environment
            echo export "SOCA_JOB_PROJECT="dcv"" >> /etc/environment
            echo export "SOCA_JOB_QUEUE="dcv"" >> /etc/environment
    
    
            source /etc/environment
            AWS=$(which aws)
            # Give yum permission to the user on this specific machine
            echo "'''
                + user
                + """ ALL=(ALL) /bin/yum" >> /etc/sudoers
            mkdir -p /apps
            mkdir -p /data

            FS_DATA_PROVIDER="""
                + soca_configuration["FileSystemDataProvider"]
                + """
            FS_DATA="""
                + soca_configuration["FileSystemData"]
                + """
            FS_APPS_PROVIDER="""
                + soca_configuration["FileSystemAppsProvider"]
                + """
            FS_APPS="""
                + soca_configuration["FileSystemApps"]
                + '''

            if [[ "$FS_DATA_PROVIDER" == "fsx_lustre" ]] || [[ "$FS_APPS_PROVIDER" == "fsx_lustre" ]]; then
                if [[ -z "$(rpm -qa lustre-client)" ]]; then
                    # Install FSx for Lustre Client
                    if [[ "$SOCA_BASE_OS" == "amazonlinux2" ]]; then
                        amazon-linux-extras install -y lustre
                    else
                        kernel=$(uname -r)
                        machine=$(uname -m)
                        echo "Found kernel version: $kernel running on: $machine"
                        yum -y install wget
                        if [[ $kernel == *"3.10.0-957"*$machine ]]; then
                            yum -y install https://downloads.whamcloud.com/public/lustre/lustre-2.10.8/el7/client/RPMS/x86_64/kmod-lustre-client-2.10.8-1.el7.x86_64.rpm
                            yum -y install https://downloads.whamcloud.com/public/lustre/lustre-2.10.8/el7/client/RPMS/x86_64/lustre-client-2.10.8-1.el7.x86_64.rpm
                        elif [[ $kernel == *"3.10.0-1062"*$machine ]]; then
                            wget https://fsx-lustre-client-repo-public-keys.s3.amazonaws.com/fsx-rpm-public-key.asc -O /tmp/fsx-rpm-public-key.asc
                            rpm --import /tmp/fsx-rpm-public-key.asc
                            wget https://fsx-lustre-client-repo.s3.amazonaws.com/el/7/fsx-lustre-client.repo -O /etc/yum.repos.d/aws-fsx.repo
                            sed -i 's#7#7.7#' /etc/yum.repos.d/aws-fsx.repo
                            yum clean all
                            yum install -y kmod-lustre-client lustre-client
                        elif [[ $kernel == *"3.10.0-1127"*$machine ]]; then
                            wget https://fsx-lustre-client-repo-public-keys.s3.amazonaws.com/fsx-rpm-public-key.asc -O /tmp/fsx-rpm-public-key.asc
                            rpm --import /tmp/fsx-rpm-public-key.asc
                            wget https://fsx-lustre-client-repo.s3.amazonaws.com/el/7/fsx-lustre-client.repo -O /etc/yum.repos.d/aws-fsx.repo
                            sed -i 's#7#7.8#' /etc/yum.repos.d/aws-fsx.repo
                            yum clean all
                            yum install -y kmod-lustre-client lustre-client
                        elif [[ $kernel == *"3.10.0-1160"*$machine ]]; then
                            wget https://fsx-lustre-client-repo-public-keys.s3.amazonaws.com/fsx-rpm-public-key.asc -O /tmp/fsx-rpm-public-key.asc
                            rpm --import /tmp/fsx-rpm-public-key.asc
                            wget https://fsx-lustre-client-repo.s3.amazonaws.com/el/7/fsx-lustre-client.repo -O /etc/yum.repos.d/aws-fsx.repo
                            yum clean all
                            yum install -y kmod-lustre-client lustre-client
                        elif [[ $kernel == *"4.18.0-193"*$machine ]]; then
                            # FSX for Lustre on aarch64 is supported only on 4.18.0-193
                            wget https://fsx-lustre-client-repo-public-keys.s3.amazonaws.com/fsx-rpm-public-key.asc -O /tmp/fsx-rpm-public-key.asc
                            rpm --import /tmp/fsx-rpm-public-key.asc
                            wget https://fsx-lustre-client-repo.s3.amazonaws.com/centos/7/fsx-lustre-client.repo -O /etc/yum.repos.d/aws-fsx.repo
                            yum clean all
                            yum install -y kmod-lustre-client lustre-client
                        else
                            echo "ERROR: Can't install FSx for Lustre client as kernel version: $kernel isn't matching expected versions: (x86_64: 3.10.0-957, -1062, -1127, -1160, aarch64: 4.18.0-193)!"
                        fi
                    fi
                fi
            fi

            if [[ "$FS_DATA_PROVIDER" == "efs" ]]; then
                echo "$FS_DATA:/ /data nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport 0 0" >> /etc/fstab
            elif [[ "$FS_DATA_PROVIDER" == "fsx_lustre" ]]; then
                FSX_ID=$(echo $FS_DATA | cut -d. -f1)
                FSX_DATA_MOUNT_NAME=$($AWS fsx describe-file-systems --file-system-ids $FSX_ID  --query FileSystems[].LustreConfiguration.MountName --output text)
                echo "$FS_DATA@tcp:/$FSX_DATA_MOUNT_NAME /data lustre defaults,noatime,flock,_netdev 0 0" >> /etc/fstab
            fi

            if [[ "$FS_APPS_PROVIDER" == "efs" ]]; then
                echo "$FS_APPS:/ /apps nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport 0 0" >> /etc/fstab
            elif [[ "$FS_APPS_PROVIDER" == "fsx_lustre" ]]; then
                FSX_ID=$(echo $FS_APPS | cut -d. -f1)
                FSX_APPS_MOUNT_NAME=$($AWS fsx describe-file-systems --file-system-ids $FSX_ID  --query FileSystems[].LustreConfiguration.MountName --output text)
                echo "$FS_APPS@tcp:/$FSX_APPS_MOUNT_NAME /apps lustre defaults,noatime,flock,_netdev 0 0" >> /etc/fstab
            fi

            FS_MOUNT=0
            mount -a 
            while [[ $? -ne 0 ]] && [[ $FS_MOUNT -lt 5 ]]
            do
                SLEEP_TIME=$(( RANDOM % 60 ))
                echo "Failed to mount FS, retrying in $SLEEP_TIME seconds and Loop $FS_MOUNT/5..."
                sleep $SLEEP_TIME
                ((FS_MOUNT++))
                mount -a
            done
                
            # Configure Chrony
            yum remove -y ntp
            yum install -y chrony
            mv /etc/chrony.conf  /etc/chrony.conf.original
            echo -e """
            # use the local instance NTP service, if available
            server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4
    
            # Use public servers from the pool.ntp.org project.
            # Please consider joining the pool (https://www.ntppool.org/join.html).
            # !!! [BEGIN] SOCA REQUIREMENT
            # You will need to open UDP egress traffic on your security group if you want to enable public pool
            #pool 2.amazon.pool.ntp.org iburst
            # !!! [END] SOCA REQUIREMENT
            # Record the rate at which the system clock gains/losses time.
            driftfile /var/lib/chrony/drift
    
            # Allow the system clock to be stepped in the first three updates
            # if its offset is larger than 1 second.
            makestep 1.0 3
    
            # Specify file containing keys for NTP authentication.
            keyfile /etc/chrony.keys
    
            # Specify directory for log files.
            logdir /var/log/chrony
    
            # save data between restarts for fast re-load
            dumponexit
            dumpdir /var/run/chrony
            """ > /etc/chrony.conf
    
            systemctl enable chronyd
            # Prepare  Log folder
            mkdir -p $SOCA_HOST_SYSTEM_LOG
            echo "@reboot /bin/bash /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ComputeNodePostReboot.sh >> $SOCA_HOST_SYSTEM_LOG/ComputeNodePostReboot.log 2>&1" | crontab -
            cp /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/config.cfg /root/
            /bin/bash /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ComputeNode.sh '''
                + soca_configuration["SchedulerPrivateDnsName"]
                + """ >> $SOCA_HOST_SYSTEM_LOG/ComputeNode.sh.log 2>&1"""
            )

            if args["hibernate"]:
                try:
                    check_hibernation_support = client_ec2.describe_instance_types(
                        InstanceTypes=[instance_type],
                        Filters=[{"Name": "hibernation-supported", "Values": ["true"]}],
                    )
                    logger.info(
                        f"Checking instance {instance_type} for Hibernation support: {check_hibernation_support}"
                    )
                    if len(check_hibernation_support.get("InstanceTypes", {})) == 0:
                        if config.Config.DCV_FORCE_INSTANCE_HIBERNATE_SUPPORT is True:
                            return errors.all_errors(
                                "DCV_LAUNCH_ERROR",
                                f"Sorry your administrator limited <a href='https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Hibernate.html' target='_blank' rel='noopener,noreferrer'>DCV to instances that support hibernation mode</a> <br> Please choose a different type of instance.",
                            )
                        else:
                            return errors.all_errors(
                                "DCV_LAUNCH_ERROR",
                                f"Sorry you have selected {instance_type} with hibernation support, but this instance type does not support it. Either disable hibernation support or pick a different instance type",
                            )

                except ClientError as e:
                    return errors.all_errors(
                        "DCV_LAUNCH_ERROR",
                        f"Error while checking hibernation support of instance {instance_type} due to {e}",
                    )

            launch_parameters = {
                "security_group_id": security_group_id,
                "instance_profile": instance_profile,
                "instance_type": instance_type,
                "soca_private_subnets": soca_configuration["PrivateSubnets"],
                "user_data": user_data,
                "subnet_id": args["subnet_id"],
                "tenancy": args["tenancy"],
                "image_id": image_id,
                "session_name": session_name,
                "session_uuid": session_uuid,
                "base_os": base_os,
                "disk_size": args["disk_size"],
                "volume_type": soca_configuration.get("DefaultVolumeType", 'gp2'),
                "cluster_id": soca_configuration["ClusterId"],
                "metadata_http_tokens": soca_configuration["MetadataHttpTokens"],
                "hibernate": args["hibernate"],
                "user": user,
                "Version": soca_configuration.get("Version", ""),
                "Region": soca_configuration.get("Region", ""),
                "Misc": soca_configuration.get("Misc", ""),
                "DefaultMetricCollection": True
                if soca_configuration["DefaultMetricCollection"] == "true"
                else False,
                "SolutionMetricsLambda": soca_configuration["SolutionMetricsLambda"],
                "ComputeNodeInstanceProfileArn": soca_configuration[
                    "ComputeNodeInstanceProfileArn"
                ],
            }
            dry_run_launch = can_launch_instance(launch_parameters)
            if dry_run_launch is True:
                launch_template = dcv_cloudformation_builder.main(**launch_parameters)
                if launch_template["success"] is True:
                    cfn_stack_name = str(
                        launch_parameters["cluster_id"]
                        + "-"
                        + launch_parameters["session_name"]
                        + "-"
                        + launch_parameters["user"]
                    )
                    cfn_stack_tags = [
                        {
                            "Key": "soca:JobName",
                            "Value": str(launch_parameters["session_name"]),
                        },
                        {"Key": "soca:JobOwner", "Value": user},
                        {"Key": "soca:JobProject", "Value": "desktop"},
                        {
                            "Key": "soca:ClusterId",
                            "Value": str(launch_parameters["cluster_id"]),
                        },
                        {"Key": "soca:NodeType", "Value": "dcv"},
                        {"Key": "soca:DCVSystem", "Value": base_os},
                    ]
                    try:
                        client_cfn.create_stack(
                            StackName=cfn_stack_name,
                            TemplateBody=launch_template["output"],
                            Tags=cfn_stack_tags,
                        )
                    except Exception as e:
                        logger.error(
                            f"Error while trying to provision {cfn_stack_name} due to {e}"
                        )
                        return errors.all_errors(
                            "DCV_LAUNCH_ERROR",
                            f"Error while trying to provision {cfn_stack_name} due to {e}",
                        )
                else:
                    return errors.all_errors(
                        "DCV_LAUNCH_ERROR", f"{launch_template['output']}"
                    )
            else:
                return errors.all_errors(
                    "DCV_LAUNCH_ERROR", f" Dry Run error: {dry_run_launch}"
                )

            new_session = LinuxDCVSessions(
                user=user,
                session_number=args["session_number"],
                session_name=session_name,
                session_state="pending",
                session_host_private_dns=False,
                session_host_private_ip=False,
                session_instance_type=instance_type,
                session_linux_distribution=base_os,
                dcv_authentication_token=None,
                session_id=session_uuid,
                tag_uuid=session_uuid,
                session_token=str(uuid.uuid4()),
                is_active=True,
                support_hibernation=args["hibernate"],
                created_on=datetime.utcnow(),
                schedule_monday_start=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_tuesday_start=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_wednesday_start=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_thursday_start=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_friday_start=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["start"],
                schedule_saturday_start=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekend"
                ]["start"],
                schedule_sunday_start=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekend"
                ]["start"],
                schedule_monday_stop=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_tuesday_stop=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_wednesday_stop=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_thursday_stop=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_friday_stop=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekdays"
                ]["stop"],
                schedule_saturday_stop=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekend"
                ]["stop"],
                schedule_sunday_stop=config.Config.DCV_LINUX_DEFAULT_SCHEDULE[
                    "weekend"
                ]["stop"],
            )
            db.session.add(new_session)
            db.session.commit()
            return {
                "success": True,
                "message": f"Session {session_name} with ID {args['session_number']} started successfully.",
            }, 200
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            logger.error(exc_type, fname, exc_tb.tb_lineno)
            return errors.all_errors(type(err).__name__, err)
