import os
import sys

from troposphere import Base64, GetAtt
from troposphere import Ref, Template, Sub
from troposphere import Tags as base_Tags  # without PropagateAtLaunch
from troposphere.autoscaling import AutoScalingGroup, \
    LaunchTemplateSpecification, \
    Tags, \
    LaunchTemplateOverrides, \
    MixedInstancesPolicy, \
    InstancesDistribution
from troposphere.autoscaling import LaunchTemplate as asg_LaunchTemplate
from troposphere.cloudformation import AWSCustomObject
from troposphere.ec2 import PlacementGroup, \
    BlockDeviceMapping, \
    LaunchTemplate, \
    LaunchTemplateData, \
    EBSBlockDevice, \
    IamInstanceProfile, \
    InstanceMarketOptions, \
    NetworkInterfaces, \
    SpotOptions, \
    CpuOptions,\
    LaunchTemplateBlockDeviceMapping

from troposphere.fsx import FileSystem, LustreConfiguration
import troposphere.ec2 as ec2


class CustomResourceSendAnonymousMetrics(AWSCustomObject):
    resource_type = "Custom::SendAnonymousMetrics"
    props = {
        "ServiceToken": (str, True),
        "DesiredCapacity": (str, True),
        "InstanceType": (str, True),
        "Efa": (str, True),
        "ScratchSize": (str, True),
        "RootSize": (str, True),
        "SpotPrice": (str, True),
        "BaseOS": (str, True),
        "StackUUID": (str, True),
        "KeepForever": (str, True),
        "TerminateWhenIdle": (str, True),
        "FsxLustre": (str, True),
        "Dcv": (str, True),
    }


def main(**params):
    try:
        # Metadata
        t = Template()
        t.set_version("2010-09-09")
        t.set_description("(SOCA) - Base template to deploy compute nodes. Version 2.6.0")
        allow_anonymous_data_collection = params["MetricCollectionAnonymous"]
        debug = False
        mip_usage = False
        instances_list = params["InstanceType"] # list of instance type. Use + to specify more than one type
        asg_lt = asg_LaunchTemplate()
        ltd = LaunchTemplateData("NodeLaunchTemplateData")
        mip = MixedInstancesPolicy()
        stack_name = Ref("AWS::StackName")

        # Begin LaunchTemplateData
        UserData = '''#!/bin/bash -x
export PATH=$PATH:/usr/local/bin
if [[ "''' + params['BaseOS'] + '''" == "centos7" ]] || [[ "''' + params['BaseOS'] + '''" == "rhel7" ]];
then
     yum install -y python3-pip
     PIP=$(which pip3)
     $PIP install awscli
     yum install -y nfs-utils # enforce install of nfs-utils
else
     yum install -y python3-pip
     PIP=$(which pip3)
     $PIP install awscli
fi
if [[ "''' + params['BaseOS'] + '''" == "amazonlinux2" ]];
    then
        /usr/sbin/update-motd --disable
fi

GET_INSTANCE_TYPE=$(curl http://169.254.169.254/latest/meta-data/instance-type)
echo export "SOCA_CONFIGURATION="''' + str(params['ClusterId']) + '''"" >> /etc/environment
echo export "SOCA_BASE_OS="''' + str(params['BaseOS']) + '''"" >> /etc/environment
echo export "SOCA_JOB_QUEUE="''' + str(params['JobQueue']) + '''"" >> /etc/environment
echo export "SOCA_JOB_OWNER="''' + str(params['JobOwner']) + '''"" >> /etc/environment
echo export "SOCA_JOB_NAME="''' + str(params['JobName']) + '''"" >> /etc/environment
echo export "SOCA_JOB_PROJECT="''' + str(params['JobProject']) + '''"" >> /etc/environment
echo export "SOCA_VERSION="''' + str(params['Version']) + '''"" >> /etc/environment
echo export "SOCA_JOB_EFA="''' + str(params['Efa']).lower() + '''"" >> /etc/environment
echo export "SOCA_JOB_ID="''' + str(params['JobId']) + '''"" >> /etc/environment
echo export "SOCA_SCRATCH_SIZE=''' + str(params['ScratchSize']) + '''" >> /etc/environment
echo export "SOCA_INSTALL_BUCKET="''' + str(params['S3Bucket']) + '''"" >> /etc/environment
echo export "SOCA_INSTALL_BUCKET_FOLDER="''' + str(params['S3InstallFolder']) + '''"" >> /etc/environment
echo export "SOCA_FSX_LUSTRE_BUCKET="''' + str(params['FSxLustreConfiguration']['fsx_lustre']).lower() + '''"" >> /etc/environment
echo export "SOCA_FSX_LUSTRE_DNS="''' + str(params['FSxLustreConfiguration']['existing_fsx']).lower() + '''"" >> /etc/environment
echo export "SOCA_INSTANCE_TYPE=$GET_INSTANCE_TYPE" >> /etc/environment
echo export "SOCA_INSTANCE_HYPERTHREADING="''' + str(params['ThreadsPerCore']).lower() + '''"" >> /etc/environment
echo export "SOCA_SYSTEM_METRICS="''' + str(params['SystemMetrics']).lower() + '''"" >> /etc/environment
echo export "SOCA_ESDOMAIN_ENDPOINT="''' + str(params['ESDomainEndpoint']).lower() + '''"" >> /etc/environment


echo export "SOCA_HOST_SYSTEM_LOG="/apps/soca/''' + str(params['ClusterId']) + '''/cluster_node_bootstrap/logs/''' + str(params['JobId']) + '''/$(hostname -s)"" >> /etc/environment
echo export "AWS_STACK_ID=${AWS::StackName}" >> /etc/environment
echo export "AWS_DEFAULT_REGION=${AWS::Region}" >> /etc/environment


source /etc/environment
AWS=$(which aws)

# Give yum permission to the user on this specific machine
echo "''' + params['JobOwner'] + ''' ALL=(ALL) /bin/yum" >> /etc/sudoers

mkdir -p /apps
mkdir -p /data

# Mount EFS
echo "''' + params['EFSDataDns'] + ''':/ /data nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport 0 0" >> /etc/fstab
echo "''' + params['EFSAppsDns'] + ''':/ /apps nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport 0 0" >> /etc/fstab
EFS_MOUNT=0
mount -a 
while [[ $? -ne 0 ]] && [[ $EFS_MOUNT -lt 5 ]]
  do
    SLEEP_TIME=$(( RANDOM % 60 ))
    echo "Failed to mount EFS, retrying in $SLEEP_TIME seconds and Loop $EFS_MOUNT/5..."
    sleep $SLEEP_TIME
    ((EFS_MOUNT++))
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
# Please consider joining the pool (http://www.pool.ntp.org/join.html).
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
$AWS s3 cp s3://$SOCA_INSTALL_BUCKET/$SOCA_INSTALL_BUCKET_FOLDER/scripts/config.cfg /root/
/bin/bash /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ComputeNode.sh ''' + params['SchedulerHostname'] + ''' >> $SOCA_HOST_SYSTEM_LOG/ComputeNode.sh.log 2>&1'''

        SpotFleet = True if ((params["SpotPrice"] is not False) and (int(params["DesiredCapacity"]) > 1 or len(instances_list)>1)) else False
        ltd.EbsOptimized = True
        for instance in instances_list:
            if "t2." in instance:
                ltd.EbsOptimized = False

            # metal + t2 does not support CpuOptions
            unsupported = ["t2.", "metal"]
            if all(itype not in instance for itype in unsupported) and (SpotFleet is False or len(instances_list) == 1):
                # Spotfleet with multiple instance types doesn't support CpuOptions
                # So we can't add CpuOptions if SpotPrice is specified and when multiple instances are specified
                ltd.CpuOptions = CpuOptions(
                    CoreCount=int(params["CoreCount"]),
                    ThreadsPerCore=1 if params["ThreadsPerCore"] is False else 2)

        ltd.IamInstanceProfile = IamInstanceProfile(Arn=params["ComputeNodeInstanceProfileArn"])
        ltd.KeyName = params["SSHKeyPair"]
        ltd.ImageId = params["ImageId"]
        if params["SpotPrice"] is not False and params["SpotAllocationCount"] is False:
            ltd.InstanceMarketOptions = InstanceMarketOptions(
                MarketType="spot",
                SpotOptions=SpotOptions(
                    MaxPrice=Ref("AWS::NoValue") if params["SpotPrice"] == "auto" else str(params["SpotPrice"])
                    # auto -> cap at OD price
                )
            )
        ltd.InstanceType = instances_list[0]
        ltd.NetworkInterfaces = [NetworkInterfaces(
            InterfaceType="efa" if params["Efa"] is not False else Ref("AWS::NoValue"),
            DeleteOnTermination=True,
            DeviceIndex=0,
            Groups=[params["SecurityGroupId"]]
        )]
        ltd.UserData = Base64(Sub(UserData))
        ltd.BlockDeviceMappings = [
            LaunchTemplateBlockDeviceMapping(
                DeviceName="/dev/xvda" if params["BaseOS"] == "amazonlinux2" else "/dev/sda1",
                Ebs=EBSBlockDevice(
                    VolumeSize=params["RootSize"],
                    VolumeType="gp2",
                    DeleteOnTermination="false" if params["KeepEbs"] is True else "true",
                    Encrypted=True))
        ]
        if int(params["ScratchSize"]) > 0:
            ltd.BlockDeviceMappings.append(
                BlockDeviceMapping(
                    DeviceName="/dev/xvdbx",
                    Ebs=EBSBlockDevice(
                        VolumeSize=params["ScratchSize"],
                        VolumeType="io1" if int(params["VolumeTypeIops"]) > 0 else "gp2",
                        Iops=params["VolumeTypeIops"] if int(params["VolumeTypeIops"]) > 0 else Ref("AWS::NoValue"),
                        DeleteOnTermination="false" if params["KeepEbs"] is True else "true",
                        Encrypted=True))
            )
        ltd.TagSpecifications = [ec2.TagSpecifications(
            ResourceType="instance",
            Tags = base_Tags(
                Name=str(params["ClusterId"]) + "-compute-job-" + str(params["JobId"]),
                _soca_JobId=str(params["JobId"]),
                _soca_JobName=str(params["JobName"]),
                _soca_JobQueue=str(params["JobQueue"]),
                _soca_StackId=stack_name,
                _soca_JobOwner=str(params["JobOwner"]),
                _soca_JobProject=str(params["JobProject"]),
                _soca_TerminateWhenIdle=str(params["TerminateWhenIdle"]),
                _soca_KeepForever=str(params["KeepForever"]).lower(),
                _soca_ClusterId=str(params["ClusterId"]),
                _soca_NodeType="soca-compute-node"))]
        # End LaunchTemplateData

        # Begin Launch Template Resource
        lt = LaunchTemplate("NodeLaunchTemplate")
        lt.LaunchTemplateName = params["ClusterId"] + "-" + str(params["JobId"])
        lt.LaunchTemplateData = ltd
        t.add_resource(lt)
        # End Launch Template Resource

        if SpotFleet is True:
            # SpotPrice is defined and DesiredCapacity > 1 or need to try more than 1 instance_type
            # Create SpotFleet

            # Begin SpotFleetRequestConfigData Resource
            sfrcd = ec2.SpotFleetRequestConfigData()
            sfrcd.AllocationStrategy = params["SpotAllocationStrategy"]
            sfrcd.ExcessCapacityTerminationPolicy = "noTermination"
            sfrcd.IamFleetRole = params["SpotFleetIAMRoleArn"]
            sfrcd.InstanceInterruptionBehavior = "terminate"
            if params["SpotPrice"] != "auto":
                sfrcd.SpotPrice = str(params["SpotPrice"])
            sfrcd.TargetCapacity = params["DesiredCapacity"]
            sfrcd.Type = "maintain"
            sfltc = ec2.LaunchTemplateConfigs()
            sflts = ec2.LaunchTemplateSpecification(
                    LaunchTemplateId=Ref(lt),
                    Version=GetAtt(lt, "LatestVersionNumber"))
            sfltc.LaunchTemplateSpecification = sflts
            sfltc.Overrides = []
            for subnet in params["SubnetId"]:
                for instance in instances_list:
                    sfltc.Overrides.append(ec2.LaunchTemplateOverrides(
                            InstanceType = instance,
                            SubnetId = subnet))
            sfrcd.LaunchTemplateConfigs = [sfltc]
            TagSpecifications = ec2.SpotFleetTagSpecification(
                ResourceType="spot-fleet-request",
                Tags=base_Tags(
                Name=str(params["ClusterId"]) + "-compute-job-" + str(params["JobId"]),
                _soca_JobId=str(params["JobId"]),
                _soca_JobName=str(params["JobName"]),
                _soca_JobQueue=str(params["JobQueue"]),
                _soca_StackId=stack_name,
                _soca_JobOwner=str(params["JobOwner"]),
                _soca_JobProject=str(params["JobProject"]),
                _soca_TerminateWhenIdle=str(params["TerminateWhenIdle"]),
                _soca_KeepForever=str(params["KeepForever"]).lower(),
                _soca_ClusterId=str(params["ClusterId"]),
                _soca_NodeType="soca-compute-node"))
            # End SpotFleetRequestConfigData Resource

            # Begin SpotFleet Resource
            spotfleet = ec2.SpotFleet("SpotFleet")
            spotfleet.SpotFleetRequestConfigData = sfrcd
            t.add_resource(spotfleet)
            # End SpotFleet Resource
        else:

            asg_lt.LaunchTemplateSpecification = LaunchTemplateSpecification(
                LaunchTemplateId=Ref(lt),
                Version=GetAtt(lt, "LatestVersionNumber")
            )

            asg_lt.Overrides = []
            for instance in instances_list:
                asg_lt.Overrides.append(LaunchTemplateOverrides(
                    InstanceType=instance))

            # Begin InstancesDistribution
            if params["SpotPrice"] is not False and \
                    params["SpotAllocationCount"] is not False and \
                    (int(params["DesiredCapacity"]) - int(params["SpotAllocationCount"])) > 0:
                mip_usage = True
                idistribution = InstancesDistribution()
                idistribution.OnDemandAllocationStrategy = "prioritized"  # only supported value
                idistribution.OnDemandBaseCapacity = params["DesiredCapacity"] - params["SpotAllocationCount"]
                idistribution.OnDemandPercentageAboveBaseCapacity = "0"  # force the other instances to be SPOT
                idistribution.SpotMaxPrice = Ref("AWS::NoValue") if params["SpotPrice"] == "auto" else str(
                    params["SpotPrice"])
                idistribution.SpotAllocationStrategy = params['SpotAllocationStrategy']
                mip.InstancesDistribution = idistribution

            # End MixedPolicyInstance

            # Begin AutoScalingGroup Resource
            asg = AutoScalingGroup("AutoScalingComputeGroup")
            asg.DependsOn = "NodeLaunchTemplate"
            if mip_usage is True or instances_list.__len__() > 1:
                mip.LaunchTemplate = asg_lt
                asg.MixedInstancesPolicy = mip

            else:
                asg.LaunchTemplate = LaunchTemplateSpecification(
                    LaunchTemplateId=Ref(lt),
                    Version=GetAtt(lt, "LatestVersionNumber"))

            asg.MinSize = int(params["DesiredCapacity"])
            asg.MaxSize = int(params["DesiredCapacity"])
            asg.VPCZoneIdentifier = params["SubnetId"]

            if params["PlacementGroup"] is True:
                pg = PlacementGroup("ComputeNodePlacementGroup")
                pg.Strategy = "cluster"
                t.add_resource(pg)
                asg.PlacementGroup = Ref(pg)

            asg.Tags = Tags(
                Name=str(params["ClusterId"]) + "-compute-job-" + str(params["JobId"]),
                _soca_JobId=str(params["JobId"]),
                _soca_JobName=str(params["JobName"]),
                _soca_JobQueue=str(params["JobQueue"]),
                _soca_StackId=stack_name,
                _soca_JobOwner=str(params["JobOwner"]),
                _soca_JobProject=str(params["JobProject"]),
                _soca_TerminateWhenIdle=str(params["TerminateWhenIdle"]),
                _soca_KeepForever=str(params["KeepForever"]).lower(),
                _soca_ClusterId=str(params["ClusterId"]),
                _soca_NodeType="soca-compute-node")
            t.add_resource(asg)
            # End AutoScalingGroup Resource

        # Begin FSx for Lustre
        if params["FSxLustreConfiguration"]["fsx_lustre"] is not False:
            if params["FSxLustreConfiguration"]["existing_fsx"] is False:
                fsx_lustre = FileSystem("FSxForLustre")
                fsx_lustre.FileSystemType = "LUSTRE"
                fsx_lustre.StorageCapacity = params["FSxLustreConfiguration"]["capacity"]
                fsx_lustre.SecurityGroupIds = [params["SecurityGroupId"]]
                fsx_lustre.SubnetIds = params["SubnetId"]
                fsx_lustre_configuration = LustreConfiguration()
                fsx_lustre_configuration.DeploymentType = params["FSxLustreConfiguration"]["deployment_type"].upper()
                if params["FSxLustreConfiguration"]["deployment_type"].upper() == "PERSISTENT_1":
                    fsx_lustre_configuration.PerUnitStorageThroughput = params["FSxLustreConfiguration"]["per_unit_throughput"]

                if params["FSxLustreConfiguration"]["s3_backend"] is not False:
                    fsx_lustre_configuration.ImportPath = params["FSxLustreConfiguration"]["import_path"] if params["FSxLustreConfiguration"]["import_path"] is not False else params["FSxLustreConfiguration"]["s3_backend"]
                    fsx_lustre_configuration.ExportPath = params["FSxLustreConfiguration"]["import_path"] if params["FSxLustreConfiguration"]["import_path"] is not False else params["FSxLustreConfiguration"]["s3_backend"] + "/" + params["ClusterId"] + "-fsxoutput/job-" +  params["JobId"] + "/"

                fsx_lustre.LustreConfiguration = fsx_lustre_configuration
                fsx_lustre.Tags = base_Tags(
                    # False disable PropagateAtLaunch
                    Name=str(params["ClusterId"] + "-compute-job-" + params["JobId"]),
                    _soca_JobId=str(params["JobId"]),
                    _soca_JobName=str(params["JobName"]),
                    _soca_JobQueue=str(params["JobQueue"]),
                    _soca_TerminateWhenIdle=str(params["TerminateWhenIdle"]),
                    _soca_StackId=stack_name,
                    _soca_JobOwner=str(params["JobOwner"]),
                    _soca_JobProject=str(params["JobProject"]),
                    _soca_KeepForever=str(params["KeepForever"]).lower(),
                    _soca_FSx="true",
                    _soca_ClusterId=str(params["ClusterId"]),
                )
                t.add_resource(fsx_lustre)
        # End FSx For Lustre

        # Begin Custom Resource
        # Change Mapping to No if you want to disable this
        if allow_anonymous_data_collection is True:
            metrics = CustomResourceSendAnonymousMetrics("SendAnonymousData")
            metrics.ServiceToken = params["SolutionMetricLambda"]
            metrics.DesiredCapacity = str(params["DesiredCapacity"])
            metrics.InstanceType = str(params["InstanceType"])
            metrics.Efa = str(params["Efa"])
            metrics.ScratchSize = str(params["ScratchSize"])
            metrics.RootSize = str(params["RootSize"])
            metrics.SpotPrice = str(params["SpotPrice"])
            metrics.BaseOS = str(params["BaseOS"])
            metrics.StackUUID = str(params["StackUUID"])
            metrics.KeepForever = str(params["KeepForever"])
            metrics.FsxLustre = str(params["FSxLustreConfiguration"])
            metrics.TerminateWhenIdle = str(params["TerminateWhenIdle"])
            metrics.Dcv = "false"
            t.add_resource(metrics)
        # End Custom Resource

        if debug is True:
            print(t.to_json())

        # Tags must use "soca:<Key>" syntax
        template_output = t.to_yaml().replace("_soca_", "soca:")
        return {'success': True,
                'output': template_output}

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        return {'success': False,
                'output': 'cloudformation_builder.py: ' + (
                            str(e) + ': error :' + str(exc_type) + ' ' + str(fname) + ' ' + str(exc_tb.tb_lineno))}
