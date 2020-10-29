import os
import sys
import random
from troposphere import Base64
from troposphere import Template, Sub
from troposphere import Tags as base_Tags  # without PropagateAtLaunch
from troposphere.cloudformation import AWSCustomObject
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


def main(**launch_parameters):
    try:
        t = Template()
        t.set_version("2010-09-09")
        t.set_description("(SOCA) - Base template to deploy DCV nodes")
        allow_anonymous_data_collection = launch_parameters["DefaultMetricCollection"]
        # Launch Actual Capacity
        instance = ec2.Instance(str(launch_parameters["session_name"]))
        instance.BlockDeviceMappings = [{'DeviceName': "/dev/xvda" if launch_parameters["base_os"] == "amazonlinux2" else "/dev/sda1",
                                         'Ebs': {
                                             'DeleteOnTermination': True,
                                             'VolumeSize': 30 if launch_parameters["disk_size"] is False else int(launch_parameters["disk_size"]),
                                             'VolumeType': 'gp2',
                                             'Encrypted': True}
                                         }]
        instance.ImageId = launch_parameters["image_id"]
        instance.SecurityGroupIds = [launch_parameters["security_group_id"]]
        if launch_parameters["hibernate"] is True:
            instance.HibernationOptions = ec2.HibernationOptions(Configured=True)
        instance.InstanceType = launch_parameters["instance_type"]
        instance.SubnetId = random.choice(launch_parameters["soca_private_subnets"]) if len(launch_parameters["soca_private_subnets"]) > 1 else launch_parameters["soca_private_subnets"][0]
        instance.IamInstanceProfile = launch_parameters["ComputeNodeInstanceProfileArn"].split("instance-profile/")[-1]
        instance.UserData = Base64(Sub((launch_parameters["user_data"])))
        instance.Tags = base_Tags(
            Name=str(launch_parameters["cluster_id"] + "-" + launch_parameters["session_name"] + "-" + launch_parameters["user"]),
            _soca_JobName=str(launch_parameters["session_name"]),
            _soca_JobOwner=str(launch_parameters["user"]),
            _soca_NodeType="dcv",
            _soca_JobProject="desktop",
            _soca_DCVSupportHibernate=str(launch_parameters["hibernate"]).lower(),
            _soca_ClusterId=str(launch_parameters["cluster_id"]),
            _soca_DCVSessionUUID=str(launch_parameters["session_uuid"]),
            _soca_DCVSystem=str(launch_parameters["base_os"]))
        t.add_resource(instance)

        # Begin Custom Resource
        # Change Mapping to No if you want to disable this
        if allow_anonymous_data_collection is True:
            metrics = CustomResourceSendAnonymousMetrics("SendAnonymousData")
            metrics.ServiceToken = launch_parameters["SolutionMetricLambda"]
            metrics.DesiredCapacity = "1"
            metrics.InstanceType = str(launch_parameters["instance_type"])
            metrics.Efa = "false"
            metrics.ScratchSize = "0"
            metrics.RootSize = str(launch_parameters["disk_size"])
            metrics.SpotPrice = "false"
            metrics.BaseOS = str(launch_parameters["base_os"])
            metrics.StackUUID = str(launch_parameters["session_uuid"])
            metrics.KeepForever = "false"
            metrics.FsxLustre = str({"fsx_lustre": "false", "existing_fsx": "false", "s3_backend": "false", "import_path": "false", "export_path": "false",
                                     "deployment_type": "false", "per_unit_throughput": "false", "capacity": 1200})
            metrics.TerminateWhenIdle = "false"
            metrics.Dcv = "true"
            t.add_resource(metrics)
        # End Custom Resource

        # Tags must use "soca:<Key>" syntax
        template_output = t.to_yaml().replace("_soca_", "soca:")
        return {'success': True,
                'output': template_output}

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        return {'success': False,
                'output': 'cloudformation_builder.py: ' + (str(e) + ': error :' + str(exc_type) + ' ' + str(fname) + ' ' + str(exc_tb.tb_lineno))}
