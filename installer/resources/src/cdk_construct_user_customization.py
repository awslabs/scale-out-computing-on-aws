#!/usr/bin/env python3

from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_s3 as s3
import random
import string


def main(scope, soca_base_parameters):
    # Extend base SOCA install with your own custom code below
    # CDK examples: https://github.com/aws-samples/aws-cdk-examples
    # CDK Python Doc: https://docs.aws.amazon.com/cdk/api/latest/python/

    #  Retrieve SOCA parameters via soca_base_parameters
    #  print(soca_base_parameters)

    # Example1: Extend a resource created by SOCA with your own custom requirements (eg: add a custom tag)
    # cdk.Tags.of(soca_base_parameters["vpc"]).add("MyCompanyTag", f"MyCustomTagValue")

    # Example2: Create new Elastic IP
    # scope.my_new_eip = ec2.CfnEIP(scope, "MyCustomEIP", instance_id=None)

    # Example3: Create new S3 Bucket
    # scope.my_new_bucket = s3.Bucket(scope, "MyCustomS3Bucket", bucket_name=''.join(random.choice(string.ascii_lowercase) for i in range(20)))

    # Resources created on this function will automatically be merged to the main stack.
    # To confirm if your resources are added correctly, use `--cdk-cmd synth` as soca_installer.sh parameter and check the output generated

    # Happy coding !

    pass
