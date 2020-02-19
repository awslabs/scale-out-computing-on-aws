# Lab 1: Deploy Environment

## Step 1: Launch stack

This automated AWS CloudFormation template deploys a scale-out computing environment in the AWS Cloud.

1. Verify that you have a key pair in the  **US West (Oregon)** region.  If not, create a new key pair.

1. Sign in to the AWS Management Console and click the link below to launch the scale-out-computing-on-aws AWS CloudFormation template.

    * [**Launch Stack in US West (Oregon)**](https://console.aws.amazon.com/cloudformation/home?region=us-west-2#/stacks/new?&templateURL=https://s3.amazonaws.com/solutions-reference/scale-out-computing-on-aws/latest/scale-out-computing-on-aws.template)

1. On the **Create stack** page, you should see the template URL in the **Amazon S3 URL** text box and choose **Next**.

1. On the **Specify stack** details page, assign the name **"soca"** to the stack.

    !!! warning
         The stack name must be less than 20 characters and must be lower-case only.

1. Under **Parameters**, modify the the last four parameters, which are marked with **REQUIRED**.  Leave all other fields with their default values.  These are variables passed the CloudFormation automation that deploys the environment.

    |Parameter|Default|Description
    ----------|-------|-----------
    |**Install Location**|
    |Installer S3 Bucket|`solutions-reference`|The default AWS bucket name. Do not change this parameter unless you are using a custom installer.
    |Installer Folder|`scale-out-computing-on-aws/latest`|The default AWS folder name. Do not change this parameter unless you are using a custom installer.
    |**Linux Distribution**|
    |Linux Distribution|AmazonLinux2|The preferred Linux distribution for the scheduler and compute instances.  Do not change this parameter.
    |Custom AMI|<Optional input>|If using a customized Amazon Machine Image, enter the ID. Leave this field blank.
    |**Network and Security**|
    |EC2 Instance Type for Scheduler node|m5.large|The instance type for the scheduler.  Do not change this parameter.
    |VPC Cluster CIDR|110.0.0.0/16|Choose the CIDR (/16) block for the VPC. Do not change this parameter.
    |IP Address|0.0.0.0/0|**REQUIRED** The public-facing IP address that is permitted to log into the environment.  You can leave it at default, but we recommend you change it to your public-facing IP address. Add the /32 suffix to the IP number.
    |Key Pair Name|<Requires input>|**REQUIRED** Select your key pair.
    |**Default LDAP User**|
    |User Name|<Requires input>|**REQUIRED** Set a username for the default cluster user.
    |Password|<Requires input>|**REQUIRED** Set a password for the default cluster user. (5 characters minimum, uppercase/lowercase/digit only)

1. Choose **Next**.

1. On the **Configure Stack Options** page, choose **Next**.

1. On the **Review** page, review the settings and check the two boxes acknowledging that the template will create AWS Identity and Access Management (IAM) resources and might require the CAPABILITY_AUTO_EXPAND capability.

1. Choose **Create stack** to deploy the stack.

You can view the status of the stack in the AWS CloudFormation console in the **Status** column. You should see a status of `CREATE_COMPLETE` in approximately 35 minutes.  Please wait for instructions from the workshop staff before moving on to the next lab.
