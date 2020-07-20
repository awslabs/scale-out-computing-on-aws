---
title: What is Scale-Out Computing on AWS ?
---

<p align="center">
<img src="imgs/soca_logo_rev2.png" style="height: 150px;">
</p>

Scale-Out Computing on AWS is a solution that helps customers more easily deploy and operate a multiuser environment for computationally intensive workflows. The solution features a large selection of compute resources; fast network backbone; unlimited storage; and budget and cost management directly integrated within AWS. The solution also deploys a user interface (UI) and automation tools that allows you to create your own queues, scheduler resources, Amazon Machine Images (AMIs), software, and libraries. 
This solution is designed to provide a production ready reference implementation to be a starting point for deploying an AWS environment to run scale-out workloads, allowing you to focus on running simulations designed to solve complex computational problems.  
____
## Easy installation
[Installation of your Scale-Out Computing on AWS cluster](install-soca-cluster/) is fully automated and managed by CloudFormation 

!!!info "Did you know?"
    - You can have multiple Scale-Out Computing on AWS clusters on the same AWS account
    - Scale-Out Computing on AWS comes with a list of unique tags, making resource tracking easy for AWS Administrators

## Access your cluster in 1 click
You can [access your Scale-Out Computing on AWS cluster](access-soca-cluster/) either using DCV (Desktop Cloud Visualization)[^1] or through SSH.

[^1]: [DCV](https://docs.aws.amazon.com/dcv/latest/adminguide/what-is-dcv.html) is a remote visualization technology that enables users to easily and securely connect to graphic-intensive 3D applications hosted on a remote high-performance server.*

## Simple Job Submission
Scale-Out Computing on AWS [supports a list of parameters designed to simplify your job submission on AWS](tutorials/integration-ec2-job-parameters/). Advanced users can either manually choose compute/storage/network configuration for their job or simply ignore these parameters and let Scale-Out Computing on AWS picks the most optimal hardware (defined by the HPC administrator)

~~~bash
# Advanced Configuration
user@host$ qsub -l instance_type=c5n.18xlarge \
    -l instance_ami=ami-123abcde
    -l nodes=2 
    -l scratch_size=300 
    -l efa_support=true
    -l spot_price=1.55 myscript.sh

# Basic Configuration
user@host$ qsub myscript.sh
~~~

!!!info
    - [Check our Web-Based utility to generate you submission command](job-configuration-generator/)
    - [Refer to this page for tutorial and examples](tutorials/launch-your-first-job/)
    - [Refer to this page to list all supported parameters](tutorials/integration-ec2-job-parameters/)
    - Jobs can also be submitted [via HTTP API](web-interface/control-hpc-job-with-http-web-rest-api/) or [via web interface](web-interface/submit-hpc-jobs-web-based-interface/)

## OS agnostic and support for custom AMI
Customers can integrate their Centos7/Rhel7/AmazonLinux2 AMI automatically by simply using ==-l instance_ami=<ami_id\>== at job submission. There is no limitation in term of AMI numbers (you can have 10 jobs running simultaneously using 10 different AMIs). SOCA supports heterogeneous environment, so you can have concurrent jobs running different operating system on the same cluster. 

!!!danger "AMI using OS different than the scheduler"
    In case your AMI is different than your scheduler host, you can specify the OS manually to ensure packages will be installed based on the node distribution.

    In this example, we assume your Scale-Out Computing on AWS deployment was done using AmazonLinux2, but you want to submit a job on your personal RHEL7 AMI
 
    ~~~bash
    user@host$ qsub -l instance_ami=<ami_id> -l base_os=rhel7 myscript.sh
    ~~~
    
    _____

!!!info "Scale-Out Computing on AWS AMI requirements"
    When you use a custom AMI, just make sure that your AMI does not use /apps, /scratch or /data partitions as Scale-Out Computing on AWS will need to use these locations during the deployment. [Read this page for AMI creation best practices](tutorials/reduce-compute-node-launch-time-with-custom-ami/)

## Web User Interface
Scale-Out Computing on AWS includes a simple web ui designed to simplify user interactions such as:

- [Start/Stop DCV sessions in 1 click](access-soca-cluster/#graphical-access-using-dcv)
- [Download private key in both PEM or PPK format](access-soca-cluster/#ssh-access)
- [Check the queue and job status in real-time](web-interface/manage-ldap-users/)
- [Add/Remove LDAP users ](web-interface/manage-ldap-users/)
- [Access the analytic dashboard](web-interface/my-activity/)
- [Access your filesystem](web-interface/my-files/)
- [Understand why your jobs are stuck in the queue](web-interface/my-job-queue/#understand-why-your-job-cannot-start)
- [Create Application profiles and let your users submit job directly via the web interface](web-interface/submit-hpc-jobs-web-based-interface/)

## HTTP Rest API
Users can submit/retrieve/delete jobs [remotely via an HTTP REST API](web-interface/control-hpc-job-with-http-web-rest-api/)

## Budgets and Cost Management
You can [review your HPC costs](budget/review-hpc-costs/) filtered by user/team/project/queue very easily using AWS Cost Explorer. 

Scale-Out Computing on AWS also supports AWS Budget and [let you create budgets](budget/set-up-budget-project/) assigned to user/team/project or queue. To prevent over-spend, Scale-Out Computing on AWS includes hooks to restrict job submission when customer-defined budget has expired.

Lastly, Scale-Out Computing on AWS let you create queue ACLs or instance restriction at a queue level. [Refer to this link for all best practices in order to control your HPC cost on AWS and prevent overspend](budget/prevent-overspend-hpc-cost-on-aws-soca/).

## Detailed Cluster Analytics 
Scale-Out Computing on AWS [includes ElasticSearch and automatically ingest job and hosts data](analytics/monitor-cluster-activity/) in real-time for accurate visualization of your cluster activity.

!!!success "Don't know where to start?"
    Scale-Out Computing on AWS [includes dashboard examples](analytics/build-kibana-dashboards/) if you are not familiar with ElasticSearch or Kibana.
    
## 100% Customizable
Scale-Out Computing on AWS is built entirely on top of AWS and can be customized by users as needed. Most of the logic is based of CloudFormation templates, shell scripts and python code.
More importantly, the entire Scale-Out Computing on AWS codebase is open-source and [available on Github](https://github.com/awslabs/scale-out-computing-on-aws).

## Persistent and Unlimited Storage
Scale-Out Computing on AWS includes two unlimited EFS storage (/apps and /data). Customers also have the ability to deploy high-speed SSD EBS disks or FSx for Lustre as scratch location on their compute nodes. [Refer to this page to learn more about the various storage options](storage/backend-storage-options/) offered by Scale-Out Computing on AWS

## Centralized user-management
Customers [can create unlimited LDAP users and groups](web-interface/manage-ldap-users/). By default Scale-Out Computing on AWS includes a default LDAP account provisioned during installation as well as a "Sudoers" LDAP group which manage SUDO permission on the cluster.

## Automatic backup
Scale-Out Computing on AWS [automatically backup your data](security/backup-restore-your-cluster/) with no additional effort required on your side.

## Support for network licenses
Scale-Out Computing on AWS [includes a FlexLM-enabled script which calculate the number of licenses](tutorials/job-licenses-flexlm) for a given features and only start the job/provision the capacity when enough licenses are available. 

## Automatic Errors Handling
Scale-Out Computing on AWS performs various dry run checks before provisioning the capacity. However, it may happen than AWS can't fullfill all requests (eg: need 5 instances but only 3 can be provisioned due to capacity shortage within a placement group). In this case, Scale-Out Computing on AWS will try to provision the capacity for 30 minutes. After 30 minutes, and if the capacity is still not available, Scale-Out Computing on AWS will automatically reset the request and try to provision capacity in a different availability zone.
[To simplify troubleshooting, all these errors are reported on the web interface](web-interface/my-job-queue/#understand-why-your-job-cannot-start)

## Custom fair-share
Each user is given a score which vary based on:

- Number of job in the queue
- Time each job is queued
- Priority of each job
- Type of instance

Job that belong to the user with the highest score will start next. Fair Share is is configured at the queue level (so you can have one queue using FIFO and another one Fair Share)

## And more ...

Refer to the various sections (tutorial/security/analytics ...) to learn more about this solution
