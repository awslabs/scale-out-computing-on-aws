---
title: Launch AlwaysOn nodes
---
## Why AlwaysOn instances?

By default, Scale-Out Computing on AWS provision on-demand capacity when there are jobs in the queue. This mean any job submitted will wait in the queue 5 to 8 minutes until EC2 capacity is ready.
 
If you want to avoid this penalty, you can provision "AlwaysOn instance". Please note you will be charged until you manually terminate it.

## How launch an AlwaysOn instance

On your scheduler host, sudo as root and run `source /etc/environment` to load Scale-Out Computing on AWS shell and then execute `/apps/soca/<CLUSTER_ID>/cluster_manager/add_nodes.py`

~~~bash
[root@ip-40-0-22-232 ~]# python3 /apps/soca/<CLUSTER_ID>/cluster_manager/add_nodes.py -h
usage: add_nodes.py [-h] --instance_type [INSTANCE_TYPE] --desired_capacity
                    [DESIRED_CAPACITY] --queue [QUEUE]
                    [--instance_ami [INSTANCE_AMI]] [--subnet_id SUBNET_ID]
                    [--job_id [JOB_ID]] --job_name [JOB_NAME] --job_owner
                    [JOB_OWNER] [--job_project [JOB_PROJECT]]
                    [--scratch_size [SCRATCH_SIZE]]
                    [--placement_group PLACEMENT_GROUP] [--tags [TAGS]]
                    [--keep_forever] [--base_os BASE_OS] [--efa]
                    [--spot_price [SPOT_PRICE]]

optional arguments:
  -h, --help            show this help message and exit
  --instance_type [INSTANCE_TYPE]
                        Instance type you want to deploy
  --desired_capacity [DESIRED_CAPACITY]
                        Number of EC2 instances to deploy
  --queue [QUEUE]       Queue to map the capacity
  --instance_ami [INSTANCE_AMI]
                        AMI to use
  --subnet_id SUBNET_ID
                        Launch capacity in a special subnet
  --job_id [JOB_ID]     Job ID for which the capacity is being provisioned
  --job_name [JOB_NAME]
                        Job Name for which the capacity is being provisioned
  --job_owner [JOB_OWNER]
                        Job Owner for which the capacity is being provisioned
  --job_project [JOB_PROJECT]
                        Job Owner for which the capacity is being provisioned
  --scratch_size [SCRATCH_SIZE]
                        Size of /scratch in GB
  --placement_group PLACEMENT_GROUP
                        Enable or disable placement group
  --tags [TAGS]         Tags, format must be {'Key':'Value'}
  --keep_forever        Wheter or not capacity will stay forever
  --base_os BASE_OS     Specify custom Base OK
  --efa                 Support for EFA
  --spot_price [SPOT_PRICE]
                        Spot Price
~~~

To enable "AlwaysOn" instance, make sure to use `--keep_forever` tag and use `alwayson` queue. If you do not want to use `alwayson` instance, make sure the queue you have created has been configured correctly to support AlwaysOn ([see instructions]({% post_url 2019-10-04-create-own-queue %}))
 
 See example below (note: you can use additional parameters if needed)

~~~bash hl_lines="3 6"
 python3 /apps/soca/<CLUSTER_ID>/cluster_manager/add_nodes.py --instance_type=c5.large \
     --desired_capacity=1 \
     --keep_forever \
     --job_owner mickael
     --job_name always_on_capacity
     --queue alwayson
~~~

When the capacity is available, simply run a job and specify `alwayson` as queue name

## How terminate an AlwaysOn instance

Simply go to your CloudFormation console, locate the stack following the naming convention: `soca-<cluster_name>-keepforever-<queue_name>-uniqueid` and terminate it.

![](../imgs/howtoqueue-1.png)