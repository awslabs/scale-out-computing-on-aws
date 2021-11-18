---
title: Launch AlwaysOn nodes
---
## Why AlwaysOn instances?

By default, Scale-Out Computing on AWS provisions on-demand capacity when there are jobs in the normal queue. This means any job submitted will wait in the queue 5 to 8 minutes until EC2 capacity is ready.

If you want to avoid this penalty, you can provision "AlwaysOn instances". Please note you will be charged until you manually terminate it or specify --terminate_when_idle option

## How to launch an AlwaysOn instances?

On your scheduler host, sudo as root and run `source /etc/environment` to load Scale-Out Computing on AWS shell and then execute `/apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 /apps/soca/$SOCA_CONFIGURATION/cluster_manager/add_nodes.py`

~~~bash
[root@ip-a-b-c-d ~]# /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 \
      /apps/soca/$SOCA_CONFIGURATION/cluster_manager/add_nodes.py -h
usage: add_nodes.py [-h] --desired_capacity [DESIRED_CAPACITY] --instance_type
                    [INSTANCE_TYPE] --job_name [JOB_NAME] --job_owner
                    [JOB_OWNER] --queue [QUEUE] [--efa_support EFA_SUPPORT]
                    [--ht_support HT_SUPPORT] [--keep_forever KEEP_FOREVER]
                    [--terminate_when_idle [TERMINATE_WHEN_IDLE]]
                    [--base_os BASE_OS] [--fsx_lustre FSX_LUSTRE]
                    [--fsx_lustre_size FSX_LUSTRE_SIZE]
                    [--fsx_lustre_per_unit_throughput
                    FSX_LUSTRE_PER_UNIT_THROUGHPUT]
                    [--fsx_lustre_deployment_type FSX_LUSTRE_DEPLOYMENT_TYPE]
                    --instance_ami [INSTANCE_AMI] [--job_id [JOB_ID]]
                    [--job_project [JOB_PROJECT]]
                    [--placement_group PLACEMENT_GROUP]
                    [--root_size [ROOT_SIZE]] [--scratch_iops [SCRATCH_IOPS]]
                    [--scratch_size [SCRATCH_SIZE]]
                    [--spot_allocation_count [SPOT_ALLOCATION_COUNT]]
                    [--spot_allocation_strategy [SPOT_ALLOCATION_STRATEGY]]
                    [--spot_price [SPOT_PRICE]] [--keep_ebs]
                    [--subnet_id SUBNET_ID] [--tags [TAGS]]
                    [--weighted_capacity [WEIGHTED_CAPACITY]]

optional arguments:
  -h, --help            show this help message and exit
  --desired_capacity [DESIRED_CAPACITY]
                        Number of EC2 instances to deploy
  --instance_type [INSTANCE_TYPE]
                        Instance type you want to deploy
  --job_name [JOB_NAME]
                        Job Name for which the capacity is being provisioned
  --job_owner [JOB_OWNER]
                        Job Owner for which the capacity is being provisioned
  --queue [QUEUE]       Queue to map the capacity
  --efa_support EFA_SUPPORT
                        Support for EFA
  --ht_support HT_SUPPORT
                        Enable Hyper Threading
  --keep_forever KEEP_FOREVER
                        Whether or not capacity will stay forever
  --terminate_when_idle [TERMINATE_WHEN_IDLE]
                        If instances will be terminated when idle for N
                        minutes
  --base_os BASE_OS     Specify custom Base OK
  --fsx_lustre FSX_LUSTRE
                        Mount existing FSx by providing the DNS
  --fsx_lustre_size FSX_LUSTRE_SIZE
                        Specify size of your FSx
  --fsx_lustre_per_unit_throughput FSX_LUSTRE_PER_UNIT_THROUGHPUT
                        Storage baseline if FSX type is Persistent
  --fsx_lustre_deployment_type FSX_LUSTRE_DEPLOYMENT_TYPE
                        Type of your FSx for Lustre
  --instance_ami [INSTANCE_AMI]
                        AMI to use
  --job_id [JOB_ID]     Job ID for which the capacity is being provisioned
  --job_project [JOB_PROJECT]
                        Job Owner for which the capacity is being provisioned
  --placement_group PLACEMENT_GROUP
                        Enable or disable placement group
  --root_size [ROOT_SIZE]
                        Size of Root partition in GB
  --scratch_iops [SCRATCH_IOPS]
                        Size of /scratch in GB
  --scratch_size [SCRATCH_SIZE]
                        Size of /scratch in GB
  --spot_allocation_count [SPOT_ALLOCATION_COUNT]
                        When using mixed OD and SPOT, choose % of SPOT
  --spot_allocation_strategy [SPOT_ALLOCATION_STRATEGY]
                        lowest-price or capacity-optimized or diversified
                        (supported only for SpotFleet)
  --spot_price [SPOT_PRICE]
                        Spot Price
  --keep_ebs            Do not delete EBS disk
  --subnet_id SUBNET_ID
                        Launch capacity in a special subnet
  --tags [TAGS]         Tags, format must be {'Key':'Value'}
  --weighted_capacity [WEIGHTED_CAPACITY]
                        Weighted capacity for EC2 instances
~~~

To launch "AlwaysOn" instances, there are two alternative methods either using --keep_forever or --terminate_when_idle options.

### Using keep_forever option

Use `--keep_forever true` and `alwayson` queue. If you do not want to use `alwayson` queue, make sure the queue you have created has been configured correctly to support AlwaysOn ([see instructions](../../web-interface/create-your-own-queue/#queue-with-alwayson-instances))

See example below (note: you can use additional parameters if needed)

~~~bash hl_lines="5 8"
 /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 \
 /apps/soca/$SOCA_CONFIGURATION/cluster_manager/add_nodes.py \
     --instance_type=c5.large \
     --desired_capacity=1 \
     --keep_forever true \
     --job_owner mickael \
     --job_name always_on_capacity \
     --queue alwayson
~~~

When the capacity is available, simply run a job and specify `alwayson` as queue name

#### Terminate an AlwaysOn instance launched with keep_forever

Simply go to your CloudFormation console, locate the stack following the naming convention: `soca-<cluster_name>-keepforever-<queue_name>-uniqueid` and terminate it.

![](../imgs/howtoqueue-1.png)

### Using terminate_when_idle option

1. Use `--terminate_when_idle N` where N represents the number of minutes when the instance(s) where be terminated after all running jobs on the instances exit,
2. Use `--keep_forever false`, and
3. Use `alwayson` queue. If you do not want to use `alwayson` queue, make sure the queue you have created has been configured correctly to support AlwaysOn ([see instructions](../../web-interface/create-your-own-queue/#queue-with-alwayson-instances))

See example below (note: you can use additional parameters if needed)

~~~bash hl_lines="5 6 9"
 /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 \
 /apps/soca/$SOCA_CONFIGURATION/cluster_manager/add_nodes.py \
     --instance_type=c5.large \
     --desired_capacity=1 \
     --terminate_when_idle 5 \
     --keep_forever false \
     --job_owner mickael \
     --job_name always_on_capacity \
     --queue alwayson
~~~

When the instances become available, simply submit a job and specify `-q alwayson`.

The instance(s) launched with `--terminate_when_idle` will be terminated automatically once all jobs running on the instance complete then the instance is detected as idle (no jobs running) for the specified number of minutes (5 in the example above).

## How to launch capacity based on vCPUs/cores instead of instances?

You can launch capacity based on vCPUs or cores using `--weighted_capacity` option and specify a corresponding weight for each instance type specified in the instance_type option. This will pass WeightedCapacity to the corresponding Auto Scaling Group or Spot Fleet.


The example below will launch capacity where the total number of vCPUs is at least 24 vCPUs depending on availability of c5.large, c5.xlarge, and c5.2xlarge instances. In this example, ht_support is set to true to utilize vCPUs on each instance, and the weighted_capacity option has 3 weights corresponding to the desired weight of c5.large (2 vCPUs), c5.xlarge (4 vCPUs), and c5.2xlarge (8 vCPUs)

~~~bash hl_lines="3-6"
 /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 \
 /apps/soca/$SOCA_CONFIGURATION/cluster_manager/add_nodes.py \
     --instance_type c5.large+c5.xlarge+c5.2xlarge \
     --desired_capacity 24 \
     --weighted_capacity 2+4+8 \
     --ht_support true \
     --terminate_when_idle 5 \
     --keep_forever false \
     --job_owner mickael \
     --job_name vcpus_capacity \
     --queue alwayson
~~~

When the instances become available, simply submit the jobs and specify `-q alwayson`.

The instance(s) launched with `--terminate_when_idle` will be terminated automatically once all jobs running on the instances complete then each instance is detected as idle (no jobs running) for the specified number of minutes (5 in the example above).
