---
title: Restrict provisioning of specific instance type
---

You can manage the EC2 instance types allowed for each queue by configuring both  `allowed_instance_types` and `excluded_instance_types`.

This allows you to restrict which instance types or family of instances are allowed to be used for jobs on a per queue basis by either white listing instance types or blocking them.

!!!note "Default settings"
    By default, users can provision any type of instance. There are no restrictions configured out of the box.
    
These parameters can be configured as:

 - List of allowed EC2 instance types for a queue: `allowed_instance_types: ["c5.4xlarge", "r5.2xlarge"]`
 - List of excluded EC2 instance types for a queue: `excluded_instance_types: ["f1.16xlarge", "i3.2xlarge"]`
 - Allow EC2 instance types by specific type or by instance family: `allowed_instance_types: ["c5", "r5.2xlarge"]`
 - Exclude EC2 instance types by specific type or by instance family: `excluded_instance_types: ["f1.16xlarge", "i3"]`

!!!note "Instance family specification uses the exact name of the instance family."
    If you add `c5` to the allowed instance list c5 instances will be allowed.  c5n instances will be blocked unless `c5n` is added to the `allowed_instance_types` to allow c5n instances to run.

## Allow only compute optimized EC2 instances

Considering `/apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml`
```hl_lines="4 9"
queue_type:
  compute:
    queues: ["normal"]
    allowed_instance_types: ["c5", "c5n"] 
    excluded_instance_types: []
    ... 
  test:
    queues: ["test"]
    allowed_instance_types: ["c5.4xlarge"] 
    excluded_instance_types: [] 
```

In this example, only EC2 instance types in the c5 and c5n families can be used for jobs submitted to the normal queue.  For the test queue only c5.4xlarge instance type will be allowed. 

~~~console
# Job submission to queue "normal" using instance type i3.2xlarge is blocked
qsub -q normal -l instance_type=i3.2xlarge -- /bin/echo test
qsub: i3.2xlarge is not a valid instance type for the job queue normal. Contact your HPC admin and update /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml

# Job submission to queue "normal" using instance from c5 family is allowed.
qsub -q normal -l instance_type=c5.2xlarge -- /bin/echo test
15.ip-110-0-12-28

# Job submission to "test" queue only allowed if using c5.4xlarge instance type
qsub -q test -l instance_type=c5.2xlarge -- /bin/echo test
qsub: c5.2xlarge is not a valid instance type for the job queue test. Contact your HPC admin and update /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml

qsub -q test -l instance_type=c5.4xlarge -- /bin/echo test
16.ip-110-0-12-28
~~~

!!!note "Instance types in `excluded_instance_types` will be blocked even if they appear in `allowed_instance_types`"
    If an instance type or family appears in both the `excluded_instance_types`list as well as `allowed_instance_types` for a queue, the `excluded_instance_types` setting takes priority.

## Block users from using specific EC2 instance types

Considering `/apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml`
```hl_lines="5 10"
queue_type:
  compute:
    queues: ["normal"]
    allowed_instance_types: [] 
    excluded_instance_types: ["f1","g4.16xlarge","g3"]
    ... 
  test:
    queues: ["test"]
    allowed_instance_types: [] 
    excluded_instance_types: ["f1","g4dn"]
```
In this example the normal queue will not allow instances in the f1 and g3 family as well as g4.16xlarge instanct types.  The test queue will not allow instances in the f1 and g4 family.

~~~console
# Job submission to queue "normal" using instance type in f1 family is blocked
qsub -q normal -l instance_type=f1.2xlarge -- /bin/echo test
qsub: f1.2xlarge is not a valid instance type for the job queue normal. Contact your HPC admin and update /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml

# Job submission to queue "test" using instance type in g4dn is blocked
qsub -q normal -l instance_type=g4dn.xlarge -- /bin/echo test
qsub: g4dn.xlarge is not a valid instance type for the job queue test. Contact your HPC admin and update /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml
~~~

## Check the logs
Scheduler hooks are located on /var/spool/pbs/server_logs/

## Code
The hook file can be found under `/apps/soca/cluster_hooks/$SOCA_CONFIGURATION/queuejob/check_queue_instance_types.py` on your Scale-Out Computing on AWS cluster)

## Disable the hook
You can disable the hook by running the following command on the scheduler host (as root):

~~~bash
user@host: qmgr -c "delete hook check_queue_instance_types event=queuejob"
~~~