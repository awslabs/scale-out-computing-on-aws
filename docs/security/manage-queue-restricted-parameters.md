---
title: Prevent user to change specific parameters
---

When submitting a job, users can override the default parameters configured for the queue ([click here to see a list of all parameters supported by SOCA](../../tutorials/integration-ec2-job-parameters/)).
 
 For security, compliance or cost reasons, you may want prevent users to override these default parameters by configuring `restricted_parameters` on your `queue_mapping.yml`

## Prevent user to choose a different instance type

Considering `/apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml`

```hl_lines="5"
queue_type:
  compute:
    queues: ["normal", "low"]
    instance_type: "c5.large"
    restricted_parameters: ["instance_type"]
    ...
```

In this example, a job will be rejected if a user try to specify the `instance_type` parameter when using the `normal` or `low` queues. In this particular case, any job sent to the `normal` or `low` queue will be forced to use `c5.large` instance, which is the default instance type configured by HPC admins. 

~~~console
qsub -q normal -l instance_type=m5.24xlarge -- /bin/echo test
qsub: instance_type is a restricted parameter and can't be configure by the user. Contact your HPC admin and update /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml
~~~

!!!note "Need to whitelist more than one instance type/family?"
    [Read the documentation](../../security/manage-queue-instance-types/) if you want to limit users to a list of multiple instance types

## Prevent user to provision additional storage

Considering `/apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml`

```hl_lines="5 9"
queue_type:
  compute:
    queues: ["normal", "low"]
    scratch_size: "200"
    restricted_parameters: ["scratch_size"]
    ... 
```
In this example, a job will be rejected if a user try to specify the `scratch_size` parameter when using the `normal` or `low` queues. In this particular case, any job sent to the `normal` or `low` queue will be forced to use a 200 GB EBS disk as `/scratch` partition. Users are no longer able to provision more storage than what's allocated to them.

~~~console
qsub -q normal -l scratch_size=550 -- /bin/echo test
qsub: scratch_size is a restricted parameter and can't be configure by the user. Contact your HPC admin and update /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml
~~~


## Combine multiple restrictions

Considering `/apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml`

```hl_lines="5"
queue_type:
  compute:
    queues: ["normal", "low"]
    scratch_size: "200"
    restricted_parameters:["instance_type", "fsx_lustre_bucket", "scratch_size"]
    ...
```

In this example, a job will be rejected if a user try to change either `instance_type`, `fsx_lustre_bucket` or `scratch_size` parameters.

~~~console
qsub -q normal -l fsx_lustre_bucket=mybucket -- /bin/echo test
qsub: fsx_lustre_bucket is a restricted parameter and can't be configure by the user. Contact your HPC admin and update /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml
~~~

## Check the logs
Scheduler hooks are located on /var/spool/pbs/server_logs/

## Code
The hook file can be found under `/apps/soca/cluster_hooks/$SOCA_CONFIGURATION/queuejob/check_queue_restricted_parameters.py` on your Scale-Out Computing on AWS cluster)

## Disable the hook
You can disable the hook by running the following command on the scheduler host (as root):

~~~bash
user@host: qmgr -c "delete hook check_queue_restricted_parameters event=queuejob"
~~~