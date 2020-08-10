---
title: Restrict number of concurrent jobs and/or instances
---


## Restrict number of concurrent running jobs

Configure `max_running_jobs` to limit the number of jobs running in parallel for a given queue
Considering `/apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml`

```hl_lines="4 8"
queue_type:
  compute:
    queues: ["normal"]
    max_running_jobs: 5 
    ... 
  test:
    queues: ["test"]
    max_running_jobs: 30
```

In this example, only 5 jobs can be running at the same time in the "normal" queue, and 30 in the "test" queue.
If a job cannot start because of this parameter, an `error_message` will be visible when running "qstat -f" or via the web interface


## Restrict number of provisioned instances 

Configure `max_provisioned_instances` to limit the number of instances that can be provisioned for a given queue

```hl_lines="4 8"
queue_type:
  compute:
    queues: ["normal"]
    max_provisioned_instances: 10 
    ... 
  test:
    queues: ["test"]
    max_provisioned_instances: 20
```

In this example, you cannot have more than 10 instances provisioned for "normal" queue, and 20 for the "test" queue.
If a job cannot start because of this parameter, an `error_message` will be visible when running "qstat -f" or via the web interface

!!!info 
    Limit apply to all type of instance. Configure `allowed_instance_types` / `excluded_instance_types` if [you also want to limit the type of EC2 instance than can be provisioned](../../security/manage-queue-instance-types/)).
