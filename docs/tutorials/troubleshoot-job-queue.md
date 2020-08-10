---
title: Debug why your jobs are not starting
---

## Jobs in dynamic queue

First of all, unless you submit a job on the "alwayson" queue, it will usually take between 5 to 10 minutes before your job can start as Scale-Out Computing on AWS needs to provision your capacity. This can vary based on the type and number of EC2 instances you have requested for your job.

### Verify the log
If your job is not starting, first verify the queue log under `/apps/soca/$SOCA_CONFIGURATION/cluster_manager/logs/<queue_name>.log`

If the log is not created or you don't see any update on it even though you submitted a job, try to run the `dispatcher.py` command manually. On the scheduler, list all crontabs as root `crontab -` and refer to "Automatic Host Provisioning" section:

~~~bash
## Automatic Host Provisioning
*/3 * * * * source /etc/environment;  /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 /apps/soca/$SOCA_CONFIGURATION/cluster_manager/dispatcher.py -c /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml -t compute
*/3 * * * * source /etc/environment;  /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 /apps/soca/$SOCA_CONFIGURATION/cluster_manager/dispatcher.py -c /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml -t desktop
*/3 * * * * source /etc/environment;  /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 /apps/soca/$SOCA_CONFIGURATION/cluster_manager/dispatcher.py -c /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml -t test
~~~

Run the command manually (ex `source /etc/environment;  /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 /apps/soca/$SOCA_CONFIGURATIONcluster_manager/dispatcher.py -c /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml -t compute`) and look for any error. Common errors include malformed yaml files.

### Verify the job resource

This guide assume you have created your queue correctly

Run `qstat -f <job_id> | grep -i resource` and try to locate `compute_node` or `stack_id` resource. When your job is launched, these resources does not exist. The script `dispatcher.py`. running as a crontab and executed every 3 minutes will create these resources automatically.

Example of job having all resources configured correctly
~~~bash hl_lines="8 9"
# Job with Scale-Out Computing on AWS resources
bash-4.2$ qstat -f 2 | grep -i resource
    Resource_List.instance_type = m5.large
    Resource_List.ncpus = 3
    Resource_List.nodect = 3
    Resource_List.nodes = 3
    Resource_List.place = scatter
    Resource_List.select = 3:ncpus=1:compute_node=job2 
    Resource_List.stack_id = soca-fpgaami-job-2
~~~

Please note these resources are created by `dispatcher.py` so allow a maximum of 3 minutes between job is submitted and resources are visibles on `qstat` output
~~~bash
# Job without Scale-Out Computing on AWS resources created yet
bash-4.2$ qstat -f 2 | grep -i resource
    Resource_List.instance_type = m5.large
    Resource_List.ncpus = 3
    Resource_List.nodect = 3
    Resource_List.nodes = 3
    Resource_List.place = scatter
    Resource_List.select = 3:ncpus=1
~~~

If you see a `compute_node` different than `tbd` as well as `stack_id`, that means Scale-Out Computing on AWS triggered capacity provisioning by creating a new CloudFormation stack.
If you go to your CloudFormation console, you should see  a new stack being created using the following naming convention: `soca-<cluster_name>-job-<job_id>`

### Retrieve node logs

On the master host, access `/apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/logs/`. This folder contains the output of all logs for all hosts provisioned by SOCA

~~~bash hl_lines="2 10 18"
# Retrieve logs for the most recent (2 weeks) jobs
ls -ltr /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/logs/ | tail -n 5
drwxr-xr-x   3 root root  6144 Jul 21 17:02 19607
drwxr-xr-x   3 root root  6144 Jul 21 17:16 19608
drwxr-xr-x   3 root root  6144 Jul 21 17:21 19609
drwxr-xr-x   6 root root  6144 Jul 21 17:40 19575
drwxr-xr-x  10 root root  6144 Jul 21 17:44 19606

# Filter for a specific job id. Each nodes provisioned for this job will show up on the directory
ls -ltr /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/logs/19606 | tail -n 5
drwxr-xr-x 2 root root 6144 Jul 21 17:47 ip-10-10-99-2
drwxr-xr-x 2 root root 6144 Jul 21 17:47 ip-10-10-102-78
drwxr-xr-x 2 root root 6144 Jul 21 17:48 ip-10-10-101-45
drwxr-xr-x 2 root root 6144 Jul 21 17:48 ip-10-10-85-64
drwxr-xr-x 2 root root 6144 Jul 21 17:48 ip-10-10-77-184

# For each hosts, you will be able to retrieve the install logs and do any troubleshooting
ls -ltr /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/logs/19606/ip-10-10-85-64
-rw-r--r-- 1 root root 77326 Jul 21 17:47 ComputeNode.sh.log
-rw-r--r-- 1 root root   864 Jul 21 17:48 ComputeNodePostReboot.log
-rw-r--r-- 1 root root    12 Jul 21 17:48 ComputeNodeUserCustom.log
-rw-r--r-- 1 root root 73009 Jul 21 17:48 ComputeNodeUserCustomization.log
-rw-r--r-- 1 root root 77995 Jul 21 17:48 ComputeNodeConfigureMetrics.log
~~~

### If CloudFormation stack is NOT "CREATE_COMPLETE"

![](../imgs/job-launch-4.png)

Click on the stack name then check the "Events" tab and refer to any "CREATE_FAILED" errors

![](../imgs/job-launch-5.png)

In this example, the size of root device is too small and can be fixed by specify a bigger EBS disk using  `-l root_size=75`


### If CloudFormation stack is "CREATE_COMPLETE"

![](../imgs/job-launch-1.png)

First, make sure CloudFormation has created a new "Launch Template" for your job.

![](../imgs/job-launch-2.png)

Then navigate to AutoScaling console, select your AutoScaling group and click "Activity". You will see any EC2 errors related in this tab.

Here is an example of capacity being provisioned correctly

![](../imgs/job-launch-3.png)

Here is an example of capacity provisioning errors:

![](../imgs/job-launch-6.png)






If capacity is being provisioned correctly, go back to Scale-Out Computing on AWS and run `pbsnodes -a`. Verify the capacity assigned to your job ID (refer to `resources_available.compute_node`) is in `state = free`.

~~~hl_lines="7"
pbsnodes -a
ip-60-0-174-166
     Mom = ip-60-0-174-166.us-west-2.compute.internal
     Port = 15002
     pbs_version = 18.1.4
     ntype = PBS
     state = free
     pcpus = 1
     resources_available.arch = linux
     resources_available.availability_zone = us-west-2c
     resources_available.compute_node = job2
     resources_available.host = ip-60-0-174-166
     resources_available.instance_type = m5.large
     resources_available.mem = 7706180kb
     resources_available.ncpus = 1
     resources_available.subnet_id = subnet-0af93e96ed9c4377d
     resources_available.vnode = ip-60-0-174-166
     resources_assigned.accelerator_memory = 0kb
     resources_assigned.hbmem = 0kb
     resources_assigned.mem = 0kb
     resources_assigned.naccelerators = 0
     resources_assigned.ncpus = 0
     resources_assigned.vmem = 0kb
     queue = normal
     resv_enable = True
     sharing = default_shared
     last_state_change_time = Sat Oct 12 17:37:28 2019
~~~

If host is not in `state = free` after 10 minutes, SSH to the host, sudo as root and check the log file located under `/root` as well as `/var/log/message | grep cloud-init`
