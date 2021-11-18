---
title: Monitor your cluster and job activity
---

!!!info
    Indexes have been renamed on SOCA 2.7.0 and newer:

    - jobs -> soca_jobs
    - pbsnodes -> soca_nodes
    - soca_desktops (new)

### Dashboard URL

Open your AWS console and navigate to CloudFormation. Select your parent Stack, click Output, and retrieve "WebUserInterface" 

### Index Information


|  | Cluster Nodes Data | Job Data | DCV Desktop Data |
| ------------------------ | ----------- | ---------- |  ---------- |
| Kibana Index Name       | soca_nodes         | soca_jobs        | soca_desktops
| Script       | /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/cluster_nodes_tracking.py         | /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/job_tracking.py        | /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/desktops_tracking.py |
| Recurrence     | 1 minute         | 1 hour **(note: job must be terminated to be shown on OpenSearch (formerly Elasticsearch))**       | 10 minutes |
| Data uploaded         | Host Info (status of provisioned host, lifecycle, memory, cpu etc ..)         | Job Info (allocated hardware, licenses, simulation cost, job owner, instance type ...)        | Desktop Instance information |
| Timestamp Key   | Use "timestamp" when you create the index for the first time         | use "start_iso" when you create the index for the first time        | Use "timestamp" when you create the index for the first time  |

!!!note
    Analytics scripts are cron jobs running on the scheduler node. You can change the recurrence to match your own requirements.

### Create Indexes

Since it's the first time you access this endpoint, you will need to configure your indexes.  
First, access Kibana URL and click "Explore on my Own"

![](../imgs/kibana-1.png)

Go under Management and Click Index Patterns

![](../imgs/kibana-2.png)

Create your first index by typing **pbsnodes***.

![](../imgs/ws-analytics-1.png)

Click next, and then specify the Time Filter key (**timestamp**). Once done, click Create Index Pattern.

![](../imgs/ws-analytics-2.png)

Repeat the same operation for **jobs*** index 

![](../imgs/ws-analytics-3.png)

This time,  select **start_iso** as time filter key.

![](../imgs/ws-analytics-4.png)


Once your indexes are configured, go to Kibana, select "Discover" tab to start visualizing the data

![](../imgs/kibana-5.png)


### Examples


#### Cluster Node

![](../imgs/kibana-6.png)


#### Job Metadata

![](../imgs/kibana-7.png)

### Troubleshooting access permission

Access to OpenSearch (formerly Elasticsearch) is restricted to the IP you have specified during the installation. If your IP change for any reason, you won't be able to access the analytics dashboard and will get the following error message:
~~~json
{"Message":"User: anonymous is not authorized to perform: es:ESHttpGet"}
~~~

To solve this issue, log in to AWS Console  and go to OpenSearch (formerly Elasticsearch) Service dashboard. Select  your OpenSearch (formerly Elasticsearch) cluster and click "Modify Access Policy"

![](../imgs/kibana-8.png)

Finally, simply add your new IP under the "Condition" block, then click Submit

![](../imgs/kibana-9.png)

Please note it may take up to 5 minutes for your IP to be validated

###[Create your own dashboard](../../analytics/build-kibana-dashboards/)