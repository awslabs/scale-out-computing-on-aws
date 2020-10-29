#!/bin/bash

# This file send the scheduler logs to S3 every day
# This is particularly useful is you are planning to do data mining with services such as Glue / Athena
# To prevent disk to fill up, we also remove files after 10 days (default). This value can be changed using DATA_RETENTION variable

source /etc/environment
DATA_RETENTION=10 # number of days logs stay in the server 
S3_BUCKET="s3://$SOCA_INSTALL_BUCKET/$SOCA_CONFIGURATION/cluster_logs/"
SCHEDULER_DIRECTORY='/var/spool/pbs'
SCHEDULER_SERVER_LOGS=$SCHEDULER_DIRECTORY'/server_logs/'
SCHEDULER_SCHED_LOGS=$SCHEDULER_DIRECTORY'/sched_logs/'
SCHEDULER_ACCOUNTING=$SCHEDULER_DIRECTORY'/server_priv/accounting/'
COMPUTE_HOST_LOG="/apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/logs"
/usr/bin/aws s3 sync $SCHEDULER_ACCOUNTING $S3_BUCKET'accounting/'
/usr/bin/aws s3 sync $SCHEDULER_SERVER_LOGS $S3_BUCKET'server_logs/'
/usr/bin/aws s3 sync $SCHEDULER_SCHED_LOGS $S3_BUCKET'sched_logs/'
/usr/bin/aws s3 sync $COMPUTE_HOST_LOG $S3_BUCKET'compute_host_logs/'

find $COMPUTE_HOST_LOG/* -type d -mtime +$DATA_RETENTION -print | xargs -I {} rm -rf "{}"
find $SCHEDULER_SERVER_LOGS -type f -mtime +$DATA_RETENTION -print | xargs -I {} rm "{}"
find $SCHEDULER_SCHED_LOGS -type f -mtime +$DATA_RETENTION -print | xargs -I {} rm "{}"
find $SCHEDULER_ACCOUNTING -type f -mtime +$DATA_RETENTION -print | xargs -I {} rm "{}"

