#!/bin/bash
######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

# Optional Arguments:
#  -j <jobid> to retrieve system logs for a given job. If not specified no job logs are retrieved.
#  -q <queue> to retrieve log for a specific queue. If not specified all queues logs are retrieved.
#  -d <user> to retrieve desktop logs for a given user. If not specified no desktop logs are retrieved.
# Refer to https://awslabs.github.io/scale-out-computing-on-aws/tutorials/troubleshoot-job-queue/ for additional data

if [[ "$EUID" -ne 0 ]]
  then echo "Script must be run as root"
  exit
fi

source /etc/environment
SCRIPT_PATH=$(dirname $(realpath "$0"))
cd $SCRIPT_PATH
NOW=$(date +%s)
HOSTNAME=$(hostname | awk '{split($0,a,"."); print a[1]}')
SCHEDULER_HOSTNAME=$(/opt/pbs/bin/qstat -Bf | grep "Server:" | awk '{print $2}')
SOCA_PATH="/apps/soca/$SOCA_CONFIGURATION"
DEBUG_PATH="debug/$NOW"
JOB_DEBUG_PATH="$DEBUG_PATH/job_log"
JOB_DESKTOP_DEBUG_PATH="$DEBUG_PATH/job_desktop_log"
QUEUE_DEBUG_PATH="$DEBUG_PATH/queues_log"
PBS_LOG_DEBUG_PATH="$DEBUG_PATH/pbs_logs"
PBS_SNAPSHOT_DEBUG_PATH="$DEBUG_PATH/pbs_snapshot"
WEB_UI_DEBUG_PATH="$DEBUG_PATH/web_ui_logs"
OTHER_DEBUG_PATH="$DEBUG_PATH/others"
CFN_DEBUG_PATH="$DEBUG_PATH/cloudformation"
mkdir -p $DEBUG_PATH

# Arguments
while getopts j:q:d: flag
do
    case "${flag}" in
        j) JOB=${OPTARG};;
        q) QUEUE=${OPTARG};;
        d) DESKTOP_USER=${OPTARG};;
        *) echo "Argument not recognized. Exiting ..." && exit 1;;
    esac
done

# Retrieve Job logs
if [[ -v $JOB ]]; then
  echo "BEGIN: Retrieving log for job $JOB"
  mkdir -p "$JOB_DEBUG_PATH"
  cp -r "$SOCA_PATH/cluster_node_bootstrap/logs/$JOB" "$JOB_DEBUG_PATH"
  tracejob $JOB > "$JOB_DEBUG_PATH/tracejob.$JOB.txt"
  echo "END: Retrieving log for job $JOB"
fi

# Retrieve desktop provisioning log.
# These are not DCV log. To get DCV logs you must SSH to the DCV hosts.
if [[ -v $DESKTOP_USER ]]; then
  echo "BEGIN: Retrieving Desktop job for user $DESKTOP_USER"
  mkdir -p "$JOB_DESKTOP_DEBUG_PATH"
  cp -r "$SOCA_PATH/cluster_node_bootstrap/logs/desktop/$DESKTOP_USER" "$JOB_DESKTOP_DEBUG_PATH"
  echo "END: Retrieving Desktop job for user $DESKTOP_USER"
fi

# Get Queues Logs
echo "BEGIN: Retrieving queue logs"
mkdir -p "$QUEUE_DEBUG_PATH"
if [[ -v $QUEUE ]]; then
  echo "No Queue specified, trying to copy all queue logs. Use -q to retrieve log for a given queue"
  cp -r "$SOCA_PATH/cluster_manager/logs" "$QUEUE_DEBUG_PATH"
else
  echo "Retrieving $QUEUE logs"
  cp "$SOCA_PATH/cluster_manager/logs/$QUEUE.log" "$QUEUE_DEBUG_PATH"
fi
echo "END: Retrieving queue logs"

# Get PBS logs
mkdir -p $PBS_LOG_DEBUG_PATH
echo "BEGIN: Retrieving PBS logs"
if [[ "$HOSTNAME" != "$SCHEDULER_HOSTNAME" ]]; then
    cp -r /var/spool/pbs/mom_logs "$PBS_LOG_DEBUG_PATH"
else
    cp -r /var/spool/pbs/sched_logs "$PBS_LOG_DEBUG_PATH"
    cp -r /var/spool/pbs/server_logs "$PBS_LOG_DEBUG_PATH"
fi
echo "END: Retrieving PBS logs"

# Get Web UI logs
mkdir -p "$WEB_UI_DEBUG_PATH"
echo "BEGIN: Retrieving Web UI logs"
cp -r "$SOCA_PATH/cluster_web_ui/logs" "$WEB_UI_DEBUG_PATH"
echo "END: Retrieving Web UI logs"

# PBS snapshot dump
mkdir -p "$PBS_SNAPSHOT_DEBUG_PATH"
echo "BEGIN: Retrieving PBS snapshot info"
qstat -f > "$PBS_SNAPSHOT_DEBUG_PATH/qstat_output.txt"
pbsnodes -a > "$PBS_SNAPSHOT_DEBUG_PATH/pbsnodes_output.txt"
qstat --version > "$OTHER_DEBUG_PATH/pbs_version.txt"

if [[ "$HOSTNAME" != "$SCHEDULER_HOSTNAME" ]]; then
 qmgr -c "print server" > "$PBS_SNAPSHOT_DEBUG_PATH/qmgr_output.txt"
fi
echo "END: Retrieving PBS snapshot info"

# Other system info
echo "BEGIN: Retrieving general system info"
mkdir -p "$OTHER_DEBUG_PATH"
cat /etc/environment > "$OTHER_DEBUG_PATH/etc_environment.txt"
env > "$OTHER_DEBUG_PATH/environment_variables.txt"
ps -aux > "$OTHER_DEBUG_PATH/running_processes.txt"
systemctl list-units --type=service > "$OTHER_DEBUG_PATH/services.txt"
iptables -L > "$OTHER_DEBUG_PATH/iptables.txt"
dmesg > "$OTHER_DEBUG_PATH/dmesg.txt"
df -h > "$OTHER_DEBUG_PATH/df.txt"
crontab -l > "$OTHER_DEBUG_PATH/crontabs.txt"
netstat -pantu > "$OTHER_DEBUG_PATH/crontabs.txt"
cp "/var/log/cloud-init.log" "$OTHER_DEBUG_PATH/cloud_init.txt"
cp "/var/log/message" "$OTHER_DEBUG_PATH/messages.txt"


echo "END: Retrieving general system info"

# Getting CLoudformation
echo "BEGIN: Retrieving Cloudformation logs"
mkdir -p "$CFN_DEBUG_PATH"
aws cloudformation describe-stacks --query "Stacks[?Tags[?Key == 'soca:ClusterId' && Value == '$SOCA_CONFIGURATION']]" >> "$CFN_DEBUG_PATH/describe_stacks.txt" 2>&1
echo "END: Retrieving Cloudformation logs"


echo "Log Collected, creating archive ..."
tar czf "$SCRIPT_PATH/$DEBUG_PATH/soca_debug_$NOW.tar.gz" "$SCRIPT_PATH/$DEBUG_PATH"

echo "******************************************"
echo "DEBUG LOGS CAN BE FOUND ON: $SCRIPT_PATH/$DEBUG_PATH"
echo "Archive: $SCRIPT_PATH/$DEBUG_PATH/soca_debug_$NOW.tar.gz"
echo "******************************************"



