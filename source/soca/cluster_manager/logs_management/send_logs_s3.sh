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

# This file send the scheduler logs to S3 every day
# This is particularly useful is you are planning to do data mining with services such as Glue / Athena
# To prevent disk to fill up, we also remove files after 10 days (default). This value can be changed using DATA_RETENTION variable

# Note: SOCA also supports AWS Backup  https://awslabs.github.io/scale-out-computing-on-aws/security/backup-restore-your-cluster/

exec > "$(dirname "$(realpath "$0")")/send_logs_s3.log" 2>&1
source /etc/environment
DATA_RETENTION=10 # number of days logs stay in the server 
AWSCLI=$(which aws)
BACKUP_S3_PREFIX_LOCATION="s3://${SOCA_INSTALL_BUCKET}/${SOCA_CONFIGURATION}/cluster_logs"
S3_BUCKET_REGION=$(${AWSCLI} s3api get-bucket-location --bucket ${SOCA_INSTALL_BUCKET} --output text)

# Note: we use the last  part of the path as the name of the folder in S3
DIRS_TO_SYNC=(
  "/var/spool/pbs/server_logs/"
  "/var/spool/pbs/sched_logs/"
  "/var/spool/pbs/server_priv/accounting/"
  "/apps/soca/${SOCA_CONFIGURATION}/cluster_node_bootstrap/logs/dcv_node/"
  "/apps/soca/${SOCA_CONFIGURATION}/cluster_node_bootstrap/logs/compute_node/"
  "/apps/soca/${SOCA_CONFIGURATION}/cluster_node_bootstrap/logs/login_node/"
)

for DIR in "${DIRS_TO_SYNC[@]}"
do

  ${AWSCLI} s3 sync ${DIR} "${BACKUP_S3_PREFIX_LOCATION}/${DIR}" --region ${S3_BUCKET_REGION}

  if [[ ${DIR} =~ "/apps/soca/${SOCA_CONFIGURATION}/cluster_node_bootstrap/logs/" ]]; then
    # remove log directory
    find ${DIR} -mindepth 1 -type d -mtime +${DATA_RETENTION} -print | xargs -I {} rm -r "{}"
  else
    # remove files, don't touch directory
    find ${DIR} -type f -mtime +${DATA_RETENTION} -print | xargs -I {} rm "{}"
  fi

done





