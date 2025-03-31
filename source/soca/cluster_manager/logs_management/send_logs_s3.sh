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
# To prevent disk to fill up, we also remove ***unmodified*** files after 10 days (default). This value can be changed using DATA_RETENTION_IN_DAYS variable

# Note: SOCA also supports AWS Backup  https://awslabs.github.io/scale-out-computing-on-aws-documentation/documentation/security/backup-restore-your-cluster/

exec > "$(dirname "$(realpath "$0")")/send_logs_s3.log" 2>&1

source /etc/environment
AWSCLI=$(which aws)
S3_BUCKET_REGION=$(${AWSCLI} s3api get-bucket-location --bucket ${SOCA_INSTALL_BUCKET} --output text)

# Number of days logs stay in the server without being modified
# It's not recommended to keep this settings too low, as the script could delete config file for job that hasn't been processed yet
# Recommended to keep this value > 5 days
DATA_RETENTION_IN_DAYS=10

# Backup location
BACKUP_S3_PREFIX_LOCATION="s3://${SOCA_INSTALL_BUCKET}/${SOCA_CLUSTER_ID}/${SOCA_VERSION}/cluster_logs"

# Content of these directory will be backup to S3, and file/dir may be subject to removal based on DATA_RETENTION_IN_DAYS value
DIRS_TO_SYNC=(
  "/var/spool/pbs/server_logs/"
  "/var/spool/pbs/sched_logs/"
  "/var/spool/pbs/server_priv/accounting/"
  "/opt/soca/${SOCA_CLUSTER_ID}/cluster_node_bootstrap/logs/dcv_node/"
  "/opt/soca/${SOCA_CLUSTER_ID}/cluster_node_bootstrap/logs/compute_node/"
  "/opt/soca/${SOCA_CLUSTER_ID}/cluster_node_bootstrap/logs/login_node/"
  "/opt/soca/${SOCA_CLUSTER_ID}/cluster_manager/orchestrator/logs/"
  "/opt/soca/${SOCA_CLUSTER_ID}/cluster_manager/analytics/logs/"
  "/opt/soca/${SOCA_CLUSTER_ID}/cluster_manager/web_interface/logs/"
)

for DIR in "${DIRS_TO_SYNC[@]}"
do
  if [[ -d "${DIR}" ]]; then
    # Sync directory to S3
    ${AWSCLI} s3 sync "${DIR}" "${BACKUP_S3_PREFIX_LOCATION}/${DIR}" --region ${S3_BUCKET_REGION} --quiet

    # Delete file/directory if needed
    if [[ ${DIR} =~ "/opt/soca/${SOCA_CLUSTER_ID}/cluster_node_bootstrap/logs/compute_node/" ]] || [[ ${DIR} =~ "/opt/soca/${SOCA_CLUSTER_ID}/cluster_node_bootstrap/logs/dcv_node/" ]]; then
      # Find all directory and delete them if older than data retention
      # These directory contains log file specific to ephemeral hosts (DCV/HPC nodes)
      find "${DIR}" -mindepth 1 -maxdepth 1 -type d -mtime +${DATA_RETENTION_IN_DAYS} -print0 | while IFS= read -r -d '' dir; do
        echo "Removing compute_node/dcv_node directory: ${dir}"
        rm -r "${dir}"
      done
    else
      # Find all files and delete them if older than data retention
      find "${DIR}" -type f -mtime +${DATA_RETENTION_IN_DAYS} -print0 | while IFS= read -r -d '' file; do
        echo "Removing file: ${file}"
        rm "$file"
      done
   fi
  else
    echo "Skipping Directory ${DIR} because it does not exist."
  fi
done