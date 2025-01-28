#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

# Check if exactly one argument is provided
if [ $# -ne 1 ]; then
  echo "Usage: $0 {cluster_nodes_tracking|job_tracking|desktop_hosts_tracking}"
  exit 1
else
  ANALYTICS_MODE=${1}
fi

source /etc/environment

if [[ -z "${SOCA_CLUSTER_ID}" ]]; then
  echo "SOCA_CLUSTER_ID environment variable not found."
  exit 1

else
  export PYTHONPATH=/apps/soca/${SOCA_CLUSTER_ID}/cluster_manager/
  case ${ANALYTICS_MODE} in
    cluster_nodes_tracking)
      "/apps/soca/${SOCA_CLUSTER_ID}/python/latest/bin/python3" "/apps/soca/${SOCA_CLUSTER_ID}/cluster_manager/analytics/cluster_nodes_tracking.py"
      ;;

    job_tracking)
      "/apps/soca/${SOCA_CLUSTER_ID}/python/latest/bin/python3" "/apps/soca/${SOCA_CLUSTER_ID}/cluster_manager/analytics/job_tracking.py"
      ;;

    desktop_hosts_tracking)
       "/apps/soca/${SOCA_CLUSTER_ID}/python/latest/bin/python3" "/apps/soca/${SOCA_CLUSTER_ID}/cluster_manager/analytics/desktop_hosts_tracking.py"
      ;;

    *)
      echo "Invalid argument: ${ANALYTICS_MODE}"
      echo "Usage: $0 {cluster_nodes_tracking|job_tracking|desktop_hosts_tracking}"
      exit 1
      ;;
  esac

fi
