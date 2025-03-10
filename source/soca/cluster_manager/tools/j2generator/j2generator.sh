#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

source /etc/environment
if [[ -z "${SOCA_CLUSTER_ID}" ]]; then
  echo "SOCA_CLUSTER_ID environment variable not found."
  exit 1
else
  export PYTHONPATH=/apps/soca/${SOCA_CLUSTER_ID}/cluster_manager/
  "/apps/soca/${SOCA_CLUSTER_ID}/python/latest/bin/python3" "/apps/soca/${SOCA_CLUSTER_ID}/cluster_manager/tools/j2generator/app.py" "$@"
fi