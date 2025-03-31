#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

source /etc/environment
if [[ -z "${SOCA_CLUSTER_ID}" ]]; then
  echo "SOCA_CLUSTER_ID environment variable not found."
  exit 1
else
  source "/opt/soca/${SOCA_CLUSTER_ID}/python/latest/soca_python.env"
  "/opt/soca/${SOCA_CLUSTER_ID}/python/latest/bin/python3" "/opt/soca/${SOCA_CLUSTER_ID}/cluster_manager/tools/j2generator/app.py" "$@"
fi