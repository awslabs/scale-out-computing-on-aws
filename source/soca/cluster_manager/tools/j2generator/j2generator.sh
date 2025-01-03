#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

source /etc/environment
if [[ -z "${SOCA_CONFIGURATION}" ]]; then
  echo "SOCA_CONFIGURATION environment variable not found."
  exit 1
else
  export PYTHONPATH=/apps/soca/${SOCA_CONFIGURATION}/cluster_manager/
  "/apps/soca/${SOCA_CONFIGURATION}/python/latest/bin/python3" "/apps/soca/${SOCA_CONFIGURATION}/cluster_manager/tools/j2generator/app.py" "$@"
fi