#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


# Load environments
# shellcheck source=/dev/null
source /etc/environment

# shellcheck source=/dev/null
source "/opt/soca/${SOCA_CLUSTER_ID}/python/latest/soca_python.env"


PYTHON_BIN="/opt/soca/${SOCA_CLUSTER_ID}/python/latest/bin/python3"
BASE_DIR="/opt/soca/${SOCA_CLUSTER_ID}/cluster_manager/orchestrator"
CONFIG_FILE="$BASE_DIR/settings/queue_mapping.yml"

if [[ -z "$1" ]]; then
    echo "Usage: $0 <queue_type>"
    echo "Example: $0 compute"
    exit 1
else
    TARGET=$1
fi


# Set SOCA_PREVIEW_NEXTGEN_SCHEDULER to "true" to test the new scheduler logic
export SOCA_PREVIEW_NEXTGEN_SCHEDULER="false" # force for dev
# export SOCA_DEBUG=1 # force for dev

if [[ "${SOCA_PREVIEW_NEXTGEN_SCHEDULER}" == "true" ]]; then
    echo "Running in Next Gen Scheduler mode, this is currently in preview and should not be used for production purposes. This module is actively being developed."
    ${PYTHON_BIN} "${BASE_DIR}/preview/dispatcher.py" -c "${CONFIG_FILE}" -t "${TARGET}"
else
    ${PYTHON_BIN} "${BASE_DIR}/dispatcher.py" -c "${CONFIG_FILE}" -t "${TARGET}"
fi