#!/bin/bash

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0  

echo "soca_installer.sh is legacy, please use edh_installer.sh instead. soca_installer.sh will be deprecated soon"
echo "Forwarding to edh_installer.sh..."
echo ""

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Forward all arguments to edh_installer.sh
exec "${SCRIPT_DIR}/edh_installer.sh" "$@"
