#!/usr/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

echo "socawebui.sh is legacy, please use edhwebui.sh instead. socawebui.sh will be deprecated soon"
echo "Redirecting to edhwebui.sh..."

# Redirect to edhwebui.sh with all arguments
exec "$(dirname "$0")/edhwebui.sh" "$@"