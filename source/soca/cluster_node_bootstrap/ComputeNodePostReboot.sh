#!/bin/bash -xe
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

set -x

source /etc/environment
source /root/config.cfg
export PATH=$PATH:/usr/local/bin

#
# Read in our bootstrap helper scripts
#
# Note: /apps/ partition is automatically added to /etc/fstab as part of the ASG UserData script

for i in /apps/soca/"${SOCA_CONFIGURATION}"/cluster_node_bootstrap/bootstrap.d/*.sh ; do
  if [[ -r "$i" ]]; then
    if [[ "${-#*i}" != "$-" ]]; then
      . "$i"
    else
      . "$i" >/dev/null
    fi
  fi
done

REQUIRE_REBOOT=0
echo "SOCA > BEGIN PostReboot setup"

# Make sure system is clean and PBS is stopped
# In case AMI already have PBS installed, force it to stop
openpbs_stop

# Clean crontab
crontab -r

# Begin DCV Customization
if [[ "$SOCA_JOB_TYPE" == "dcv" ]]; then
    echo "Installing DCV"
    /bin/bash /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ComputeNodeInstallDCV.sh >> $SOCA_HOST_SYSTEM_LOG/ComputeNodeInstallDCV.log 2>&1
    if [[ $? -eq 3 ]];
     then
       REQUIRE_REBOOT=1
    fi
    sleep 30
fi
# End DCV Customization

# Validate user identities
if [[ "$SOCA_AUTH_PROVIDER" == "activedirectory" ]]; then
   active_directory_validate_user_identity
fi
# End validate user identities

# Begin EFA Customization
if [[ "$SOCA_JOB_EFA" == "true" ]]; then
    efa_install
fi

# Configure FSx if specified by the user.
# Right before the reboot to minimize the time to wait for FSx to be AVAILABLE
if [[ "$SOCA_FSX_LUSTRE_BUCKET" != 'false' ]] || [[ "$SOCA_FSX_LUSTRE_DNS" != 'false' ]] ; then
    fsx_lustre_setup
fi

# Tag EBS disks manually as CFN ASG does not support it
tags_ebs_volumes

# Tag Network Interface for the Compute Node
tags_eni

echo -e "
Compute Node Ready for queue: $SOCA_JOB_QUEUE
" > /etc/motd

echo "Require Reboot: $REQUIRE_REBOOT"
if [[ $REQUIRE_REBOOT -eq 1 ]];
then
    rc_local_after_final_reboot
    reboot
else
  # Mount all disks
  mount -a

  # Disable HyperThreading
  if [[ $SOCA_INSTANCE_HYPERTHREADING == "false" ]]; then
      system_disable_hyperthreading
  fi

  if [[ "$SOCA_FSX_LUSTRE_BUCKET" != "false" ]] || [[ "$SOCA_FSX_LUSTRE_DNS" != "false" ]] ; then
    fsx_lustre_client_tuning_postmount
  fi

  # Begin USER Customization
  /bin/bash /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ComputeNodeUserCustomization.sh >> $SOCA_HOST_SYSTEM_LOG/ComputeNodeUserCustomization.log 2>&1
  # End USER Customization

  # Begin Metric Customization
  /bin/bash /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ComputeNodeConfigureMetrics.sh >> $SOCA_HOST_SYSTEM_LOG/ComputeNodeConfigureMetrics.log 2>&1
  # End Metric Customization

  # Post-Boot routine completed, starting PBS
  openpbs_start
fi

