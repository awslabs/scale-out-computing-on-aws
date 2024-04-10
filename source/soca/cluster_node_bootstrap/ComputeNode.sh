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

if [[ $# -lt 1 ]]; then
    exit 1
fi

SCHEDULER_HOSTNAME=$1

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


# Prepare System
cd ~

# In case AMI already have PBS installed, force it to stop
openpbs_stop

# Install SSM
amazon_ssm_agent_install

# Install system packages + verify if we are using a custom AMI
system_packages_install

# Check if the yum updates above installed a new kernel version
REQUIRE_REBOOT=0
if [[ $(rpm -qa kernel | wc -l) -gt 1 ]]; then
    REQUIRE_REBOOT=1
fi

# Configure Scratch Directory if specified by the user
system_configure_scratch

# Install OpenPBS if needed
openpbs_install

# Edit path with new scheduler/python locations
echo "export PATH=\"/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/opt/pbs/bin:/opt/pbs/sbin:/opt/pbs/bin:/apps/soca/$SOCA_CONFIGURATION/python/latest/bin\"" >> /etc/environment

# Configure Host
echo $SERVER_IP $SERVER_HOSTNAME $SERVER_HOSTNAME_ALT >> /etc/hosts

# Configure OpenLDAP or Microsoft AD
if [[ "$SOCA_AUTH_PROVIDER" == "openldap" ]]; then
  openldap_configure
else
  active_directory_configure
fi

# Disable SELINUX & firewalld
system_disable_selinux_firewalld

# Disable StrictHostKeyChecking
system_disable_stricthostkeychecking

# Configure PBS
openpbs_postinstall_mom_config

# Disable Nouveau driver if GPU instance
if [[ "${GPU_INSTANCE_FAMILY[@]}" =~ "${INSTANCE_FAMILY}" ]]; then
  gpu_instance_disable_nouveau_driver
fi

# Configure Chrony
chrony_configure

# Disable ulimits
ulimits_disable

# Reboot to disable SELINUX if needed
if [[ $REQUIRE_REBOOT -eq 1 ]] || [[ $SOCA_JOB_TYPE == "dcv" ]]; then
    echo "Rebooting Compute Node - ( RequireReboot: ${REQUIRE_REBOOT} / SOCA_JOB_TYPE: ${SOCA_JOB_TYPE})"
    sudo reboot
else
    crontab -r
    /bin/bash /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ComputeNodePostReboot.sh >> $SOCA_HOST_SYSTEM_LOG/ComputeNodePostReboot.log 2>&1
fi

# Upon reboot, ComputeNodePostReboot will be executed
