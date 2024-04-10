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

source /etc/environment
source /root/config.cfg

for i in /apps/soca/"${SOCA_CONFIGURATION}"/cluster_node_bootstrap/bootstrap.d/*.sh ; do
  if [[ -r "$i" ]]; then
    if [[ "${-#*i}" != "$-" ]]; then
      . "$i"
    else
      . "$i" >/dev/null
    fi
  fi
done

echo "Detected Instance family $INSTANCE_FAMILY"
mkdir -p /root/gpu_drivers

echo "GPU INSTANCE FAMILY ${GPU_INSTANCE_FAMILY[@]}"
echo "NVIDIA INSTANCE FAMILY ${NVIDIA_GPU_INSTANCE_FAMILY[@]}"
echo "AMD INSTANCE FAMILY ${AMD_GPU_INSTANCE_FAMILY[@]}"

# DCV PreRequisites
if [[ -z "$(rpm -qa gnome-terminal)" ]]; then
  if [[ $SOCA_BASE_OS == "amazonlinux2" ]]; then
      yum install -y $(echo ${DCV_AMAZONLINUX_PKGS[*]})
  elif [[ ${SOCA_BASE_OS} == "rhel7" ]]; then
    yum groups mark convert
    yum groupinstall "Server with GUI" -y --skip-broken
  elif [[ ${SOCA_BASE_OS} == "centos7" ]]; then
    yum groups mark convert
    yum groupinstall "GNOME Desktop" -y --skip-broken
  elif [[ ${SOCA_BASE_OS} =~ ^(rhel8|rhel9|rocky8|rocky9)$ ]]; then
    yum groupinstall "Server with GUI" -y --skip-broken --disablerepo=epel-cisco-openh264
    sed -i 's/#WaylandEnable=false/WaylandEnable=false/' /etc/gdm/custom.conf
    systemctl restart gdm
    # The following is a workaroud to disable the pop-up "Authentication required to refresh system repositories"
    # see details in https://bugzilla.redhat.com/show_bug.cgi?id=1857654
    echo "[Disable Package Management all Users]
  Identity=unix-user:*
  Action=org.freedesktop.packagekit.system-sources-refresh
  ResultAny=no
  ResultInactive=no
  ResultActive=no" > /etc/polkit-1/localauthority/50-local.d/repos.pkla
    systemctl restart polkit
    # The next commands remove the "System Not Registered" notification
    # see details in https://access.redhat.com/solutions/6976776
    sed -i 's,Exec=/usr/libexec/gsd-subman,#Exec=/usr/libexec/gsd-subman,' /etc/xdg/autostart/org.gnome.SettingsDaemon.Subscription.desktop
    yum -y remove subscription-manager-cockpit
  else
    echo "No additional customization needed for this OS"
  fi
else
  echo "Found gnome-terminal pre-installed... skipping dcv prereq installation..."
fi

pushd /root/gpu_drivers

# Install latest NVIDIA driver if GPU instance is detected
if [[ "${GPU_INSTANCE_FAMILY[@]}" =~ "${INSTANCE_FAMILY}" ]]; then
  echo "Detected GPU Instance"
  if [[ "${NVIDIA_GPU_INSTANCE_FAMILY[@]}" =~ "${INSTANCE_FAMILY}" ]]; then
    echo "Detected NVIDIA GPU"
    gpu_instance_install_nvidia_driver
    gpu_instance_optimize_gpu_clock_speed_nvidia
  elif [[ "${AMD_GPU_INSTANCE_FAMILY[@]}" =~ "${INSTANCE_FAMILY}" ]]; then
    echo "Detected AMD GPU"
    gpu_instance_install_amd_driver
  fi
fi

popd

# Automatic start Gnome upon reboot
systemctl set-default graphical.target

cd ~

if [[ ${SOCA_BASE_OS} =~ ^(rhel7|centos7|amazonlinux2)$ ]]; then
  if [[ ${MACHINE} == "x86_64" ]]; then
    DCV_URL=${DCV_7_X86_64_URL}
    DCV_HASH=${DCV_7_X86_64_HASH}
    DCV_TGZ=${DCV_7_X86_64_TGZ}
    DCV_VERSION=${DCV_7_X86_64_VERSION}
  elif [[ $MACHINE == "aarch64" ]]; then
    DCV_URL=${DCV_7_AARCH64_URL}
    DCV_HASH=${DCV_7_AARCH64_HASH}
    DCV_TGZ=${DCV_7_AARCH64_TGZ}
    DCV_VERSION=${DCV_7_AARCH64_VERSION}
  else
    echo -e "FATAL ERROR: Unrecognized Machine type: Detected ${MACHINE}, expected x86_64 or aarch64"
    exit 1
  fi

elif [[ ${SOCA_BASE_OS} =~ ^(rhel8|rocky8)$ ]]; then
  if [[ ${MACHINE} == "x86_64" ]]; then
    DCV_URL=${DCV_8_X86_64_URL}
    DCV_HASH=${DCV_8_X86_64_HASH}
    DCV_TGZ=${DCV_8_X86_64_TGZ}
    DCV_VERSION=${DCV_8_X86_64_VERSION}
  elif [[ $MACHINE == "aarch64" ]]; then
    DCV_URL=${DCV_8_AARCH64_URL}
    DCV_HASH=${DCV_8_AARCH64_HASH}
    DCV_TGZ=${DCV_8_AARCH64_TGZ}
    DCV_VERSION=${DCV_8_AARCH64_VERSION}
  else
    echo -e "FATAL ERROR: Unrecognized Machine type: Detected ${MACHINE}, expected x86_64 or aarch64"
    exit 1
  fi
elif [[ ${SOCA_BASE_OS} =~ ^(rhel9|rocky9)$ ]]; then
   if [[ ${MACHINE} == "x86_64" ]]; then
    DCV_URL=${DCV_9_X86_64_URL}
    DCV_HASH=${DCV_9_X86_64_HASH}
    DCV_TGZ=${DCV_9_X86_64_TGZ}
    DCV_VERSION=${DCV_9_X86_64_VERSION}
  elif [[ $MACHINE == "aarch64" ]]; then
    DCV_URL=${DCV_9_AARCH64_URL}
    DCV_HASH=${DCV_9_AARCH64_HASH}
    DCV_TGZ=${DCV_9_AARCH64_TGZ}
    DCV_VERSION=${DCV_9_AARCH64_VERSION}
  else
    echo -e "FATAL ERROR: Unrecognized Machine type: Detected ${MACHINE}, expected x86_64 or aarch64"
    exit 1
  fi
else
  echo -e "FATAL ERROR: Unrecognized Base OS : Detected  ${SOCA_BASE_OS} "
  exit 1
fi

echo "Detected following DCV download information:"
echo "DCV_URL ${DCV_URL}"
echo "DCV_HASH ${DCV_HASH}"
echo "DCV_TGZ ${DCV_TGZ}"
echo "DCV_VERSION ${DCV_VERSION}"

# Download and Install DCV
echo "Downloading DCV ..."
wget $DCV_URL
if [[ $(md5sum $DCV_TGZ | awk '{print $1}') != $DCV_HASH ]];  then
    echo -e "FATAL ERROR: Checksum for DCV failed. File may be compromised." > /etc/motd
    exit 1
fi
echo "Extracting DCV archive ..."
tar zxvf $DCV_TGZ
cd nice-dcv-$DCV_VERSION

echo "Installing DCV ..."

rpm -ivh nice-xdcv-*.${MACHINE}.rpm --nodeps
rpm -ivh nice-dcv-server-*.${MACHINE}.rpm --nodeps
rpm -ivh nice-dcv-web-viewer-*.${MACHINE}.rpm --nodeps

echo "Enable DCV support for USB remotization .. "
yum install -y dkms
DCVUSBDRIVERINSTALLER=$(which dcvusbdriverinstaller)
$DCVUSBDRIVERINSTALLER --quiet

# Enable GPU support
if [[ "${GPU_INSTANCE_FAMILY[@]}" =~ "${INSTANCE_FAMILY}" ]]; then
    echo "Detected GPU instance, adding support for nice-dcv-gl"
    rpm -ivh nice-dcv-gl*.rpm --nodeps
fi

# Configure DCV
mv /etc/dcv/dcv.conf /etc/dcv/dcv.conf.orig
IDLE_TIMEOUT=1440 # in minutes. Disconnect DCV (but not terminate the session) after 1 day if not active
USER_HOME=$(eval echo ~$SOCA_DCV_OWNER)
DCV_STORAGE_ROOT="$USER_HOME/storage-root" # Create the storage root location if needed


mkdir -p $DCV_STORAGE_ROOT
chown $SOCA_DCV_OWNER $DCV_STORAGE_ROOT

echo -e """
[license]
[log]
[session-management]
virtual-session-xdcv-args=\"-listen tcp\"
[session-management/defaults]
[session-management/automatic-console-session]
storage-root=\"$DCV_STORAGE_ROOT\"
[display]
# add more if using an instance with more GPU
cuda-devices=[\"0\"]
[display/linux]
gl-displays = [\":1.0\"]
[display/linux]
use-glx-fallback-provider=false
[connectivity]
web-url-path=\"/$SERVER_HOSTNAME_ALT\"
idle-timeout=$IDLE_TIMEOUT
[security]
auth-token-verifier=\"$SOCA_DCV_AUTHENTICATOR\"
no-tls-strict=true
os-auto-lock=false
""" > /etc/dcv/dcv.conf

# Disable DPMS
echo "Disabling X11 DPMS"
echo -e """
Section \"Extensions\"
    Option      \"DPMS\" \"Disable\"
EndSection""" > /etc/X11/xorg.conf.d/99-disable-dpms.conf

# Start DCV server
sudo systemctl enable dcvserver
sudo systemctl stop dcvserver
sleep 5
sudo systemctl start dcvserver

systemctl stop firewalld
systemctl disable firewalld

# Start X
systemctl isolate graphical.target

# Start Session
echo "Launching session ... : dcv create-session --user $SOCA_DCV_OWNER --owner $SOCA_DCV_OWNER --type virtual --storage-root "$DCV_STORAGE_ROOT" $SOCA_DCV_SESSION_ID"
dcv create-session --user $SOCA_DCV_OWNER --owner $SOCA_DCV_OWNER --type virtual --storage-root "$DCV_STORAGE_ROOT" $SOCA_DCV_SESSION_ID
echo $?
sleep 5

# Final reboot is needed to update GPU drivers if running GPU instance. Reboot will be triggered by ComputeNodePostReboot.sh
if [[ "${GPU_INSTANCE_FAMILY[@]}" =~ "${INSTANCE_FAMILY}" ]]; then
  echo "@reboot dcv create-session --owner $SOCA_DCV_OWNER --storage-root \"$DCV_STORAGE_ROOT\" $SOCA_DCV_SESSION_ID # Do Not Delete"| crontab - -u $SOCA_DCV_OWNER
  exit 3 # notify ComputeNodePostReboot.sh to force reboot
else
  echo "@reboot dcv create-session --owner $SOCA_DCV_OWNER --storage-root \"$DCV_STORAGE_ROOT\" $SOCA_DCV_SESSION_ID # Do Not Delete"| crontab - -u $SOCA_DCV_OWNER
  exit 0
fi
