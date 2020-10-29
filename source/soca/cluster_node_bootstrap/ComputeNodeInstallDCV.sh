#!/bin/bash -xe

source /etc/environment
source /root/config.cfg

DCV_HOST_ALTNAME=$(hostname | cut -d. -f1)
AWS=$(which aws)
INSTANCE_FAMILY=`curl --silent  http://169.254.169.254/latest/meta-data/instance-type | cut -d. -f1`
echo "Detected Instance family $INSTANCE_FAMILY"
GPU_INSTANCE_FAMILY=(g3 g4 g4dn)

# Install Gnome or  Mate Desktop
if [[ $SOCA_BASE_OS == "rhel7" ]]
then
  yum groupinstall "Server with GUI" -y
elif [[ $SOCA_BASE_OS == "amazonlinux2" ]]
then
  yum install -y $(echo ${DCV_AMAZONLINUX_PKGS[*]})
  amazon-linux-extras install mate-desktop1.x
  bash -c 'echo PREFERRED=/usr/bin/mate-session > /etc/sysconfig/desktop'
else
  # Centos7
  yum groupinstall "GNOME Desktop" -y
fi

# Automatic start Gnome upon reboot
systemctl set-default graphical.target

# Install latest NVIDIA driver if GPU instance is detected
if [[ "${GPU_INSTANCE_FAMILY[@]}" =~ "${INSTANCE_FAMILY}" ]];
then
  # clean previously installed drivers
  echo "Detected GPU instance .. installing NVIDIA Drivers"
  rm -f /root/NVIDIA-Linux-x86_64*.run
  $AWS s3 cp --quiet --recursive s3://ec2-linux-nvidia-drivers/latest/ .
  rm -rf /tmp/.X*
  /bin/sh /root/NVIDIA-Linux-x86_64*.run -q -a -n -X -s
  NVIDIAXCONFIG=$(which nvidia-xconfig)
  $NVIDIAXCONFIG --preserve-busid --enable-all-gpus
fi

# Download and Install DCV
cd ~
wget $DCV_URL
if [[ $(md5sum $DCV_TGZ | awk '{print $1}') != $DCV_HASH ]];  then
    echo -e "FATAL ERROR: Checksum for DCV failed. File may be compromised." > /etc/motd
    exit 1
fi

# Install DCV server and Xdcv
tar zxvf $DCV_TGZ
cd nice-dcv-$DCV_VERSION
rpm -ivh nice-xdcv-*.rpm --nodeps
rpm -ivh nice-dcv-server*.rpm --nodeps

# Enable DCV support for USB remotization
yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm
yum install -y dkms
DCVUSBDRIVERINSTALLER=$(which dcvusbdriverinstaller)
$DCVUSBDRIVERINSTALLER --quiet

# Enable GPU support
if [[ "${GPU_INSTANCE_FAMILY[@]}" =~ "${INSTANCE_FAMILY}" ]];
then
    echo "Detected GPU instance, adding support for nice-dcv-gl"
    rpm -ivh nice-dcv-gl*.rpm --nodeps
    #DCVGLADMIN=$(which dcvgladmin)
    #$DCVGLADMIN enable
fi

# Configure DCV
mv /etc/dcv/dcv.conf /etc/dcv/dcv.conf.orig
IDLE_TIMEOUT=1440 # in minutes. Disconnect DCV (but not terminate the session) after 1 day if not active
USER_HOME=$(eval echo ~$SOCA_DCV_OWNER)
DCV_STORAGE_ROOT="$USER_HOME/storage-root" # Create the storage root location if needed
mkdir -p $DCV_STORAGE_ROOT
chown $SOCA_DCV_OWNER:$SOCA_DCV_OWNER $DCV_STORAGE_ROOT

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
web-url-path=\"/$DCV_HOST_ALTNAME\"
idle-timeout=$IDLE_TIMEOUT
[security]
auth-token-verifier=\"$SOCA_DCV_AUTHENTICATOR\"
no-tls-strict=true
os-auto-lock=false
""" > /etc/dcv/dcv.conf

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
if [[ "${GPU_INSTANCE_FAMILY[@]}" =~ "${INSTANCE_FAMILY}" ]];
then
  echo "@reboot dcv create-session --owner $SOCA_DCV_OWNER --storage-root \"$DCV_STORAGE_ROOT\" $SOCA_DCV_SESSION_ID # Do Not Delete"| crontab - -u $SOCA_DCV_OWNER
  exit 3 # notify ComputeNodePostReboot.sh to force reboot
else
  echo "@reboot dcv create-session --owner $SOCA_DCV_OWNER --storage-root \"$DCV_STORAGE_ROOT\" $SOCA_DCV_SESSION_ID # Do Not Delete"| crontab - -u $SOCA_DCV_OWNER
  exit 0
fi
