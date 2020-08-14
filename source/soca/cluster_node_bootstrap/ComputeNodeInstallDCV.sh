#!/bin/bash -xe

source /etc/environment
source /root/config.cfg
DCV_HOST_ALTNAME=$(hostname | cut -d. -f1)
AWS=$(which aws)
INSTANCE_TYPE=`curl --silent  http://169.254.169.254/latest/meta-data/instance-type | cut -d. -f1`
GPU_INSTANCE_FAMILY=(g2 g3 g4 g4dn p2 p3 p3dn)

# Install Gnome & Mate Desktop
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

# Download and Install DCV
cd ~
wget $DCV_URL
if [[ $(md5sum $DCV_TGZ | awk '{print $1}') != $DCV_HASH ]];  then
    echo -e "FATAL ERROR: Checksum for DCV failed. File may be compromised." > /etc/motd
    exit 1
fi
tar zxvf $DCV_TGZ
cd nice-dcv-$DCV_VERSION
rpm -ivh *.rpm --nodeps


# Uninstall dcv-gl if not GPU instances
if [[ ! "${GPU_INSTANCE_FAMILY[@]}" =~ "${INSTANCE_TYPE}" ]];
then
    DCVGLADMIN=$(which dcvgladmin)
    $DCVGLADMIN disable
fi

# Configure
mv /etc/dcv/dcv.conf /etc/dcv/dcv.conf.orig

#https://docs.aws.amazon.com/dcv/latest/adminguide/manage-disconnect.html
IDLE_TIMEOUT=1440 # in minutes. Disconnect DCV (but not terminate the session) after 1 day if not active

echo -e """
[license]
[log]
[session-management]
virtual-session-xdcv-args=\"-listen tcp\"
[session-management/defaults]
[session-management/automatic-console-session]
[display]
# add more if using an instance with more GPU
cuda-devices=[\"0\"]
[display/linux]
# add more if using an instance with more GPU
gl-displays = [\":0.0\"]
[display/linux]
use-glx-fallback-provider=false
[connectivity]
web-url-path=\"/$DCV_HOST_ALTNAME\"
idle-timeout=$IDLE_TIMEOUT
[security]
auth-token-verifier=\"http://localhost:8444\"
""" > /etc/dcv/dcv.conf

# Start DCV Authenticator
mkdir -p /var/run/dcvsimpleextauth
chmod 777 /var/run/dcvsimpleextauth
sudo systemctl enable dcvsimpleextauth
sudo systemctl start dcvsimpleextauth

# Start DCV server
sudo systemctl enable dcvserver
sudo systemctl start dcvserver

systemctl stop firewalld
systemctl disable firewalld

# Final reboot is needed to update GPU drivers if running on G2/G3. Reboot will be triggered by ComputeNodePostReboot.sh

if [[ "${GPU_INSTANCE_FAMILY[@]}" =~ "${INSTANCE_TYPE}" ]];
then
    exit 3 # notify ComputeNodePostReboot.sh to force reboot
fi

# Start X
systemctl isolate graphical.target
exit 0