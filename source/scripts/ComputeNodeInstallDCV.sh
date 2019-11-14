#!/bin/bash -xe

source /etc/environment
source /root/config.cfg
DCV_HOST_ALTNAME=$(hostname | cut -d. -f1)
AWS=$(which aws)
INSTANCE_TYPE=`curl --silent  http://169.254.169.254/latest/meta-data/instance-type | cut -d. -f1`


# Install Gnome
if [[ $SOCA_BASE_OS == "rhel7" ]]
then
   yum groupinstall "Server with GUI" -y

elif [[ $SOCA_BASE_OS == "amazonlinux2" ]]
then
   yum install -y $(echo ${DCV_AMAZONLINUX_PKGS[*]})

else
    # Centos7
   yum groupinstall "GNOME Desktop" -y
fi

# If GPU instance, install Nvidia Drivers first
if [[ "$INSTANCE_TYPE" == "g2" || "$INSTANCE_TYPE" == "g3"  ]]
then
    $AWS s3 cp --recursive s3://ec2-linux-nvidia-drivers/latest/ .
    /bin/sh /root/NVIDIA-Linux-x86_64*.run -q -a -n -X -s
    NVIDIAXCONFIG=$(which nvidia-xconfig)
    $NVIDIAXCONFIG --preserve-busid --enable-all-gpus
fi

# Automatic start Gnome upon reboot
systemctl set-default graphical.target

# Download and Install DCV
cd ~
wget $DCV_URL
if [[ $(md5sum $DCV_TGZ | awk '{print $1}') != $DCV_HASH ]];  then
    echo -e "FATAL ERROR: Checksum for PBSPro failed. File may be compromised." > /etc/motd
    exit 1
fi
tar zxvf $DCV_TGZ
cd nice-dcv-$DCV_VERSION
rpm -ivh *.rpm --nodeps

# Uninstall dcv-gl if not GPU instances
# Note: NVIDIA-CUDA drivers must be installed first
if [[ "$INSTANCE_TYPE" != "g2" || "$INSTANCE_TYPE" != "g3"  ]]
then
    DCVGLADMIN=$(which dcvgladmin)
    $DCVGLADMIN disable
fi

# Configure
mv /etc/dcv/dcv.conf /etc/dcv/dcv.conf.orig

echo -e """
[license]
[log]
[session-management]
virtual-session-xdcv-args=\"-listen tcp\"
[session-management/defaults]
[session-management/automatic-console-session]
[display]
[display/linux]
use-glx-fallback-provider=false
[connectivity]
web-url-path=\"/$DCV_HOST_ALTNAME\"
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

# Final reboot is needed to update GPU drivers if running on G2/G3
if [[ "$INSTANCE_TYPE" == "g2" && "$INSTANCE_TYPE" == "g3"  ]]
then
    reboot
fi
# Start X
systemctl isolate graphical.target