#!/bin/bash -xe

source /etc/environment
source /root/config.cfg

if [ $# -lt 1 ]
  then
    exit 0
fi

# In case AMI already have PBS installed, force it to stop
service pbs stop

# Install SSM
yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
systemctl enable amazon-ssm-agent
systemctl restart amazon-ssm-agent

SCHEDULER_HOSTNAME=$1
AWS=$(which aws)

# Prepare PBS/System
cd ~

# Install System required libraries
if [[ $SOCA_BASE_OS == "rhel7" ]];
then
    yum install -y $(echo ${SYSTEM_PKGS[*]} ${SCHEDULER_PKGS[*]}) --enablerepo rhui-REGION-rhel-server-optional
else
    yum install -y $(echo ${SYSTEM_PKGS[*]} ${SCHEDULER_PKGS[*]})
fi

yum install -y $(echo ${OPENLDAP_SERVER_PKGS[*]} ${SSSD_PKGS[*]})

# Configure Scratch Directory if specified by the user
mkdir /scratch/
if [[ $SOCA_SCRATCH_SIZE -ne 0 ]];
then
    LIST_ALL_DISKS=$(lsblk --list | grep disk | awk '{print $1}')
    for disk in $LIST_ALL_DISKS;
	    do
	    CHECK_IF_PARTITION_EXIST=$(lsblk -b /dev/$disk | grep part | wc -l)
	    CHECK_PARTITION_SIZE=$(lsblk -lnb /dev/$disk -o SIZE)
	    let SOCA_SCRATCH_SIZE_IN_BYTES=$SOCA_SCRATCH_SIZE*1024*1024*1024
	    if [[ $CHECK_IF_PARTITION_EXIST -eq 0 ]] && [[ $CHECK_PARTITION_SIZE -eq $SOCA_SCRATCH_SIZE_IN_BYTES ]];
	    then
	        echo "Detected /dev/$disk with no partition as scratch device"
		    mkfs -t ext4 /dev/$disk
            echo "/dev/$disk /scratch ext4 defaults 0 0" >> /etc/fstab
	    fi
    done
else
    # Use Instance Store if possible.
    # When instance has more than 1 instance store, raid + mount them as /scratch
	VOLUME_LIST=()
	if [[ ! -z $(ls /dev/nvme[0-9]n1) ]];
        then
        echo 'Detected Instance Store: NVME'
        DEVICES=$(ls /dev/nvme[0-9]n1)

    elif [[ ! -z $(ls /dev/xvdc[a-z]) ]];
        then
        echo 'Detected Instance Store: SSD'
        DEVICES=$(ls /dev/xvdc[a-z])
    else
        echo 'No instance store detected on this machine.'
    fi

	if [[ ! -z $DEVICES ]];
	then
        echo "Detected Instance Store with NVME:" $DEVICES
        # Clear Devices which are already mounted (eg: when customer import their own AMI)
        for device in $DEVICES;
        do
            CHECK_IF_PARTITION_EXIST=$(lsblk -b $device | grep part | wc -l)
            if [[ $CHECK_IF_PARTITION_EXIST -eq 0 ]];
             then
             echo "$device is free and can be used"
             VOLUME_LIST+=($device)
            fi
        done

	    VOLUME_COUNT=${#VOLUME_LIST[@]}
	    if [[ $VOLUME_COUNT -eq 1 ]];
	    then
	        # If only 1 instance store, mfks as ext4
	        echo "Detected  1 NVMe device available, formatting as ext4 .."
	        mkfs -t ext4 $VOLUME_LIST
	        echo "$VOLUME_LIST /scratch ext4 defaults 0 0" >> /etc/fstab
	    elif [[ $VOLUME_COUNT -gt 1 ]];
	    then
	        # if more than 1 instance store disks, raid them !
	        echo "Detected more than 1 NVMe device available, creating XFS fs ..."
	        DEVICE_NAME="md0"
            for dev in ${VOLUME_LIST[@]} ; do dd if=/dev/zero of=$dev bs=1M count=1 ; done
            echo yes | mdadm --create -f --verbose --level=0 --raid-devices=$VOLUME_COUNT /dev/$DEVICE_NAME ${VOLUME_LIST[@]}
            mkfs -t ext4 /dev/$DEVICE_NAME
            mdadm --detail --scan | tee -a /etc/mdadm.conf
            echo "/dev/$DEVICE_NAME /scratch ext4 defaults 0 0" >> /etc/fstab
        else
            echo "All volumes detected already have a partition or mount point and can't be used as scratch devices"
	    fi
    fi
fi


# Install OpenPBS if needed
cd ~
OPENPBS_INSTALLED_VERS=$(/opt/pbs/bin/qstat --version | awk {'print $NF'})
if [[ "$OPENPBS_INSTALLED_VERS" != "$OPENPBS_VERSION" ]]
then
    echo "OpenPBS Not Detected, Installing OpenPBS ..."
    cd ~
    wget $OPENPBS_URL
    if [[ $(md5sum $OPENPBS_TGZ | awk '{print $1}') != $OPENPBS_HASH ]];  then
        echo -e "FATAL ERROR: Checksum for OpenPBS failed. File may be compromised." > /etc/motd
        exit 1
    fi
    tar zxvf $OPENPBS_TGZ
    cd openpbs-$OPENPBS_VERSION
    ./autogen.sh
    ./configure --prefix=/opt/pbs
    make -j6
    make install -j6
    /opt/pbs/libexec/pbs_postinstall
    chmod 4755 /opt/pbs/sbin/pbs_iff /opt/pbs/sbin/pbs_rcp
    systemctl disable pbs
else
    echo "OpenPBS already installed, and at correct version."
fi

# Edit path with new scheduler/python locations
echo "export PATH=\"/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/opt/pbs/bin:/opt/pbs/sbin:/opt/pbs/bin:/apps/soca/$SOCA_CONFIGURATION/python/latest/bin\"" >> /etc/environment

# Disable SELINUX
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config

# Configure Host
SERVER_IP=$(hostname -I)
SERVER_HOSTNAME=$(hostname)
SERVER_HOSTNAME_ALT=$(echo $SERVER_HOSTNAME | cut -d. -f1)
echo $SERVER_IP $SERVER_HOSTNAME $SERVER_HOSTNAME_ALT >> /etc/hosts


# Configure Ldap
echo "URI ldap://$SCHEDULER_HOSTNAME" >> /etc/openldap/ldap.conf
echo "BASE $LDAP_BASE" >> /etc/openldap/ldap.conf

echo -e "[domain/default]
enumerate = True
autofs_provider = ldap
cache_credentials = True
ldap_search_base = $LDAP_BASE
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
sudo_provider = ldap
ldap_sudo_search_base = ou=Sudoers,$LDAP_BASE
ldap_uri = ldap://$SCHEDULER_HOSTNAME
ldap_id_use_start_tls = True
use_fully_qualified_names = False
ldap_tls_cacertdir = /etc/openldap/cacerts

[sssd]
services = nss, pam, autofs, sudo
full_name_format = %2\$s\%1\$s
domains = default

[nss]
homedir_substring = /data/home

[pam]

[sudo]
ldap_sudo_full_refresh_interval=86400
ldap_sudo_smart_refresh_interval=3600

[autofs]

[ssh]

[pac]

[ifp]

[secrets]" > /etc/sssd/sssd.conf


chmod 600 /etc/sssd/sssd.conf
systemctl enable sssd
systemctl restart sssd

echo | openssl s_client -connect $SCHEDULER_HOSTNAME:389 -starttls ldap > /root/open_ssl_ldap
mkdir /etc/openldap/cacerts/
cat /root/open_ssl_ldap | openssl x509 > /etc/openldap/cacerts/openldap-server.pem

authconfig --disablesssd --disablesssdauth --disableldap --disableldapauth --disablekrb5 --disablekrb5kdcdns --disablekrb5realmdns --disablewinbind --disablewinbindauth --disablewinbindkrb5 --disableldaptls --disablerfc2307bis --updateall
sss_cache -E
authconfig --enablesssd --enablesssdauth --enableldap --enableldaptls --enableldapauth --ldapserver=ldap://$SCHEDULER_HOSTNAME --ldapbasedn=$LDAP_BASE --enablelocauthorize --enablemkhomedir --enablecachecreds --updateall

echo "sudoers: files sss" >> /etc/nsswitch.conf

# Disable SELINUX & firewalld
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config

systemctl stop firewalld
systemctl disable firewalld

# Disable StrictHostKeyChecking
echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config
echo "UserKnownHostsFile /dev/null" >> /etc/ssh/ssh_config

# Configure PBS
cp /etc/pbs.conf /etc/pbs.conf.orig
echo -e "
PBS_SERVER=$SCHEDULER_HOSTNAME
PBS_START_SERVER=0
PBS_START_SCHED=0
PBS_START_COMM=0
PBS_START_MOM=1
PBS_EXEC=/opt/pbs
PBS_HOME=/var/spool/pbs
PBS_CORE_LIMIT=unlimited
PBS_SCP=/usr/bin/scp
" > /etc/pbs.conf

cp /var/spool/pbs/mom_priv/config /var/spool/pbs/mom_priv/config.orig
echo -e "
\$clienthost $SCHEDULER_HOSTNAME
\$usecp *:/dev/null /dev/null
\$usecp *:/data /data
"  > /var/spool/pbs/mom_priv/config

INSTANCE_FAMILY=`curl --silent  http://169.254.169.254/latest/meta-data/instance-type | cut -d. -f1`

# If GPU instance, disable NOUVEAU drivers before installing DCV as this require a reboot
# Rest of the DCV configuration is managed by ComputeNodeInstallDCV.sh
GPU_INSTANCE_FAMILY=(p2 p3 g2 g3 g4 g4dn)
if [[ "${GPU_INSTANCE_FAMILY[@]}" =~ "${INSTANCE_FAMILY}" ]];
then
    echo "Detected GPU instance .. disable NOUVEAU driver"
    cat << EOF | sudo tee --append /etc/modprobe.d/blacklist.conf
blacklist vga16fb
blacklist nouveau
blacklist rivafb
blacklist nvidiafb
blacklist rivatv
EOF
    echo GRUB_CMDLINE_LINUX="rdblacklist=nouveau" >> /etc/default/grub
    sudo grub2-mkconfig -o /boot/grub2/grub.cfg
fi

# Configure Chrony
yum remove -y ntp
mv /etc/chrony.conf  /etc/chrony.conf.original
echo -e """
# use the local instance NTP service, if available
server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4

# Use public servers from the pool.ntp.org project.
# Please consider joining the pool (http://www.pool.ntp.org/join.html).
# !!! [BEGIN] SOCA REQUIREMENT
# You will need to open UDP egress traffic on your security group if you want to enable public pool
#pool 2.amazon.pool.ntp.org iburst
# !!! [END] SOCA REQUIREMENT
# Record the rate at which the system clock gains/losses time.
driftfile /var/lib/chrony/drift

# Allow the system clock to be stepped in the first three updates
# if its offset is larger than 1 second.
makestep 1.0 3

# Specify file containing keys for NTP authentication.
keyfile /etc/chrony.keys

# Specify directory for log files.
logdir /var/log/chrony

# save data between restarts for fast re-load
dumponexit
dumpdir /var/run/chrony
""" > /etc/chrony.conf
systemctl enable chronyd

# Disable ulimit
echo -e  "
* hard memlock unlimited
* soft memlock unlimited
" >> /etc/security/limits.conf


# Reboot to disable SELINUX
sudo reboot
# Upon reboot, ComputenodePostReboot will be executed
