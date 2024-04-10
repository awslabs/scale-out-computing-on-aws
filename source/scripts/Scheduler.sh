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

if [[ $# -lt 2 ]]; then
    exit 1
fi


function auto_install {
  # Now perform the installs on the potentially updated package lists
  MAX_INSTALL_ATTEMPTS=10
  ATTEMPT_NUMBER=1
  SUCCESS=false

  if [[ $# -eq 0 ]]; then
    echo "No package list to install. Exiting... "
    exit 1
  fi

  while  [ $SUCCESS = false ] &&  [ $ATTEMPT_NUMBER -le $MAX_INSTALL_ATTEMPTS ]; do
    echo "Attempting to install packages (Attempt ${ATTEMPT_NUMBER}/${MAX_INSTALL_ATTEMPTS})"

    yum install -y $*
    if [[ $? -eq 0 ]]; then
      echo "Successfully installed packages on Attempt ${ATTEMPT_NUMBER}/${MAX_INSTALL_ATTEMPTS}"
      SUCCESS=true
    else
      echo "Failed to install packages on Attempt ${ATTEMPT_NUMBER}/${MAX_INSTALL_ATTEMPTS} . Sleeping for 60sec for retry"
      sleep 60
      ((ATTEMPT_NUMBER++))
    fi
  done

}

# Install SSM
machine=$(uname -m)
if ! systemctl status amazon-ssm-agent; then
    if [[ $machine == "x86_64" ]]; then
        yum install -y $SSM_X86_64_URL
    elif [[ $machine == "aarch64" ]]; then
        yum install -y $SSM_AARCH64_URL
    fi
    systemctl enable amazon-ssm-agent || true
    systemctl restart amazon-ssm-agent
fi

mkdir -p /apps/soca/"$SOCA_CONFIGURATION"
FS_DATA_PROVIDER=$1
FS_DATA=$2
FS_APPS_PROVIDER=$3
FS_APPS=$4
SERVER_IP=$(hostname -I)
SERVER_HOSTNAME=$(hostname)
SERVER_HOSTNAME_ALT=$(echo $SERVER_HOSTNAME | cut -d. -f1)
echo $SERVER_IP $SERVER_HOSTNAME $SERVER_HOSTNAME_ALT >> /etc/hosts

# Number of CPUs on the host (for compiles)
NCPU=$(nproc)

# Install System required libraries / EPEL
if [[ $SOCA_BASE_OS == "rhel7" ]] || [[ $SOCA_BASE_OS == "rhel8" ]] || [[ $SOCA_BASE_OS == "rhel9" ]]; then
  # RHEL7 / RHEL8 / RHEL9
  if [[ $SOCA_BASE_OS == "rhel7" ]]; then
    EPEL_URL=$EPEL7_URL
    EPEL_RPM=$EPEL7_RPM
    EPEL_REPO="epel"
    yum-config-manager --enable rhel-7-server-rhui-optional-rpms

  elif [[ $SOCA_BASE_OS == "rhel8" ]]; then
    EPEL_URL=$EPEL8_URL
    EPEL_RPM=$EPEL8_RPM
    EPEL_REPO="epel"
  elif [[ $SOCA_BASE_OS == "rhel9" ]]; then
    EPEL_URL=$EPEL9_URL
    EPEL_RPM=$EPEL9_RPM
    EPEL_REPO="epel"
  else
    echo "Unknown Redhat BaseOS: ${SOCA_BASE_OS}   . Update Scheduler bootstrap!"
    exit 1
  fi

  echo "Using EPEL URL/filename/repo name: ${EPEL_URL} / ${EPEL_RPM} / ${EPEL_REPO}"
  curl --silent "$EPEL_URL" -o "$EPEL_RPM"
  yum -y install "$EPEL_RPM"

  # Fixup package lists based on the BaseOS version

  # RHEL7
  if [[ $SOCA_BASE_OS == "rhel7" ]]; then
    # RHEL7
    echo "RHEL7"
  elif [[ $SOCA_BASE_OS == "rhel8" ]]; then
    # RHEL8
    echo "RHEL8"
    REMOVE_PKGS=(
      libselinux-python
      libverto-tevent
      system-lsb
      tcp_wrappers
      redhat-lsb
      dejavu-fonts-common
      postgresql
      postgresql-contrib
      postgresql-server
      compat-openldap
      http-parser
      ntp
    )

    ADD_PKGS=(
      rsyslog
      amazon-efs-utils
      amazon-cloudwatch-agent
      python3-libselinux
      dejavu-fonts-all
      postgresql15
      postgresql15-contrib
      postgresql15-server
      openldap-compat
      authselect-compat
    )
  elif [[ $SOCA_BASE_OS == "rhel9" ]]; then
    # RHEL9
    echo "RHEL9 - Not implemented!"
    exit 1
  fi

elif [[ $SOCA_BASE_OS == "centos7" ]]; then
  # CentOS
  yum -y install epel-release
  yum install -y $(echo ${SYSTEM_PKGS[*]} ${SCHEDULER_PKGS[*]})

elif  [[ $SOCA_BASE_OS == "amazonlinux2" ]] || [[ $SOCA_BASE_OS == "amazonlinux2023" ]]; then
  # AL2 / AL2023 entry point
  yum update --security -y

  if [[ $SOCA_BASE_OS == "amazonlinux2" ]]; then
    amazon-linux-extras install -y epel

  elif [[ $SOCA_BASE_OS == "amazonlinux2023" ]]; then
    # Fixup AL2023 package changes
    REMOVE_PKGS=(
      libselinux-python
      libverto-tevent
      system-lsb
      tcp_wrappers
      redhat-lsb
      dejavu-fonts-common
      postgresql
      postgresql-contrib
      postgresql-server
      compat-openldap
      http-parser
      ntp
    )
    ADD_PKGS=(
      rsyslog
      amazon-efs-utils
      amazon-cloudwatch-agent
      python3-libselinux
      dejavu-fonts-all
      postgresql15
      postgresql15-contrib
      postgresql15-server
      openldap-compat
      authselect-compat
    )
  fi
else
    echo "Unsupported BaseOS: $SOCA_BASE_OS - Please update your SOCA configuration or update bootstrap Scheduler.sh!"
fi

# All BaseOSes return here for remaining installations
for p in "${!SYSTEM_PKGS[@]}"; do
  pkg_name=${SYSTEM_PKGS[p]}
  [[ " ${REMOVE_PKGS[*]} " =~ " ${pkg_name} " ]] && unset 'SYSTEM_PKGS[p]'
done

for p in "${!SCHEDULER_PKGS[@]}"; do
  pkg_name=${SCHEDULER_PKGS[p]}
  [[ " ${REMOVE_PKGS[*]} " =~ " ${pkg_name} " ]] && unset 'SCHEDULER_PKGS[p]'
done

for p in "${!SSSD_PKGS[@]}"; do
  pkg_name=${SSSD_PKGS[p]}
  [[ " ${REMOVE_PKGS[*]} " =~ " ${pkg_name} " ]] && unset 'SSSD_PKGS[p]'
done

for p in "${!OPENLDAP_SERVER_PKGS[@]}"; do
  pkg_name=${OPENLDAP_SERVER_PKGS[p]}
  [[ " ${REMOVE_PKGS[*]} " =~ " ${pkg_name} " ]] && unset 'OPENLDAP_SERVER_PKGS[p]'
done

# Now add new packages.
for i in "${ADD_PKGS[@]}"; do
  SYSTEM_PKGS+=($i)
done

# Now perform the installs on the potentially updated package lists
auto_install ${SYSTEM_PKGS[*]} ${SCHEDULER_PKGS[*]}

auto_install ${OPENLDAP_SERVER_PKGS[*]} ${SSSD_PKGS[*]}


# Mount File system
mkdir -p /apps
mkdir -p /data

if [[ "$FS_DATA_PROVIDER" == "fsx_lustre" ]] || [[ "$FS_APPS_PROVIDER" == "fsx_lustre" ]]; then
    if [[ -z "$(rpm -qa lustre-client)" ]]; then
        # Install FSx for Lustre Client
        if [[ "$SOCA_BASE_OS" == "amazonlinux2023" ]]; then
          # AL2023 does not support Lustre at this time
          echo "FSx for Lustre is not supported on amazonlinux2023 at this time - https://github.com/amazonlinux/amazon-linux-2023/issues/309"
          exit 1
        elif [[ "$SOCA_BASE_OS" == "amazonlinux2" ]]; then
            amazon-linux-extras install -y lustre
        else
            kernel=$(uname -r)
            machine=$(uname -m)
            echo "Found kernel version: $kernel running on: $machine"
            if [[ $kernel == *"3.10.0-957"*$machine ]]; then
                yum -y install https://downloads.whamcloud.com/public/lustre/lustre-2.10.8/el7/client/RPMS/x86_64/kmod-lustre-client-2.10.8-1.el7.x86_64.rpm
                yum -y install https://downloads.whamcloud.com/public/lustre/lustre-2.10.8/el7/client/RPMS/x86_64/lustre-client-2.10.8-1.el7.x86_64.rpm
            elif [[ $kernel == *"3.10.0-1062"*$machine ]]; then
                wget https://fsx-lustre-client-repo-public-keys.s3.amazonaws.com/fsx-rpm-public-key.asc -O /tmp/fsx-rpm-public-key.asc
                rpm --import /tmp/fsx-rpm-public-key.asc
                wget https://fsx-lustre-client-repo.s3.amazonaws.com/el/7/fsx-lustre-client.repo -O /etc/yum.repos.d/aws-fsx.repo
                sed -i 's#7#7.7#' /etc/yum.repos.d/aws-fsx.repo
                yum clean all
                yum install -y kmod-lustre-client lustre-client
            elif [[ $kernel == *"3.10.0-1127"*$machine ]]; then
                wget https://fsx-lustre-client-repo-public-keys.s3.amazonaws.com/fsx-rpm-public-key.asc -O /tmp/fsx-rpm-public-key.asc
                rpm --import /tmp/fsx-rpm-public-key.asc
                wget https://fsx-lustre-client-repo.s3.amazonaws.com/el/7/fsx-lustre-client.repo -O /etc/yum.repos.d/aws-fsx.repo
                sed -i 's#7#7.8#' /etc/yum.repos.d/aws-fsx.repo
                yum clean all
                yum install -y kmod-lustre-client lustre-client
            elif [[ $kernel == *"3.10.0-1160"*$machine ]]; then
                wget https://fsx-lustre-client-repo-public-keys.s3.amazonaws.com/fsx-rpm-public-key.asc -O /tmp/fsx-rpm-public-key.asc
                rpm --import /tmp/fsx-rpm-public-key.asc
                wget https://fsx-lustre-client-repo.s3.amazonaws.com/el/7/fsx-lustre-client.repo -O /etc/yum.repos.d/aws-fsx.repo
                yum clean all
                yum install -y kmod-lustre-client lustre-client
            elif [[ $kernel == *"4.18.0-193"*$machine ]]; then
                # FSX for Lustre on aarch64 is supported only on 4.18.0-193
                wget https://fsx-lustre-client-repo-public-keys.s3.amazonaws.com/fsx-rpm-public-key.asc -O /tmp/fsx-rpm-public-key.asc
                rpm --import /tmp/fsx-rpm-public-key.asc
                wget https://fsx-lustre-client-repo.s3.amazonaws.com/centos/7/fsx-lustre-client.repo -O /etc/yum.repos.d/aws-fsx.repo
                yum clean all
                yum install -y kmod-lustre-client lustre-client
            else
                echo "ERROR: Can't install FSx for Lustre client as kernel version: $kernel isn't matching expected versions: (x86_64: 3.10.0-957, -1062, -1127, -1160, aarch64: 4.18.0-193)!"
            fi
        fi
    fi
fi

AWS=$(command -v aws)
if [[ "$FS_DATA_PROVIDER" == "efs" ]] || [[ "$FS_DATA_PROVIDER" == "fsx_openzfs" ]]; then
  NFS_OPTS_DATA="nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2"
  if [[ "$FS_DATA_PROVIDER" == "fsx_openzfs" ]]; then
    SOURCE_MOUNT="/fsx"
  else
    SOURCE_MOUNT="/"
    NFS_OPTS_DATA+=",noresvport"
  fi
  echo "${FS_DATA}:${SOURCE_MOUNT} /data/ nfs4 ${NFS_OPTS_DATA} 0 0" >> /etc/fstab
elif [[ "$FS_DATA_PROVIDER" == "fsx_lustre" ]]; then
  FSX_ID=$(echo "$FS_DATA" | cut -d. -f1)
  FSX_DATA_MOUNT_NAME=$($AWS fsx describe-file-systems --file-system-ids "$FSX_ID"  --query FileSystems[].LustreConfiguration.MountName --output text)
  echo "$FS_DATA@tcp:/$FSX_DATA_MOUNT_NAME /data lustre defaults,noatime,flock,_netdev 0 0" >> /etc/fstab
fi

if [[ "$FS_APPS_PROVIDER" == "efs" ]] || [[ "$FS_DATA_PROVIDER" == "fsx_openzfs" ]]; then
  NFS_OPTS_APPS="nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2"
  if [[ "$FS_APPS_PROVIDER" == "fsx_openzfs" ]]; then
    SOURCE_MOUNT="/fsx"
  else
    SOURCE_MOUNT="/"
    NFS_OPTS_APPS+=",noresvport"
  fi
  echo "${FS_APPS}:${SOURCE_MOUNT} /apps nfs4 ${NFS_OPTS_APPS} 0 0" >> /etc/fstab
elif [[ "$FS_APPS_PROVIDER" == "fsx_lustre" ]]; then
    FSX_ID=$(echo "$FS_APPS" | cut -d. -f1)
    FSX_APPS_MOUNT_NAME=$($AWS fsx describe-file-systems --file-system-ids "$FSX_ID" --query FileSystems[].LustreConfiguration.MountName --output text)
    echo "$FS_APPS@tcp:/$FSX_APPS_MOUNT_NAME /apps lustre defaults,noatime,flock,_netdev 0 0" >> /etc/fstab
fi


FS_MOUNT=0
mount -a
while [[ $? -ne 0 ]] && [[ $FS_MOUNT -le 5 ]]
do
    SLEEP_TIME=$(( RANDOM % 60 ))
    echo "Failed to mount FS, retrying in $SLEEP_TIME seconds and Loop $FS_MOUNT/5 ..."
    sleep $SLEEP_TIME
    ((FS_MOUNT++))
    mount -a
done

# Exit if folder already exist
if [[ -d "/apps/soca/$SOCA_CONFIGURATION" ]]; then
  echo "/apps/soca/$SOCA_CONFIGURATION folder already exist. To prevent configuration overwrite, we exit the script. Please pick a different SOCA cluster name or delete the folder"
  exit 1
fi

# Install Python if needed
PYTHON_INSTALLED_VERS=$(/apps/soca/"$SOCA_CONFIGURATION"/python/latest/bin/python3 --version | awk {'print $NF'})
if [[ "$PYTHON_INSTALLED_VERS" != "$PYTHON_VERSION" ]]; then
    echo "Python not detected, installing"
    mkdir -p /root/soca/"$SOCA_CONFIGURATION"/python/installer
    cd /root/soca/"$SOCA_CONFIGURATION"/python/installer
    wget "${PYTHON_URL}"
    if [[ $(md5sum "${PYTHON_TGZ}" | awk '{print $1}') != "${PYTHON_HASH}" ]];  then
        echo -e "FATAL ERROR: Checksum for Python failed. File may be compromised." > /etc/motd
        exit 1
    fi
    tar xvf "$PYTHON_TGZ"
    cd Python-"$PYTHON_VERSION"
    ./configure LDFLAGS="-L/usr/lib64/openssl" CPPFLAGS="-I/usr/include/openssl" -enable-loadable-sqlite-extensions --prefix=/apps/soca/"$SOCA_CONFIGURATION"/python/"$PYTHON_VERSION"
    make -j "${NCPU}"
    make install
    ln -sf /apps/soca/"$SOCA_CONFIGURATION"/python/"$PYTHON_VERSION" /apps/soca/"$SOCA_CONFIGURATION"/python/latest
else
    echo "Python already installed and at correct version (${PYTHON_VERSION})."
fi

#
# Install Redis
#
REDIS_CLI=$(command -v redis-cli)
REDIS_INSTALLED_VERS=$(${REDIS_CLI} --version | cut -f2 -d" ")
REDIS_ADMIN_USER="soca-redis-adminuser"
REDIS_ADMIN_PASSWORD=$(openssl rand 8192 | openssl sha256 | awk '{print $2}')
REDIS_RUN_AS_USER="redis"
if [[ "$REDIS_INSTALLED_VERS" != "$REDIS_VERSION" ]]; then
    echo "Redis not detected. Installing version $REDIS_VERSION"
    mkdir -p /root/soca/"$SOCA_CONFIGURATION"/redis/installer
    cd /root/soca/"$SOCA_CONFIGURATION"/redis/installer
    wget "$REDIS_URL"
    if [[ $(md5sum "$REDIS_TGZ" | awk '{print $1}') != "$REDIS_HASH" ]];  then
        echo -e "FATAL ERROR: Checksum for Redis failed. File may be compromised." > /etc/motd
        exit 1
    fi
    tar xvf "$REDIS_TGZ"
    cd redis-"$REDIS_VERSION"
    time make V=1 USE_SYSTEMD=yes BUILD_TLS=yes -j "${NCPU}"
    time make install

    adduser --system --no-create-home --user-group redis
    mkdir -p /var/lib/redis
    chown redis:redis /var/lib/redis
    chmod 770 /var/lib/redis
    mkdir -p /etc/systemd/system
    mkdir -p /etc/redis

    echo "${REDIS_ADMIN_USER}" >/root/RedisAdminUsername.txt
    echo "${REDIS_ADMIN_PASSWORD}" > /root/RedisAdminPassword.txt
    echo "
# SOCA Redis minimal configuration
bind 127.0.0.1 -::1
protected-mode yes
port 6379
tcp-backlog 128
unixsocket /var/lib/redis/redis.sock
timeout 0
tcp-keepalive 300
supervised auto
loglevel notice
syslog-enabled yes
dir /var/lib/redis/
maxclients 256
maxmemory 256mb
lazyfree-lazy-expire yes
rename-command CONFIG \"\"
rename-command SHUTDOWN \"\"
aclfile /etc/redis/users.acl

" > /etc/redis/redis.conf

    # Generate Redis ACL File
    echo "user default resetpass
user ${REDIS_ADMIN_USER} on allcommands allkeys allchannels >${REDIS_ADMIN_PASSWORD}" > /etc/redis/users.acl

    # Secure our ACL file
    chmod 600 /etc/redis/users.acl
    chown ${REDIS_RUN_AS_USER} /etc/redis/users.acl

    # Configure Redis systemd
    echo "
[Unit]
Description=Redis In-Memory Data Store
After=network.target

[Service]
User=${REDIS_RUN_AS_USER}
Group=${REDIS_RUN_AS_USER}
ExecStart=/usr/local/bin/redis-server /etc/redis/redis.conf
ExecStop=/usr/local/bin/redis-cli shutdown
Restart=always

[Install]
WantedBy=multi-user.target
"> /etc/systemd/system/redis.service

    systemctl enable redis
    systemctl start redis
    systemctl status redis
    sleep 5
    echo "Running Redis ping check..."
    time ${REDIS_CLI} --user "$(cat /root/RedisAdminUsername.txt)" --pass "$(cat /root/RedisAdminPassword.txt)" ping

else
    echo "Redis already installed and at correct version (${REDIS_VERSION})."
fi

# Install OpenPBS if needed
cd ~
OPENPBS_INSTALLED_VERS=$(/opt/pbs/bin/qstat --version | awk {'print $NF'})
if [[ "$OPENPBS_INSTALLED_VERS" != "$OPENPBS_VERSION" ]]; then
    echo "OpenPBS Not Detected, Installing OpenPBS ..."
    cd ~
    wget "$OPENPBS_URL"
    if [[ $(md5sum "$OPENPBS_TGZ" | awk '{print $1}') != "${OPENPBS_HASH}" ]];  then
        echo -e "FATAL ERROR: Checksum for OpenPBS failed. File may be compromised." > /etc/motd
        exit 1
    fi
    tar zxvf "$OPENPBS_TGZ"
    cd openpbs-"$OPENPBS_VERSION"
    ./autogen.sh
    ./configure --prefix=/opt/pbs
    make -j ${NCPU}
    make install -j ${NCPU}
    /opt/pbs/libexec/pbs_postinstall
    chmod 4755 /opt/pbs/sbin/pbs_iff /opt/pbs/sbin/pbs_rcp
else
    echo "OpenPBS already installed, and at correct version (${OPENPBS_VERSION})."
    echo "PBS_SERVER=$SERVER_HOSTNAME_ALT
PBS_START_SERVER=1
PBS_START_SCHED=1
PBS_START_COMM=1
PBS_START_MOM=0
PBS_EXEC=/opt/pbs
PBS_HOME=/var/spool/pbs
PBS_CORE_LIMIT=unlimited
PBS_SCP=/usr/bin/scp
" > /etc/pbs.conf
    echo "$clienthost $SERVER_HOSTNAME_ALT" > /var/spool/pbs/mom_priv/config
fi


# Edit path with new scheduler/python locations
echo "export PATH=\"/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/opt/pbs/bin:/opt/pbs/sbin:/opt/pbs/bin:/apps/soca/$SOCA_CONFIGURATION/python/latest/bin\"" >> /etc/environment

# Default AWS Resources
cat <<EOF >>/var/spool/pbs/server_priv/resourcedef
anonymous_metrics type=string
asg_spotfleet_id type=string
availability_zone type=string
base_os type=string
compute_node type=string flag=h
efa_support type=string
error_message type=string
force_ri type=string
fsx_lustre type=string
fsx_lustre_deployment_type type=string
fsx_lustre_per_unit_throughput type=string
fsx_lustre_size type=string
ht_support type=string
instance_profile type=string
instance_ami type=string
instance_id type=string
instance_type type=string
instance_type_used type=string
keep_ebs type=string
placement_group type=string
root_size type=string
scratch_iops type=string
scratch_size type=string
security_groups type=string
spot_allocation_count type=string
spot_allocation_strategy type=string
spot_price type=string
stack_id type=string
subnet_id type=string
system_metrics type=string
EOF

systemctl enable pbs
systemctl start pbs

# Default Server config
/opt/pbs/bin/qmgr -c "create node $SERVER_HOSTNAME_ALT"
/opt/pbs/bin/qmgr -c "set node $SERVER_HOSTNAME_ALT queue = workq"
/opt/pbs/bin/qmgr -c "set server flatuid=true"
/opt/pbs/bin/qmgr -c "set server job_history_enable=1"
/opt/pbs/bin/qmgr -c "set server job_history_duration = 72:00:00"
/opt/pbs/bin/qmgr -c "set server scheduler_iteration = 30"
/opt/pbs/bin/qmgr -c "set server max_concurrent_provision = 5000"

# Default Queue Config
/opt/pbs/bin/qmgr -c "create queue low"
/opt/pbs/bin/qmgr -c "set queue low queue_type = Execution"
/opt/pbs/bin/qmgr -c "set queue low started = True"
/opt/pbs/bin/qmgr -c "set queue low enabled = True"
/opt/pbs/bin/qmgr -c "set queue low default_chunk.compute_node=tbd"
/opt/pbs/bin/qmgr -c "create queue normal"
/opt/pbs/bin/qmgr -c "set queue normal queue_type = Execution"
/opt/pbs/bin/qmgr -c "set queue normal started = True"
/opt/pbs/bin/qmgr -c "set queue normal enabled = True"
/opt/pbs/bin/qmgr -c "set queue normal default_chunk.compute_node=tbd"
/opt/pbs/bin/qmgr -c "create queue high"
/opt/pbs/bin/qmgr -c "set queue high queue_type = Execution"
/opt/pbs/bin/qmgr -c "set queue high started = True"
/opt/pbs/bin/qmgr -c "set queue high enabled = True"
/opt/pbs/bin/qmgr -c "set queue high default_chunk.compute_node=tbd"
/opt/pbs/bin/qmgr -c "create queue job-shared"
/opt/pbs/bin/qmgr -c "set queue job-shared queue_type = Execution"
/opt/pbs/bin/qmgr -c "set queue job-shared started = True"
/opt/pbs/bin/qmgr -c "set queue job-shared enabled = True"
/opt/pbs/bin/qmgr -c "set queue job-shared default_chunk.compute_node=tbd"
/opt/pbs/bin/qmgr -c "create queue test"
/opt/pbs/bin/qmgr -c "set queue test queue_type = Execution"
/opt/pbs/bin/qmgr -c "set queue test started = True"
/opt/pbs/bin/qmgr -c "set queue test enabled = True"
/opt/pbs/bin/qmgr -c "set queue test default_chunk.compute_node=tbd"
/opt/pbs/bin/qmgr -c "create queue alwayson"
/opt/pbs/bin/qmgr -c "set queue alwayson queue_type = Execution"
/opt/pbs/bin/qmgr -c "set queue alwayson started = True"
/opt/pbs/bin/qmgr -c "set queue alwayson enabled = True"
/opt/pbs/bin/qmgr -c "set server default_queue = normal"

# Add compute_node to list of required resource
sed -i 's/resources: "ncpus, mem, arch, host, vnode, aoe, eoe"/resources: "ncpus, mem, arch, host, vnode, aoe, eoe, compute_node"/g' /var/spool/pbs/sched_priv/sched_config

# Configure OpenLDAP is auth provider is set to OpenLDAP
if [[ "$SOCA_AUTH_PROVIDER" == "openldap" ]]; then
  systemctl enable slapd
  systemctl start slapd
  ADMIN_LDAP_PASSWORD=$(slappasswd -g)
  ADMIN_LDAP_PASSWORD_ENCRYPTED=$(/sbin/slappasswd -s "$ADMIN_LDAP_PASSWORD" -h "{SSHA}")
  echo -n "admin" > /root/OpenLdapAdminUsername.txt
  echo -n "$ADMIN_LDAP_PASSWORD" > /root/OpenLdapAdminPassword.txt
  chmod 600 /root/OpenLdapAdminPassword.txt
  echo "URI ldap://$SERVER_HOSTNAME" >> /etc/openldap/ldap.conf
  echo "BASE $SOCA_LDAP_BASE" >> /etc/openldap/ldap.conf

  # Generate 10y certificate for ldaps
  openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
      -subj "/C=US/ST=California/L=Sunnyvale/O=Aligo/CN=$SERVER_HOSTNAME" \
      -keyout /etc/openldap/certs/soca.key -out /etc/openldap/certs/soca.crt

  chown ldap:ldap /etc/openldap/certs/soca.key /etc/openldap/certs/soca.crt
  chmod 600 /etc/openldap/certs/soca.key /etc/openldap/certs/soca.crt

  # Create OpenLDAP config
  if [[ $SOCA_BASE_OS == "amazonlinux2023" ]]; then
    OPEN_LDAP_CONFIG_KEY="{2}mdb"
  else
    OPEN_LDAP_CONFIG_KEY="{2}hdb"
  fi

  echo -e "
dn: olcDatabase=${OPEN_LDAP_CONFIG_KEY},cn=config
changetype: modify
replace: olcSuffix
olcSuffix: $SOCA_LDAP_BASE

dn: olcDatabase=${OPEN_LDAP_CONFIG_KEY},cn=config
changetype: modify
replace: olcRootDN
olcRootDN: cn=admin,$SOCA_LDAP_BASE

dn: olcDatabase=${OPEN_LDAP_CONFIG_KEY},cn=config
changetype: modify
replace: olcRootPW
olcRootPW: $ADMIN_LDAP_PASSWORD_ENCRYPTED" > db.ldif

  echo -e "
dn: cn=config
changetype: modify
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/openldap/certs/soca.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/openldap/certs/soca.key" > update_ssl_cert.ldif

  echo -e "
dn: olcDatabase=${OPEN_LDAP_CONFIG_KEY},cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by group.exact="ou=admins,$SOCA_LDAP_BASE" write by * none
-
add: olcAccess
olcAccess: {1}to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" write by dn.base="ou=admins,$SOCA_LDAP_BASE" write by * read" > change_user_password.ldif

  echo -e "
dn: cn=sudo,cn=schema,cn=config
objectClass: olcSchemaConfig
cn: sudo
olcAttributeTypes: ( 1.3.6.1.4.1.15953.9.1.1 NAME 'sudoUser' DESC 'User(s) who may  run sudo' EQUALITY caseExactIA5Match SUBSTR caseExactIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.15953.9.1.2 NAME 'sudoHost' DESC 'Host(s) who may run sudo' EQUALITY caseExactIA5Match SUBSTR caseExactIA5SubstringsMatch SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.15953.9.1.3 NAME 'sudoCommand' DESC 'Command(s) to be executed by sudo' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.15953.9.1.4 NAME 'sudoRunAs' DESC 'User(s) impersonated by sudo (deprecated)' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.15953.9.1.5 NAME 'sudoOption' DESC 'Options(s) followed by sudo' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.15953.9.1.6 NAME 'sudoRunAsUser' DESC 'User(s) impersonated by sudo' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcAttributeTypes: ( 1.3.6.1.4.1.15953.9.1.7 NAME 'sudoRunAsGroup' DESC 'Group(s) impersonated by sudo' EQUALITY caseExactIA5Match SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 )
olcObjectClasses: ( 1.3.6.1.4.1.15953.9.2.1 NAME 'sudoRole' SUP top STRUCTURAL DESC 'Sudoer Entries' MUST ( cn ) MAY ( sudoUser $ sudoHost $ sudoCommand $ sudoRunAs $ sudoRunAsUser $ sudoRunAsGroup $ sudoOption $ description ) )" > sudoers.ldif

  /bin/ldapmodify -Y EXTERNAL -H ldapi:/// -f db.ldif
  /bin/ldapmodify -Y EXTERNAL -H ldapi:/// -f update_ssl_cert.ldif
  /bin/ldapmodify -Y EXTERNAL -H ldapi:/// -f change_user_password.ldif
  /bin/ldapadd -Y EXTERNAL -H ldapi:/// -f sudoers.ldif
  /bin/ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif
  /bin/ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/nis.ldif
  /bin/ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/inetorgperson.ldif

  echo -e "
dn: $SOCA_LDAP_BASE
dc: soca
objectClass: top
objectClass: domain

dn: cn=admin,$SOCA_LDAP_BASE
objectClass: organizationalRole
cn: admin
description: LDAP Manager

dn: ou=People,$SOCA_LDAP_BASE
objectClass: organizationalUnit
ou: People

dn: ou=Group,$SOCA_LDAP_BASE
objectClass: organizationalUnit
ou: Group

dn: ou=Sudoers,$SOCA_LDAP_BASE
objectClass: organizationalUnit

dn: ou=admins,$SOCA_LDAP_BASE
objectClass: organizationalUnit
ou: Group" > base.ldif

  /bin/ldapadd -x -W -y /root/OpenLdapAdminPassword.txt -D "cn=admin,$SOCA_LDAP_BASE" -f base.ldif

  authconfig \
      --enablesssd \
      --enablesssdauth \
      --enableldap \
      --enableldapauth \
      --ldapserver="ldap://$SERVER_HOSTNAME" \
      --ldapbasedn="$SOCA_LDAP_BASE" \
      --enablelocauthorize \
      --enablemkhomedir \
      --enablecachecreds \
      --updateall

  echo "sudoers: files sss" >> /etc/nsswitch.conf

  ## Configure SSSD
  echo -e "[domain/default]
enumerate = True
autofs_provider = ldap
cache_credentials = True
ldap_search_base = $SOCA_LDAP_BASE
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
sudo_provider = ldap
ldap_tls_cacert = /etc/openldap/certs/soca.crt
ldap_sudo_search_base = ou=Sudoers,$SOCA_LDAP_BASE
ldap_uri = ldap://$SERVER_HOSTNAME
ldap_id_use_start_tls = True
use_fully_qualified_names = False
ldap_tls_cacertdir = /etc/openldap/certs/
ldap_sudo_full_refresh_interval=86400
ldap_sudo_smart_refresh_interval=3600

[sssd]
services = nss, pam, autofs, sudo
full_name_format = %2\$s\%1\$s
domains = default

[nss]
homedir_substring = /data/home

[pam]

[sudo]


[autofs]

[ssh]

[pac]

[ifp]

[secrets]" > /etc/sssd/sssd.conf
  chmod 600 /etc/sssd/sssd.conf

  systemctl enable sssd
  systemctl restart sssd
fi

# Disable SELINUX
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config

# Disable StrictHostKeyChecking
echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config
echo "UserKnownHostsFile /dev/null" >> /etc/ssh/ssh_config

# Install Python required libraries
# Source environment to reload path for Python3
/apps/soca/"$SOCA_CONFIGURATION"/python/"$PYTHON_VERSION"/bin/pip3 install -r /root/requirements.txt

# Configure Chrony
yum remove -y ntp
mv /etc/chrony.conf  /etc/chrony.conf.original
echo -e """
# use the local instance NTP service, if available
server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4

# Use public servers from the pool.ntp.org project.
# Please consider joining the pool (https://www.pool.ntp.org/join.html).
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
echo -e "
* hard memlock unlimited
* soft memlock unlimited
" >> /etc/security/limits.conf

# Reboot to ensure SELINUX is disabled
# Note: Upon reboot, SchedulerPostReboot.sh script will be executed and will finalize scheduler configuration
reboot
