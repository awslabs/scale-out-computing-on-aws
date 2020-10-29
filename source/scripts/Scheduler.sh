#!/bin/bash -xe

source /etc/environment
source /root/config.cfg

if [ $# -lt 2 ]
  then
    exit 1
fi

# Install SSM
yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
systemctl enable amazon-ssm-agent
systemctl restart amazon-ssm-agent


mkdir -p /apps/soca/$SOCA_CONFIGURATION
EFS_DATA=$1
EFS_APPS=$2
SERVER_IP=$(hostname -I)
SERVER_HOSTNAME=$(hostname)
SERVER_HOSTNAME_ALT=$(echo $SERVER_HOSTNAME | cut -d. -f1)
echo $SERVER_IP $SERVER_HOSTNAME $SERVER_HOSTNAME_ALT >> /etc/hosts

if [[ $SOCA_BASE_OS == "rhel7" ]]
then
    yum install -y $(echo ${SYSTEM_PKGS[*]} ${SCHEDULER_PKGS[*]}) --enablerepo rhui-REGION-rhel-server-optional
else
    yum install -y $(echo ${SYSTEM_PKGS[*]} ${SCHEDULER_PKGS[*]})
fi

yum install -y $(echo ${OPENLDAP_SERVER_PKGS[*]} ${SSSD_PKGS[*]})

# Mount EFS
mkdir /apps
mkdir /data
echo "$EFS_DATA:/ /data/ nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport 0 0" >> /etc/fstab
echo "$EFS_APPS:/ /apps nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2,noresvport 0 0" >> /etc/fstab
mount -a

# Install Python if needed
PYTHON_INSTALLED_VERS=$(/apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 --version | awk {'print $NF'})
if [[ "$PYTHON_INSTALLED_VERS" != "$PYTHON_VERSION" ]]
then
    echo "Python not detected, installing"
    mkdir -p /apps/soca/$SOCA_CONFIGURATION/python/installer
    cd /apps/soca/$SOCA_CONFIGURATION/python/installer
    wget $PYTHON_URL
    if [[ $(md5sum $PYTHON_TGZ | awk '{print $1}') != $PYTHON_HASH ]];  then
        echo -e "FATAL ERROR: Checksum for Python failed. File may be compromised." > /etc/motd
        exit 1
    fi
    tar xvf $PYTHON_TGZ
    cd Python-$PYTHON_VERSION
    ./configure LDFLAGS="-L/usr/lib64/openssl" CPPFLAGS="-I/usr/include/openssl" -enable-loadable-sqlite-extensions --prefix=/apps/soca/$SOCA_CONFIGURATION/python/$PYTHON_VERSION
    make
    make install
    ln -sf /apps/soca/$SOCA_CONFIGURATION/python/$PYTHON_VERSION /apps/soca/$SOCA_CONFIGURATION/python/latest
else
    echo "Python already installed and at correct version."
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
else
    echo "OpenPBS already installed, and at correct version."
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
instance_ami type=string
instance_id type=string
instance_type type=string
instance_type_used type=string
keep_ebs type=string
placement_group type=string
root_size type=string
scratch_iops type=string
scratch_size type=string
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
/opt/pbs/bin/qmgr -c "set server job_history_duration = 01:00:00"
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
/opt/pbs/bin/qmgr -c "create queue desktop"
/opt/pbs/bin/qmgr -c "set queue desktop queue_type = Execution"
/opt/pbs/bin/qmgr -c "set queue desktop started = True"
/opt/pbs/bin/qmgr -c "set queue desktop enabled = True"
/opt/pbs/bin/qmgr -c "set queue desktop default_chunk.compute_node=tbd"
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

# Configure Ldap
systemctl enable slapd
systemctl start slapd

MASTER_LDAP_PASSWORD=$(slappasswd -g)
MASTER_LDAP_PASSWORD_ENCRYPTED=$(/sbin/slappasswd -s $MASTER_LDAP_PASSWORD -h "{SSHA}")
echo -n "admin" > /root/OpenLdapAdminUsername.txt
echo -n $MASTER_LDAP_PASSWORD > /root/OpenLdapAdminPassword.txt
chmod 600 /root/OpenLdapAdminPassword.txt
echo "URI ldap://$SERVER_HOSTNAME" >> /etc/openldap/ldap.conf
echo "BASE $LDAP_BASE" >> /etc/openldap/ldap.conf

# Generate 10y certificate for ldaps
openssl req -new -newkey rsa:2048 -days 3650 -nodes -x509 \
    -subj "/C=US/ST=California/L=Sunnyvale/O=Aligo/CN=$SERVER_HOSTNAME" \
    -keyout /etc/openldap/certs/soca.key -out /etc/openldap/certs/soca.crt

chown ldap:ldap /etc/openldap/certs/soca.key /etc/openldap/certs/soca.crt
chmod 600 /etc/openldap/certs/soca.key /etc/openldap/certs/soca.crt

echo -e "
dn: olcDatabase={2}hdb,cn=config
changetype: modify
replace: olcSuffix
olcSuffix: $LDAP_BASE

dn: olcDatabase={2}hdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: cn=admin,$LDAP_BASE

dn: olcDatabase={2}hdb,cn=config
changetype: modify
replace: olcRootPW
olcRootPW: $MASTER_LDAP_PASSWORD_ENCRYPTED
" > db.ldif

echo -e "
dn: cn=config
changetype: modify
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/openldap/certs/soca.crt
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/openldap/certs/soca.key
" > update_ssl_cert.ldif

echo -e "
dn: olcDatabase={2}hdb,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to attrs=userPassword by self write by anonymous auth by group.exact="ou=admins,$LDAP_BASE" write by * none
-
add: olcAccess
olcAccess: {1}to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth" write by dn.base="ou=admins,$LDAP_BASE" write by * read
" > change_user_password.ldif

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
olcObjectClasses: ( 1.3.6.1.4.1.15953.9.2.1 NAME 'sudoRole' SUP top STRUCTURAL DESC 'Sudoer Entries' MUST ( cn ) MAY ( sudoUser $ sudoHost $ sudoCommand $ sudoRunAs $ sudoRunAsUser $ sudoRunAsGroup $ sudoOption $ description ) )
" > sudoers.ldif

/bin/ldapmodify -Y EXTERNAL -H ldapi:/// -f db.ldif
/bin/ldapmodify -Y EXTERNAL -H ldapi:/// -f update_ssl_cert.ldif
/bin/ldapmodify -Y EXTERNAL -H ldapi:/// -f change_user_password.ldif
/bin/ldapadd -Y EXTERNAL -H ldapi:/// -f sudoers.ldif
/bin/ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/cosine.ldif
/bin/ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/nis.ldif
/bin/ldapadd -Y EXTERNAL -H ldapi:/// -f /etc/openldap/schema/inetorgperson.ldif

echo -e "
dn: $LDAP_BASE
dc: soca
objectClass: top
objectClass: domain

dn: cn=admin,$LDAP_BASE
objectClass: organizationalRole
cn: admin
description: LDAP Manager

dn: ou=People,$LDAP_BASE
objectClass: organizationalUnit
ou: People

dn: ou=Group,$LDAP_BASE
objectClass: organizationalUnit
ou: Group

dn: ou=Sudoers,$LDAP_BASE
objectClass: organizationalUnit

dn: ou=admins,$LDAP_BASE
objectClass: organizationalUnit
ou: Group
" > base.ldif

/bin/ldapadd -x -W -y /root/OpenLdapAdminPassword.txt -D "cn=admin,$LDAP_BASE" -f base.ldif

authconfig \
    --enablesssd \
    --enablesssdauth \
    --enableldap \
    --enableldapauth \
    --ldapserver="ldap://$SERVER_HOSTNAME" \
    --ldapbasedn="$LDAP_BASE" \
    --enablelocauthorize \
    --enablemkhomedir \
    --enablecachecreds \
    --updateall

echo "sudoers: files sss" >> /etc/nsswitch.conf

# Configure SSSD
echo -e "[domain/default]
enumerate = True
autofs_provider = ldap
cache_credentials = True
ldap_search_base = $LDAP_BASE
id_provider = ldap
auth_provider = ldap
chpass_provider = ldap
sudo_provider = ldap
ldap_tls_cacert = /etc/openldap/certs/soca.crt
ldap_sudo_search_base = ou=Sudoers,$LDAP_BASE
ldap_uri = ldap://$SERVER_HOSTNAME
ldap_id_use_start_tls = True
use_fully_qualified_names = False
ldap_tls_cacertdir = /etc/openldap/certs/

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

# Disable SELINUX
sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config

# Disable StrictHostKeyChecking
echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config
echo "UserKnownHostsFile /dev/null" >> /etc/ssh/ssh_config

# Install Python required libraries
# Source environment to reload path for Python3
/apps/soca/$SOCA_CONFIGURATION/python/$PYTHON_VERSION/bin/pip3 install -r /root/requirements.txt

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

# Reboot to ensure SELINUX is disabled
# Note: Upon reboot, SchedulerPostReboot.sh script will be executed and will finalize scheduler configuration
reboot
