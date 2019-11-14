#!/bin/bash -xe

source /etc/environment
source /root/config.cfg

if [ $# -lt 2 ]
  then
    exit 1
fi

EFS_DATA=$1
EFS_APPS=$2
SERVER_IP=$(hostname -I)
SERVER_HOSTNAME=$(hostname)
SERVER_HOSTNAME_ALT=$(echo $SERVER_HOSTNAME | cut -d. -f1)
echo $SERVER_IP $SERVER_HOSTNAME $SERVER_HOSTNAME_ALT >> /etc/hosts

if [[ $SOCA_BASE_OS = "rhel7" ]]
then
    yum install -y $(echo ${SYSTEM_PKGS[*]}) --enablerepo rhui-REGION-rhel-server-optional
    yum install -y $(echo ${SCHEDULER_PKGS[*]}) --enablerepo rhui-REGION-rhel-server-optional
else
    yum install -y $(echo ${SYSTEM_PKGS[*]})
    yum install -y $(echo ${SCHEDULER_PKGS[*]})
fi

yum install -y $(echo ${OPENLDAP_SERVER_PKGS[*]})
yum install -y $(echo ${SSSD_PKGS[*]})

# Mount EFS
mkdir /apps
mkdir /data
echo "$EFS_DATA:/ /data/ nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2 0 0" >> /etc/fstab
echo "$EFS_APPS:/ /apps nfs4 nfsvers=4.1,rsize=1048576,wsize=1048576,hard,timeo=600,retrans=2 0 0" >> /etc/fstab
mount -a

# Install Python
mkdir -p /apps/python/installer
cd /apps/python/installer
wget $PYTHON_URL
if [[ $(md5sum $PYTHON_TGZ | awk '{print $1}') != $PYTHON_HASH ]];  then
    echo -e "FATAL ERROR: Checksum for Python failed. File may be compromised." > /etc/motd
    exit 1
fi
tar xvf $PYTHON_TGZ
cd Python-$PYTHON_VERSION
./configure LDFLAGS="-L/usr/lib64/openssl" CPPFLAGS="-I/usr/include/openssl" --prefix=/apps/python/$PYTHON_VERSION
make
make install
ln -sf /apps/python/$PYTHON_VERSION /apps/python/latest
# Install PBSPro
cd ~
wget $PBSPRO_URL
if [[ $(md5sum $PBSPRO_TGZ | awk '{print $1}') != $PBSPRO_HASH ]];  then
    echo -e "FATAL ERROR: Checksum for PBSPro failed. File may be compromised." > /etc/motd
    exit 1
fi
tar zxvf $PBSPRO_TGZ
cd pbspro-$PBSPRO_VERSION
./autogen.sh
./configure --prefix=/opt/pbs
make
make install
/opt/pbs/libexec/pbs_postinstall
chmod 4755 /opt/pbs/sbin/pbs_iff /opt/pbs/sbin/pbs_rcp

# Edit path with new scheduler/python locations
echo "export PATH=\"/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/opt/pbs/bin:/opt/pbs/sbin:/opt/pbs/bin:/apps/python/latest/bin\" " >> /etc/environment

# Default AWS Resources
cat <<EOF >>/var/spool/pbs/server_priv/resourcedef
compute_node type=string flag=h
instance_type_used type=string
instance_type type=string
stack_id type=string
availability_zone type=string
subnet_id type=string
instance_ami type=string
scratch_size type=string
scratch_iops type=string
root_size type=string
placement_group type=string
spot_price type=string
efa_support type=string
ht_support type=string
base_os type=string
fsx_lustre_bucket type=string
fsx_lustre_size type=string
fsx_lustre_dns type=string
EOF

systemctl enable pbs
systemctl start pbs

# Default Server config
/opt/pbs/bin/qmgr -c "create node $SERVER_HOSTNAME_ALT"
/opt/pbs/bin/qmgr -c "set node $SERVER_HOSTNAME_ALT queue = workq"
/opt/pbs/bin/qmgr -c "set server flatuid=true"
/opt/pbs/bin/qmgr -c "set server job_history_enable=1"
/opt/pbs/bin/qmgr -c "set server job_history_duration = 00:01:00"
/opt/pbs/bin/qmgr -c "set server scheduler_iteration = 30"

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
/opt/pbs/bin/qmgr -c "create queue alwayson"
/opt/pbs/bin/qmgr -c "set queue alwayson queue_type = Execution"
/opt/pbs/bin/qmgr -c "set queue alwayson started = True"
/opt/pbs/bin/qmgr -c "set queue alwayson enabled = True"
/opt/pbs/bin/qmgr -c  "set server default_queue = normal"

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
/apps/python/$PYTHON_VERSION/bin/pip3 install awscli==1.16.151 \
      boto3==1.9.141 \
      pytz==2019.1 \
      prettytable==0.7.2 \
      python-ldap==3.2.0 \
      cryptography==2.6.1 \
      requests-aws4auth==0.9 \
      elasticsearch==6.3.1 \
      requests==2.6.0 \
      flask==1.0.3 \
      gunicorn==19.9.0 \
      pyopenssl==19.0.0 \
      flask_wtf==0.14.2

# Install SSM
yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
systemctl enable amazon-ssm-agent
systemctl restart amazon-ssm-agent

# Reboot to ensure SELINUX is disabled
# Note: Upon reboot, SchedulerPostReboot.sh script will be executed and will finalize scheduler configuration
reboot
