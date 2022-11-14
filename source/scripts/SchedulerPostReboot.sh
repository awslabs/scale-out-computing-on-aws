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

set -ex

source /etc/environment
source /root/config.cfg
AWS=$(command -v aws)

function get_secret {
    # When using custom AMI, the scheduler is fully operational even before SecretManager is ready.
    # LDAP_Manager has a dependency on SecretManager so we have to wait a little bit (or create the user manually once secretmanager is available)
    MAX_ATTEMPT=10
    CURRENT_ATTEMPT=0
    SLEEP_INTERVAL=180
    command="$AWS secretsmanager get-secret-value --secret-id $SOCA_CONFIGURATION --query SecretString --output text"
    while ! secret=$($command); do
        ((CURRENT_ATTEMPT=CURRENT_ATTEMPT+1))
        if [[ $CURRENT_ATTEMPT -ge $MAX_ATTEMPT ]]; then
            echo "error: Timed out waiting for secret from secrets manager"
            return 1
        fi
        echo "Secret Manager is not ready yet ... Waiting $SLEEP_INTERVAL s... Loop count is: $CURRENT_ATTEMPT/$MAX_ATTEMPT"
        sleep $SLEEP_INTERVAL
    done
    echo "Secret Manager is ready"
    echo $secret
}

# First flush the current crontab to prevent this script to run on the next reboot
crontab -r

# Retrieve SOCA configuration under soca.tar.gz and extract it on /apps/
$AWS s3 cp s3://$SOCA_INSTALL_BUCKET/$SOCA_INSTALL_BUCKET_FOLDER/soca.tar.gz /root
mkdir -p /apps/soca/$SOCA_CONFIGURATION
tar -xvf /root/soca.tar.gz -C /apps/soca/$SOCA_CONFIGURATION --no-same-owner
cp /root/config.cfg /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/config.cfg
mkdir -p /apps/soca/$SOCA_CONFIGURATION/cluster_manager/logs
chmod +x /apps/soca/$SOCA_CONFIGURATION/cluster_manager/socaqstat.py

# Download static pricing list for China regions
wget https://pricing.cn-north-1.amazonaws.com.cn/offers/v1.0/cn/AmazonEC2/current/index.json -O /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/pricing_index.json
cat <<EOT >> /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/download_china_pricing_index.sh
#!/bin/bash
wget https://pricing.cn-north-1.amazonaws.com.cn/offers/v1.0/cn/AmazonEC2/current/index.json -O /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/pricing_index.json
EOT
chmod +x /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/download_china_pricing_index.sh

# Generate default queue_mapping file based on default AMI chosen by customer
cat <<EOT >> /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml
# This manage automatic provisioning for your queues
# These are default values. Users can override them at job submission
# https://awslabs.github.io/scale-out-computing-on-aws/tutorials/create-your-own-queue/
queue_type:
  compute:
    queues: ["high", "normal", "low"]
    # Uncomment to limit the number of concurrent running jobs
    # max_running_jobs: 50
    # Uncomment to limit the number of concurrent running instances
    # max_provisioned_instances: 30
    # Queue ACLs:  https://awslabs.github.io/scale-out-computing-on-aws/tutorials/manage-queue-acls/
    allowed_users: [] # empty list = all users can submit job
    excluded_users: [] # empty list = no restriction, ["*"] = only allowed_users can submit job
    # Queue mode (can be either fifo or fairshare)
    # queue_mode: "fifo"
    # Instance types restrictions: https://awslabs.github.io/scale-out-computing-on-aws/security/manage-queue-instance-types/
    allowed_instance_types: [] # Empty list, all EC2 instances allowed. You can restrict by instance type (Eg: ["c5.4xlarge"]) or instance family (eg: ["c5"])
    excluded_instance_types: [] # Empty list, no EC2 instance types prohibited.  You can restrict by instance type (Eg: ["c5.4xlarge"]) or instance family (eg: ["c5"])
    # List of parameters user can not override: https://awslabs.github.io/scale-out-computing-on-aws/security/manage-queue-restricted-parameters/
    restricted_parameters: []
    # Scaling mode (can be either single_job, or multiple_jobs): single_job runs a single job per EC2 instance, multiple_jobs allows running multiple jobs on the same EC2 instance
    scaling_mode: "single_job" # Allowed values: single_job, multiple_jobs
    # List of additional security groups / IAM instance profile that can be used https://awslabs.github.io/scale-out-computing-on-aws/security/use-custom-sgs-roles/
    allowed_security_group_ids: []
    allowed_instance_profiles: []
    # Default job parameters: https://awslabs.github.io/scale-out-computing-on-aws/tutorials/integration-ec2-job-parameters/
    instance_ami: "$SOCA_INSTALL_AMI" # Required
    instance_type: "c5.large" # Required
    ht_support: "false"
    root_size: "10"
    #scratch_size: "100"
    #scratch_iops: "3600"
    #efa_support: "false"
    # .. Refer to the doc for more supported parameters
  job-shared:
    queues: ["job-shared"]
    # Uncomment to limit the number of concurrent running jobs
    # max_running_jobs: 50
    # Queue ACLs:  https://awslabs.github.io/scale-out-computing-on-aws/tutorials/manage-queue-acls/
    allowed_users: [] # empty list = all users can submit job
    excluded_users: [] # empty list = no restriction, ["*"] = only allowed_users can submit job
    # Queue mode (can be either fifo or fairshare)
    # queue_mode: "fifo"
    # Instance types restrictions: https://awslabs.github.io/scale-out-computing-on-aws/security/manage-queue-instance-types/
    allowed_instance_types: [] # Empty list, all EC2 instances allowed. You can restrict by instance type (Eg: ["c5.4xlarge"]) or instance family (eg: ["c5"])
    excluded_instance_types: [] # Empty list, no EC2 instance types prohibited.  You can restrict by instance type (Eg: ["c5.4xlarge"]) or instance family (eg: ["c5"])
    # List of parameters user can not override: https://awslabs.github.io/scale-out-computing-on-aws/security/manage-queue-restricted-parameters/
    restricted_parameters: []
    # Default job parameters: https://awslabs.github.io/scale-out-computing-on-aws/tutorials/integration-ec2-job-parameters/
    # Scaling mode (can be either single_job, or multiple_jobs): single_job runs a single job per EC2 instance, multiple_jobs allows running multiple jobs on the same EC2 instance
    scaling_mode: "multiple_jobs" # Allowed values: single_job, multiple_jobs
    instance_ami: "$SOCA_INSTALL_AMI" # Required
    instance_type: "c5.large+c5.xlarge+c5.2xlarge" # Required
    # Terminate when idle: The value specifies the default duration (in mins) where the compute instances would be terminated after being detected as free (no jobs running) for N consecutive minutes
    terminate_when_idle: 3 # Required when scaling_mode is set to multiple_jobs
    ht_support: "true" 
    placement_group: "false"
    root_size: "10"
    # .. Refer to the doc for more supported parameters
  test:
    queues: ["test"]
    # Uncomment to limit the number of concurrent running jobs
    # max_running_jobs: 50
    # Uncomment to limit the number of concurrent running instances
    # max_provisioned_instances: 30
    # Queue ACLs:  https://awslabs.github.io/scale-out-computing-on-aws/tutorials/manage-queue-acls/
    allowed_users: [] # empty list = all users can submit job
    excluded_users: [] # empty list = no restriction, ["*"] = only allowed_users can submit job
    # Queue mode (can be either fifo or fairshare)
    # queue_mode: "fifo"
    # Instance types restrictions: https://awslabs.github.io/scale-out-computing-on-aws/security/manage-queue-instance-types/
    allowed_instance_types: [] # Empty list, all EC2 instances allowed. You can restrict by instance type (Eg: ["c5.4xlarge"]) or instance family (eg: ["c5"])
    excluded_instance_types: [] # Empty list, no EC2 instance types prohibited.  You can restrict by instance type (Eg: ["c5.4xlarge"]) or instance family (eg: ["c5"])
    # List of parameters user can not override: https://awslabs.github.io/scale-out-computing-on-aws/security/manage-queue-restricted-parameters/
    restricted_parameters: []
    # List of additional security groups / IAM instance profile that can be used https://awslabs.github.io/scale-out-computing-on-aws/security/use-custom-sgs-roles/
    allowed_security_group_ids: []
    allowed_instance_profiles: []
    # Default job parameters: https://awslabs.github.io/scale-out-computing-on-aws/tutorials/integration-ec2-job-parameters/
    instance_ami: "$SOCA_INSTALL_AMI"  # Required
    instance_type: "c5.large"  # Required
    ht_support: "false"
    root_size: "10"
    #spot_price: "auto"
    #placement_group: "false"
    # .. Refer to the doc for more supported parameters
EOT

# Generate 10 years internal SSL certificate for Soca Web UI
cd /apps/soca/$SOCA_CONFIGURATION/cluster_web_ui
openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 \
    -subj "/C=US/ST=California/L=Sunnyvale/CN=internal.soca.webui.cert" \
    -keyout cert.key -out cert.crt

# Wait for PBS to restart
sleep 60

## Update PBS Hooks with the current script location
sed -i "s/%SOCA_CONFIGURATION/$SOCA_CONFIGURATION/g" /apps/soca/$SOCA_CONFIGURATION/cluster_hooks/queuejob/check_queue_acls.py
sed -i "s/%SOCA_CONFIGURATION/$SOCA_CONFIGURATION/g" /apps/soca/$SOCA_CONFIGURATION/cluster_hooks/queuejob/check_queue_instance_types.py
sed -i "s/%SOCA_CONFIGURATION/$SOCA_CONFIGURATION/g" /apps/soca/$SOCA_CONFIGURATION/cluster_hooks/queuejob/check_queue_custom_sgs_roles.py
sed -i "s/%SOCA_CONFIGURATION/$SOCA_CONFIGURATION/g" /apps/soca/$SOCA_CONFIGURATION/cluster_hooks/queuejob/check_queue_restricted_parameters.py
sed -i "s/%SOCA_CONFIGURATION/$SOCA_CONFIGURATION/g" /apps/soca/$SOCA_CONFIGURATION/cluster_hooks/queuejob/check_licenses_mapping.py
sed -i "s/%SOCA_CONFIGURATION/$SOCA_CONFIGURATION/g" /apps/soca/$SOCA_CONFIGURATION/cluster_hooks/queuejob/check_project_budget.py
sed -i "s/%SOCA_CONFIGURATION/$SOCA_CONFIGURATION/g" /apps/soca/$SOCA_CONFIGURATION/cluster_hooks/job_notifications.py

# Create Default PBS hooks
qmgr -c "create hook check_queue_acls event=queuejob"
qmgr -c "import hook check_queue_acls application/x-python default /apps/soca/$SOCA_CONFIGURATION/cluster_hooks/queuejob/check_queue_acls.py"
qmgr -c "create hook check_queue_instance_types event=queuejob"
qmgr -c "import hook check_queue_instance_types application/x-python default /apps/soca/$SOCA_CONFIGURATION/cluster_hooks/queuejob/check_queue_instance_types.py"
qmgr -c "create hook check_queue_restricted_parameters event=queuejob"
qmgr -c "import hook check_queue_restricted_parameters application/x-python default /apps/soca/$SOCA_CONFIGURATION/cluster_hooks/queuejob/check_queue_restricted_parameters.py"
qmgr -c "create hook check_queue_custom_sgs_roles event=queuejob"
qmgr -c "import hook check_queue_custom_sgs_roles application/x-python default /apps/soca/$SOCA_CONFIGURATION/cluster_hooks/queuejob/check_queue_custom_sgs_roles.py"
qmgr -c "create hook check_licenses_mapping event=queuejob"
qmgr -c "import hook check_licenses_mapping application/x-python default /apps/soca/$SOCA_CONFIGURATION/cluster_hooks/queuejob/check_licenses_mapping.py"


# Reload config
systemctl restart pbs

# Create crontabs
echo "
## Cluster Analytics
* * * * * source /etc/environment; /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/cluster_nodes_tracking.py >> /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/cluster_nodes_tracking.log 2>&1
@hourly source /etc/environment; /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/job_tracking.py >> /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/job_tracking.log 2>&1
*/10 * * * * source /etc/environment; /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/desktop_hosts_tracking.py >> /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/desktop_hosts_tracking.log 2>&1
@daily /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/download_china_pricing_index.sh > /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/download_china_pricing_index.log 2>&1

## Cluster Log Management
@daily  source /etc/environment; /bin/bash /apps/soca/$SOCA_CONFIGURATION/cluster_logs_management/send_logs_s3.sh >>/apps/soca/$SOCA_CONFIGURATION/cluster_logs_management/send_logs_s3.log 2>&1

## Cluster Management
* * * * * source /etc/environment;  /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3  /apps/soca/$SOCA_CONFIGURATION/cluster_manager/nodes_manager.py >> /apps/soca/$SOCA_CONFIGURATION/cluster_manager/nodes_manager.py.log 2>&1

## Cluster Web UI
### Restart UI at reboot
@reboot /apps/soca/$SOCA_CONFIGURATION/cluster_web_ui/socawebui.sh start

## Automatic Host Provisioning
* * * * * source /etc/environment;  /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 /apps/soca/$SOCA_CONFIGURATION/cluster_manager/dispatcher.py -c /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml -t compute
* * * * * source /etc/environment;  /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 /apps/soca/$SOCA_CONFIGURATION/cluster_manager/dispatcher.py -c /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml -t job-shared
* * * * * source /etc/environment;  /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 /apps/soca/$SOCA_CONFIGURATION/cluster_manager/dispatcher.py -c /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml -t test

# Add/Remove DCV hosts and configure ALB
*/3 * * * * source /etc/environment; /apps/soca/$SOCA_CONFIGURATION/python/latest/bin/python3 /apps/soca/$SOCA_CONFIGURATION/cluster_manager/dcv_alb_manager.py >> /apps/soca/$SOCA_CONFIGURATION/cluster_manager/dcv_alb_manager.py.log 2>&1
" | crontab -

# Make sure Secret Manager is available first
secret=$(get_secret)

if [[ "$SOCA_AUTH_PROVIDER" == "activedirectory" ]]; then
  DS_DOMAIN_NAME=$(echo "$secret" | grep -oP '"DSDomainName": \"(.*?)\"' | sed 's/"DSDomainName": //g' | tr -d '"')
  UPPER_DS_DOMAIN_NAME=$(echo "$DS_DOMAIN_NAME" | tr a-z A-Z)
  DS_DOMAIN_ADMIN_USERNAME=$(echo "$secret" | grep -oP '"DSDomainAdminUsername": \"(.*?)\"' | sed 's/"DSDomainAdminUsername": //g' | tr -d '"')
  DS_DOMAIN_ADMIN_PASSWORD=$(echo "$secret" | grep -oP '"DSDomainAdminPassword": \"(.*?)\"' | sed 's/"DSDomainAdminPassword": //g' | tr -d '"')
  DS_DOMAIN_NETBIOS=$(echo "$secret" | grep -oP '"DSDomainNetbios": \"(.*?)\"' | sed 's/"DSDomainNetbios": //g' | tr -d '"')
  DS_DOMAIN_BASE=$(echo "$secret" | grep -oP '"DSDomainBase": \"(.*?)\"' | sed 's/"DSDomainBase": //g' | tr -d '"')
  DS_DIRECTORY_ID=$(echo "$secret" | grep -oP '"DSDirectoryId": \"(.*?)\"' | sed 's/"DSDirectoryId": //g' | tr -d '"')

  # Waiting for the Route53 Resolver to be fully active, otherwise SOCA won't be able to resolve the AD domain
  SCHEDULER_UPPER_HOSTNAME=$(hostname | awk '{split($0,h,"."); print toupper(h[1])}')
  MAX_ATTEMPT=10
  CURRENT_ATTEMPT=0
  echo "DS_DIRECTORY_ID: $DS_DIRECTORY_ID"
  echo "DS_DOMAIN_BASE: $DS_DOMAIN_BASE"
  echo "DS_DOMAIN_NAME: $DS_DOMAIN_NAME"
  echo "DS_DOMAIN_NETBIOS: $DS_DOMAIN_NETBIOS"

  nslookup "$DS_DOMAIN_NAME"
  while [[ $? -ne 0 ]] && [[ $CURRENT_ATTEMPT -le $MAX_ATTEMPT ]]
  do
      echo "Waiting for Route 53 outbound endpoint and rule to become active... Waiting 3mn... Loop count is: $CURRENT_ATTEMPT/$MAX_ATTEMPT"
      sleep 180
      ((CURRENT_ATTEMPT=CURRENT_ATTEMPT+1))
      nslookup "$DS_DOMAIN_NAME"
  done

  # Create AD caching credentials. These files will be used to retrieve AD Join Domain user as we do not want to query secret manager every time we provision a compute host
  mkdir -p "/apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation"
  chmod 600 "/apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation"
  echo -n "$DS_DOMAIN_NAME" > "/apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/domain_name.cache"
  echo -n "$DS_DOMAIN_ADMIN_USERNAME" > "/apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain_user.cache"
  echo -n "$DS_DOMAIN_ADMIN_PASSWORD" > "/apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain.cache"
  chmod 600 "/apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/domain_name.cache"
  chmod 600 "/apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain_user.cache"
  chmod 600 "/apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain.cache"

  # Join host to realm
  ADCLI=$(command -v adcli)
  REALM=$(command -v realm)
  MAX_ATTEMPT=10
  CURRENT_ATTEMPT=0
  echo $DS_DOMAIN_ADMIN_PASSWORD | $REALM join --user $DS_DOMAIN_ADMIN_USERNAME $UPPER_DS_DOMAIN_NAME --verbose
  while [[ $? -ne 0 ]] && [[ $CURRENT_ATTEMPT -le $MAX_ATTEMPT ]]
  do
      SLEEP_TIME=$(( RANDOM % 60 ))
      id $DS_DOMAIN_ADMIN_USERNAME
      echo "Realm join didn't complete successfully. Retrying in $SLEEP_TIME seconds... Loop count is: $CURRENT_ATTEMPT/$MAX_ATTEMPT"
      sleep $SLEEP_TIME
      ((CURRENT_ATTEMPT=CURRENT_ATTEMPT+1))
      echo $DS_DOMAIN_ADMIN_PASSWORD | $ADCLI delete-computer -U $DS_DOMAIN_ADMIN_USERNAME --stdin-password --domain=$DS_DOMAIN_NAME $SCHEDULER_UPPER_HOSTNAME
      echo $DS_DOMAIN_ADMIN_PASSWORD | $REALM leave --user $DS_DOMAIN_ADMIN_USERNAME $UPPER_DS_DOMAIN_NAME --verbose
      echo $DS_DOMAIN_ADMIN_PASSWORD | $REALM join --user $DS_DOMAIN_ADMIN_USERNAME $UPPER_DS_DOMAIN_NAME --verbose
  done

  echo -e "
## Add the \"AWS Delegated Administrators\" group from the domain.
%AWS\ Delegated\ Administrators ALL=(ALL:ALL) ALL" >> /etc/sudoers

  cp /etc/sssd/sssd.conf /etc/sssd/sssd.conf.orig

  echo -e "[sssd]
domains = default
config_file_version = 2
services = nss, pam

[domain/default]
ad_domain = $DS_DOMAIN_NAME
krb5_realm = $UPPER_DS_DOMAIN_NAME
realmd_tags = manages-system joined-with-samba
cache_credentials = True
id_provider = ad
krb5_store_password_if_offline = True
default_shell = /bin/bash
ldap_id_mapping = True
use_fully_qualified_names = False
fallback_homedir = /data/home/%u
access_provider = ad

[nss]
homedir_substring = /data/home

[pam]

[autofs]

[ssh]

[secrets]" > /etc/sssd/sssd.conf

  chmod 600 /etc/sssd/sssd.conf
  systemctl enable sssd
  systemctl restart sssd
fi

# Append the cluster name on the SOCA HTML template
IFS="-" read name sanitized_cluster_name <<< "echo $SOCA_CONFIGURATION"
sed -i "s/__SOCA_CLUSTER__NAME__/$sanitized_cluster_name/g" /apps/soca/$SOCA_CONFIGURATION/cluster_web_ui/templates/common/horizontal_menu_bar.html

# Install NodeJS/NPM if needed
if [[ ! $(command -v npm) ]];
then
  echo "npm not detected, installing it ... "
  export NVM_DIR="/root/nvm/$(date +%s)/.nvm"
  mkdir -p $NVM_DIR
  echo "Downloading $NVM_URL"
  wget "$NVM_URL"
  if [[ $(md5sum $NVM_INSTALL_SCRIPT | awk '{print $1}') != $NVM_HASH ]];  then
        echo -e "FATAL ERROR: Checksum for NVM failed. File may be compromised." > /etc/motd
        exit 1
  fi
  chmod +x $NVM_INSTALL_SCRIPT
  /bin/bash $NVM_INSTALL_SCRIPT
  source "$NVM_DIR/nvm.sh"  # This loads nvm
  # shellcheck disable=SC1090
  source "$NVM_DIR/bash_completion"
  nvm install v8.7.0
fi

# Install required Node module
npm install --prefix /apps/soca/"$SOCA_CONFIGURATION"/cluster_web_ui/static monaco-editor@0.24.0

# Start Web UI
chmod +x /apps/soca/"$SOCA_CONFIGURATION"/cluster_web_ui/socawebui.sh
/apps/soca/"$SOCA_CONFIGURATION"/cluster_web_ui/socawebui.sh start

# Wait until the endpoint is reachable
sleep 30

# Create default LDAP user with admin privileges
mkdir -p /data/home

sanitized_username="$3"
sanitized_password="$4"
admin_api_key=$(cat /apps/soca/$SOCA_CONFIGURATION/cluster_web_ui/keys/admin_api_key.txt)

curl -k -H "X-SOCA-TOKEN: $admin_api_key" \
 --data-urlencode "user=$sanitized_username" \
 --data-urlencode "password=$sanitized_password" \
 --data-urlencode "sudoers=1" \
 --data-urlencode "email=admin@soca" \
 --data-urlencode "uid=0" \
 --data-urlencode "gid=0" \
 -X POST https://127.0.0.1:8443/api/ldap/user >> /root/create_new_user.log 2>&1

# Re-enable access
if [[ "$SOCA_BASE_OS" == "amazonlinux2" ]] || [[ "$SOCA_BASE_OS" == "rhel7" ]]; then
     usermod --shell /bin/bash ec2-user
fi

if [[ "$SOCA_BASE_OS" == "centos7" ]]; then
     usermod --shell /bin/bash centos
fi

# Avoid customer to use system account to submit job
if [[ "$SOCA_BASE_OS" == "amazonlinux2" ]] || [[ "$SOCA_BASE_OS" == "rhel7" ]]; then
    echo "alias qsub='echo -e \" !!!! Do not submit job with system account. \n\n Please use LDAP account instead. !!!! \"'" >> /home/ec2-user/.bash_profile
fi

if [[ "$SOCA_BASE_OS" == "centos7" ]]; then
    echo "alias qsub='echo -e \" !!!! Do not submit job with system account. \n\n Please use LDAP account instead. !!!! \"'" >> /home/centos/.bash_profile
fi

# Enforce minimum permissions
chmod 600 /apps/soca/$SOCA_CONFIGURATION

# Verify PBS
if [[ -z "$(pgrep pbs)" ]]; then
    echo -e "
    /!\ /!\ /!\ /!\ /!\ /!\ /!\ /!\
    ERROR WHILE CREATING SOCA HPC
    *******************************
    PBS SERVICE NOT DETECTED
    ********************************
    The USER-DATA did not run properly
    Please look for any errors on /var/log/message | grep cloud-init
    " > /etc/motd
    exit 1
fi

# Verify SSSD
if [[ -z "$(pgrep sssd)" ]]; then
    echo -e "
    /!\ /!\ /!\ /!\ /!\ /!\ /!\ /!\
    ERROR WHILE CREATING SOCA HPC
    *******************************
    SSSD SERVICE NOT DETECTED
    ********************************
    The USER-DATA did not run properly
    Please look for any errors on /var/log/message | grep cloud-init
    " > /etc/motd
    exit 1
fi

# Cluster is ready
echo -e "
   _____  ____   ______ ___
  / ___/ / __ \ / ____//   |
  \__ \ / / / // /    / /| |
 ___/ // /_/ // /___ / ___ |
/____/ \____/ \____//_/  |_|
Cluster: $SOCA_CONFIGURATION
> source /etc/environment to load SOCA paths
" > /etc/motd


# Clean directories
rm -rf /root/openpbs-${OPENPBS_VERSION} /root/${OPENPBS_TGZ}

# Install OpenMPI under /apps/openmpi/<openmpi_version>
# This will take a while and is not system blocking, so adding at the end of the install process
mkdir -p /apps/soca/$SOCA_CONFIGURATION/openmpi/installer
mkdir -p /apps/openmpi
cd /apps/soca/$SOCA_CONFIGURATION/openmpi/installer

wget "$OPENMPI_URL"
if [[ $(md5sum "$OPENMPI_TGZ" | awk '{print $1}') != "$OPENMPI_HASH" ]];  then
    echo -e "FATAL ERROR: Checksum for OpenMPI failed. File may be compromised." > /etc/motd
    exit 1
fi

tar xvf "$OPENMPI_TGZ"
cd openmpi-"$OPENMPI_VERSION"
./configure --prefix="/apps/openmpi/$OPENMPI_VERSION"
make
make install
