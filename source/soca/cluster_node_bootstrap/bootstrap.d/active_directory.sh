function active_directory_configure {
  echo "[BEGIN] active_directory_configure ... "
  # Configure Active Directory auth
  if [[ ! -f /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/domain_name.cache ]]; then
      DS_DOMAIN_NAME=$($AWS secretsmanager get-secret-value --secret-id $SOCA_CONFIGURATION --query SecretString --output text | grep -oP '"DSDomainName": \"(.*?)\"' | sed 's/"DSDomainName": //g' | tr -d '"')
  else
      DS_DOMAIN_NAME=$(cat /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/domain_name.cache)
  fi

  UPPER_DS_DOMAIN_NAME=$(echo $DS_DOMAIN_NAME | tr a-z A-Z)

  # Retrieve account with join permission if available, otherwise query SecretManager
  if [[ ! -f /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain_user.cache ]]; then
      DS_DOMAIN_ADMIN_USERNAME=$($AWS secretsmanager get-secret-value --secret-id $SOCA_CONFIGURATION --query SecretString --output text | grep -oP '"DSDomainAdminUsername": \"(.*?)\"' | sed 's/"DSDomainAdminUsername": //g' | tr -d '"')
      echo -n $DS_DOMAIN_ADMIN_USERNAME > /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain_user.cache
  else
      DS_DOMAIN_ADMIN_USERNAME=$(cat /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain_user.cache)
  fi

  if [[ ! -f /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain.cache ]]; then
      DS_DOMAIN_ADMIN_PASSWORD=$($AWS secretsmanager get-secret-value --secret-id $SOCA_CONFIGURATION --query SecretString --output text | grep -oP '"DSDomainAdminPassword": \"(.*?)\"' | sed 's/"DSDomainAdminPassword": //g' | tr -d '"')
      echo -n $DS_DOMAIN_ADMIN_PASSWORD > /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain.cache
  else
      DS_DOMAIN_ADMIN_PASSWORD=$(cat /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain.cache)
  fi

  SERVER_UPPER_HOSTNAME=$(hostname | awk '{split($0,h,"."); print toupper(h[1])}')

  ADCLI=$(command -v adcli)
  REALM=$(command -v realm)
  HOSTNAME_DATA=$(echo "${SOCA_CONFIGURATION}-${AWS_REGION}-${AWS_INSTANCE_ID}"  | openssl dgst -sha1 -binary | xxd -p | awk '{split($0,h,"."); print toupper(h[1])}')
  HOSTNAME_PREFIX="SOCA-"
  AVAILABLE_CHAR=$((15 - ${#HOSTNAME_PREFIX}))
  SHAKE_VALUE=${HOSTNAME_DATA: -${AVAILABLE_CHAR}}
  SOCA_AD_HOSTNAME="${HOSTNAME_PREFIX}${SHAKE_VALUE}"
  MAX_ATTEMPT=10
  CURRENT_ATTEMPT=0
  echo "Joining ${SERVER_UPPER_HOSTNAME} to AD as ${SOCA_AD_HOSTNAME}"
  echo $DS_DOMAIN_ADMIN_PASSWORD | $REALM join --user $DS_DOMAIN_ADMIN_USERNAME $UPPER_DS_DOMAIN_NAME --computer-name="${SOCA_AD_HOSTNAME}" --verbose
  while [[ $? -ne 0 ]] && [[ $CURRENT_ATTEMPT -le $MAX_ATTEMPT ]]
  do
      SLEEP_TIME=$(( RANDOM % 60 ))
      id $DS_DOMAIN_ADMIN_USERNAME
      echo "Realm join didn't complete successfully. Retrying in $SLEEP_TIME seconds... Loop count is: $CURRENT_ATTEMPT/$MAX_ATTEMPT"
      sleep $SLEEP_TIME
      ((CURRENT_ATTEMPT=CURRENT_ATTEMPT+1))
      echo $DS_DOMAIN_ADMIN_PASSWORD | $ADCLI delete-computer -U $DS_DOMAIN_ADMIN_USERNAME --stdin-password --domain=$DS_DOMAIN_NAME $SOCA_AD_HOSTNAME
      echo $DS_DOMAIN_ADMIN_PASSWORD | $REALM leave --user $DS_DOMAIN_ADMIN_USERNAME $UPPER_DS_DOMAIN_NAME --verbose
      echo $DS_DOMAIN_ADMIN_PASSWORD | $REALM join --user $DS_DOMAIN_ADMIN_USERNAME $UPPER_DS_DOMAIN_NAME --computer-name="${SOCA_AD_HOSTNAME}" --verbose
  done

  echo -e "
## Add the \"AWS Delegated Administrators\" group from the ${DS_DOMAIN_NAME} domain.
%AWS\ Delegated\ Administrators ALL=(ALL:ALL) ALL
" >> /etc/sudoers

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

# Use our AD-created SOCA hostname
ldap_sasl_authid = ${SOCA_AD_HOSTNAME}\$

[nss]
homedir_substring = /data/home

[pam]

[autofs]

[ssh]

[secrets]" > /etc/sssd/sssd.conf

  chmod 600 /etc/sssd/sssd.conf
  systemctl enable sssd
  systemctl restart sssd
  echo "sudoers: files sss" >> /etc/nsswitch.conf
  echo "[END] active_directory_configure ... "
}

function active_directory_validate_user_identity {
   echo "[BEGIN] validate_user_identity"
   # Retrieve account with join permission if available, otherwise query SecretManager
    if [[ -f /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain_user.cache ]]; then
        DS_DOMAIN_ADMIN_USERNAME=$(cat /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain_user.cache)
    else
        DS_DOMAIN_ADMIN_USERNAME=$($AWS secretsmanager get-secret-value --secret-id $SOCA_CONFIGURATION --query SecretString --output text | grep -oP '"DSDomainAdminUsername": \"(.*?)\"' | sed 's/"DSDomainAdminUsername": //g' | tr -d '"')
        echo -n $DS_DOMAIN_ADMIN_USERNAME > /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain_user.cache
    fi
    MAX_ATTEMPT=5
    CURRENT_ATTEMPT=0
    ID=$(command -v id)
    $ID $DS_DOMAIN_ADMIN_USERNAME > /dev/null 2>&1
    while [[ $? -ne 0 ]] && [[ $CURRENT_ATTEMPT -le $MAX_ATTEMPT ]]
    do
        SLEEP_TIME=$(( RANDOM % 30 ))
        echo "User identity not resolving successfully. Retrying in $SLEEP_TIME seconds... Loop count is: $CURRENT_ATTEMPT/$MAX_ATTEMPT"
        systemctl restart sssd
        ((CURRENT_ATTEMPT=CURRENT_ATTEMPT+1))
        $ID $DS_DOMAIN_ADMIN_USERNAME > /dev/null 2>&1
    done
    echo "[COMPLETED] validate_user_identity"
}