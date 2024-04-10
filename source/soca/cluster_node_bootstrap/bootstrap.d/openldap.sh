
function openldap_configure {
   echo "[BEGIN] openldap_configure ... "
  MAX_ATTEMPT=10
  LDAP_NAME=$($AWS secretsmanager get-secret-value --secret-id $SOCA_CONFIGURATION --query SecretString --output text | grep -oP '"LdapName": \"(.*?)\"' | sed 's/"LdapName": //g' | tr -d '"')
  CURRENT_ATTEMPT=0
  SLEEP_INTERVAL=180
  # Loop to make sure SecretsManager produces a result in case we are ready too quickly for it
  LDAP_CONFIG=$($AWS secretsmanager get-secret-value --secret-id $SOCA_CONFIGURATION --query SecretString --output text)
  while [[ $? -ne 0 ]] && [[ $CURRENT_ATTEMPT -le $MAX_ATTEMPT ]]
  do
      echo "AWS Secrets Manager is not ready yet. Sleeping $SLEEP_INTERVAL seconds.. Loop count is: $CURRENT_ATTEMPT/$MAX_ATTEMPT"
      sleep $SLEEP_INTERVAL
      ((CURRENT_ATTEMPT=CURRENT_ATTEMPT+1))
      LDAP_CONFIG=$($AWS secretsmanager get-secret-value --secret-id $SOCA_CONFIGURATION --query SecretString --output text)
  done

  LDAP_BASE=$(echo "$LDAP_CONFIG" | grep -oP '"LdapBase":\s*\"(.*?)\"' | sed 's/"LdapBase":\s*//g' | tr -d '"')
  LDAP_NAME=$(echo "$LDAP_CONFIG" | grep -oP '"LdapName":\s*\"(.*?)\"' | sed 's/"LdapName":\s*//g' | tr -d '"')
  echo "URI ldap://$LDAP_NAME" >> /etc/openldap/ldap.conf
  echo "BASE $LDAP_BASE" >> /etc/openldap/ldap.conf
  if [ -e /etc/sssd/sssd.conf ]; then
      cp /etc/sssd/sssd.conf /etc/sssd/sssd.conf.orig
  fi
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
ldap_tls_reqcert = never
use_fully_qualified_names = False
ldap_tls_cacertdir = /etc/openldap/cacerts
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

  mkdir -p /etc/openldap/cacerts/
  echo "Fetching OpenLDAP self-signed certificate"
  openssl s_client -showcerts -connect "$SCHEDULER_HOSTNAME":389 -starttls ldap  </dev/null  |  openssl x509 -out /etc/openldap/cacerts/openldap-server.pem

  if [[ $SOCA_BASE_OS == "amazonlinux2023" ]]; then
      echo "Adding OpenLDAP self-signed certificate to system CA trust store"
      cp /etc/openldap/cacerts/openldap-server.pem /etc/pki/ca-trust/source/anchors/
      echo "Updating system CA Trust Store"
      update-ca-trust
      echo "Rebuilding /etc/openldap/cacerts directory"
      openssl rehash /etc/openldap/cacerts
  fi

  echo "Performing Authconfig adjustments"
  case $SOCA_BASE_OS in
      "centos7" | "rhel7" | "amazonlinux2")
        authconfig --disablesssd --disablesssdauth --disableldap --disableldapauth --disablekrb5 --disablekrb5kdcdns --disablekrb5realmdns --disablewinbind --disablewinbindauth --disablewinbindkrb5 --disableldaptls --disablerfc2307bis --updateall
        sss_cache -E
        authconfig --enablesssd --enablesssdauth --enableldap --enableldaptls --enableldapauth --ldapserver=ldap://"$SCHEDULER_HOSTNAME" --ldapbasedn="$LDAP_BASE" --enablelocauthorize --enablemkhomedir --enablecachecreds --updateall
        authconfig --enablesssd --enablesssdauth --enablelocauthorize --enablemkhomedir --enablecachecreds --updateall
        ;;

      "rhel8" | "amazonlinux2023")
        authselect select sssd with-mkhomedir --force
        ;;

      *)
        echo "ERROR - Unable to determine Authconfig"
        ;;
  esac
  chmod 600 /etc/sssd/sssd.conf
  systemctl enable sssd
  systemctl restart sssd
  echo "sudoers: files sss" >> /etc/nsswitch.conf
  echo "[COMPLETED] openldap_configure ... "
}
