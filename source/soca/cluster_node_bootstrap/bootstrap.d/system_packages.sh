function system_packages_install {
  echo "[BEGIN] system_packages_install  ... "
  if [[ ! -f /root/soca_preinstalled_packages.log ]]; then
  echo "No preinstalled package log found - preparing BaseOS - ${SOCA_BASE_OS}.."

  case $SOCA_BASE_OS in
    "amazonlinux2")
      # AL2
      echo "Customizing for Amazon Linux 2"
      amazon-linux-extras install -y epel
      ;;
    "amazonlinux2023")
      # AL2023
      echo "Customizing for Amazon Linux 2023"
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
      ;;
    "centos7")
      # CentOS 7
      echo "Customizing for CentOS 7"
      yum -y install epel-release
      ;;
    "rhel7")
      # RHEL 7
      echo "Customizing for RHEL 7"
      EPEL_URL=$EPEL7_URL
      EPEL_RPM=$EPEL7_RPM
      EPEL_REPO="epel"
      ;;
    "rhel8"|"rocky8")
      # RHEL 8 or Rocky 8
      echo "Customizing for RHEL 8"
      EPEL_URL=$EPEL8_URL
      EPEL_RPM=$EPEL8_RPM
      EPEL_REPO="epel"
      REMOVE_PKGS=(
        libselinux-python
        libverto-tevent
        system-lsb
        compat-openldap
        ntp
        htop
        tcp_wrappers
        python-sssdconfig
      )
      ADD_PKGS=(
        wget
        rsyslog
        python3-libselinux
        python3-sss
        authselect-compat
        dejavu-fonts-common
        redhat-lsb
        ec2-hibinit-agent
      )
      ;;
    "rhel9"|"rocky9")
      # RHEL 9
      echo "Customizing for RHEL 9"
      EPEL_URL=$EPEL9_URL
      EPEL_RPM=$EPEL9_RPM
      EPEL_REPO="epel"
      REMOVE_PKGS=(
        libselinux-python
        libverto-tevent
        system-lsb
        redhat-lsb
        dejavu-fonts-common
        compat-openldap
        ntp
        htop
        tcp_wrappers
        python-sssdconfig
      )
      ADD_PKGS=(
        wget
        rsyslog
        python3-libselinux
        python3-sss
        authselect-compat
        ec2-hibinit-agent
      )
      ;;
    *)
      # Unknown BaseOS
      echo "FATAL ERROR - Unknown Base OS: ${SOCA_BASE_OS}"
      exit 1
      ;;
  esac

  # Pre package install OS customization
  if [[ ${SOCA_BASE_OS} =~ ^(rhel8|rocky8|rhel9|rocky9)$ ]]; then
    echo "Using RedHat EPEL URL/filename/repo name: ${EPEL_URL} / ${EPEL_RPM} / ${EPEL_REPO}"
    curl --silent "${EPEL_URL}" -o "${EPEL_RPM}"
    yum -y install "${EPEL_RPM}"
  fi

  if [[ ${SOCA_BASE_OS} == "rhel7" ]]; then
    yum-config-manager --enable rhel-7-server-rhui-optional-rpms
  fi

  if [[ ${SOCA_BASE_OS} == "rhel8" ]]; then
    dnf config-manager --set-enabled codeready-builder-for-rhel-8-rhui-rpms
  fi

  if [[ ${SOCA_BASE_OS} == "rhel9" ]]; then
    dnf config-manager --set-enabled codeready-builder-for-rhel-9-rhui-rpms
  fi

  if [[ ${SOCA_BASE_OS} == "rocky8" ]]; then
    dnf config-manager --set-enabled powertools
    if [[ ${SOCA_JOB_TYPE} == "dcv" ]]; then
      ADD_PKGS+=('vulkan')
    fi
  fi

  if [[ ${SOCA_BASE_OS} == "rocky9" ]]; then
    # PowerTool is known as crb on Rocky9 https://wiki.rockylinux.org/rocky/repo/#notes-on-crb
    dnf config-manager --set-enabled crb
  fi

  # Cleanup our _PKGS lists
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

#  for p in "${!OPENLDAP_SERVER_PKGS[@]}"; do
#    pkg_name=${OPENLDAP_SERVER_PKGS[p]}
#    [[ " ${REMOVE_PKGS[*]} " =~ " ${pkg_name} " ]] && unset 'OPENLDAP_SERVER_PKGS[p]'
#  done

  # Now add new packages.
  for i in "${ADD_PKGS[@]}"; do
    SYSTEM_PKGS+=($i)
  done

  # Now perform the installs on the potentially updated package lists
  auto_install ${SYSTEM_PKGS[*]} ${SCHEDULER_PKGS[*]} ${SSSD_PKGS[*]}

  # Post Install commands
  if [[ ${SOCA_BASE_OS} =~ ^(rhel8|rocky8|rhel9|rocky9)$ ]]; then
     systemctl enable hibinit-agent
  fi

else
  echo "Existing Package log found - bypassing package installation steps..."
fi
 echo "[COMPLETED] system_packages_install  ... "

}