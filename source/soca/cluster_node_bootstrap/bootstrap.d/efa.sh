function efa_install {
  echo "[BEGIN] efa_install"
  pushd /root/
  curl --silent -O "$EFA_URL"
  if [[ $(md5sum $EFA_TGZ | awk '{print $1}') != $EFA_HASH ]];  then
      echo -e "FATAL ERROR: Checksum for EFA failed. File may be compromised." > /etc/motd
      exit 1
  fi
  tar -xf "$EFA_TGZ"

  if [[ ${SOCA_BASE_OS} =~ ^(rhel8|rocky8|rhel9|rocky9|amazonlinux2023)$ ]]; then
    PACKAGE_TO_REMOVE=(libibverbs)
    echo "Removing existing packages to avoid dependency conflicts"
    yum remove -y $(echo ${PACKAGE_TO_REMOVE[*]})
  fi

  cd aws-efa-installer
  /bin/bash efa_installer.sh -y
  popd
  echo "[COMPLETED] efa_install"
}