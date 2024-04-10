function openpbs_stop {
  echo "[BEGIN] openpbs_stop... "
  systemctl stop pbs || true
  echo "[COMPLETED] openpbs_stop  ... "
}

function openpbs_start {
  echo "[BEGIN] openpbs_start... "
  systemctl restart pbs || exit
  echo "[COMPLETED] openpbs_start  ... "
}

function openpbs_install {
  echo "[BEGIN] openpbs_install... "
  OPENPBS_INSTALLED_VERS=$(/opt/pbs/bin/qstat --version | awk {'print $NF'})
  if [[ "$OPENPBS_INSTALLED_VERS" != "$OPENPBS_VERSION" ]]; then
      echo "OpenPBS Not Detected, Installing OpenPBS ..."
      cd ~
      wget $OPENPBS_URL
      if [[ $(md5sum $OPENPBS_TGZ | awk '{print $1}') != $OPENPBS_HASH ]]; then
          echo -e "FATAL ERROR: Checksum for OpenPBS failed. File may be compromised." > /etc/motd
          exit 1
      fi
      tar zxvf "$OPENPBS_TGZ"
      cd openpbs-"$OPENPBS_VERSION"
      ./autogen.sh
      ./configure --prefix=/opt/pbs
      make -j${NCPUS}
      make install -j${NCPUS}
      /opt/pbs/libexec/pbs_postinstall
      chmod 4755 /opt/pbs/sbin/pbs_iff /opt/pbs/sbin/pbs_rcp
      systemctl disable pbs
  else
      echo "OpenPBS already installed, and at correct version."
  fi
  echo "[COMPLETED] openpbs_install... "
}


function openpbs_postinstall_mom_config {
   echo "[BEGIN] openpbs_postinstall_mom_config... "
  cp /etc/pbs.conf /etc/pbs.conf.orig
  echo -e "
PBS_SERVER=$SCHEDULER_HOSTNAME
PBS_START_SERVER=0
PBS_START_SCHED=0
PBS_START_COMM=0
PBS_START_MOM=1
PBS_EXEC=/opt/pbs
PBS_LEAF_NAME=$SERVER_HOSTNAME
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
  echo "[COMPLETED] openpbs_postinstall_mom_config... "
}