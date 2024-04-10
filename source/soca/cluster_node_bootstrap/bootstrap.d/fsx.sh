
function fsx_lustre_client_tuning_postmount {
  echo "[BEGIN] fsx_lustre_client_tuning_postmount"
  # https://docs.aws.amazon.com/fsx/latest/LustreGuide/performance.html#performance-tips
  GB_MEM=$(free --si -g | grep -E '^Mem:' | awk '{print $2}')
  echo "Detected ${NCPUS} CPUs / ${GB_MEM} GiB memory for Lustre performance tuning"
  if [[ "${NPROCS}" -ge 64 ]]; then
    echo "Applying CPU count Lustre performance tuning"
    lctl set_param osc.*OST*.max_rpcs_in_flight=32
    lctl set_param mdc.*.max_rpcs_in_flight=64
    lctl set_param mdc.*.max_mod_rpcs_in_flight=50
  fi

  if [[ "${GB_MEM}" -ge 64 ]]; then
    echo "Applying memory size Lustre performance tuning"
    lctl set_param ldlm.namespaces.*.lru_max_age=600000
  fi
  lctl lustre_build_version
  echo "[COMPLETED] fsx_lustre_client_tuning_postmount"
}

function fsx_lustre_client_tuning_prereboot {
  echo "[BEGIN] fsx_lustre_client_tuning_prereboot"
  # https://docs.aws.amazon.com/fsx/latest/LustreGuide/performance.html#performance-tips
  echo "Detected ${NCPUS} CPUs for Lustre performance tuning prereboot"
  if [[ "${NCPUS}" -ge 64 ]]; then
    echo "Applying CPU count Lustre performance tuning"
    echo "options ptlrpc ptlrpcd_per_cpt_max=32" >> /etc/modprobe.d/modprobe.conf
    echo "options ksocklnd credits=2560" >> /etc/modprobe.d/modprobe.conf
    REBOOT_REQUIRED=1
  fi
  echo "[COMPLETED] fsx_lustre_client_tuning_prereboot"
}


function fsx_lustre_driver_installer {
  echo "[BEGIN] fsx_lustre_driver_installer"
  local EL_VERSION=$1
  local REPO_VERSION_REWRITE=$2

  if [[ ! ${EL_VERSION} =~ ^(7|8|9)$ ]]; then
    echo "EL Version must be either 7, 8 or 9"
  else
    echo "Getting FSx Lustre repo for RHEL distros version ${EL_VERSION}"
    wget https://fsx-lustre-client-repo-public-keys.s3.amazonaws.com/fsx-rpm-public-key.asc -O /tmp/fsx-rpm-public-key.asc
    rpm --import /tmp/fsx-rpm-public-key.asc
    wget https://fsx-lustre-client-repo.s3.amazonaws.com/el/"${EL_VERSION}"/fsx-lustre-client.repo -O /etc/yum.repos.d/aws-fsx.repo

    if [[ -n "${REPO_VERSION_REWRITE}" ]]; then
      echo "SED Rewrite enabled {$REPO_VERSION_REWRITE}"
      sed -i "${REPO_VERSION_REWRITE}" /etc/yum.repos.d/aws-fsx.repo
    fi

    yum clean all
    yum install -y kmod-lustre-client lustre-client
    REQUIRE_REBOOT=1
  fi
  echo "[COMPLETED] fsx_lustre_driver_installer"
}


function fsx_lustre_setup {
  echo "[BEGIN] fsx_lustre "
    FSX_MOUNTPOINT="/fsx"
    mkdir -p $FSX_MOUNTPOINT

    # Make /fsx R/W/X by everyone. ACL still applies at folder level
    chmod 777 $FSX_MOUNTPOINT

    if [[ "$SOCA_FSX_LUSTRE_DNS" == 'false' ]]; then
        # Retrieve FSX DNS assigned to this job
        FSX_ARN=$($AWS resourcegroupstaggingapi get-resources --tag-filters  "Key=soca:FSx,Values=true" "Key=soca:StackId,Values=$AWS_STACK_ID" --query ResourceTagMappingList[].ResourceARN --output text)
        echo "GET_FSX_ARN: ${FSX_ARN}"
        FSX_ID=$(echo "${FSX_ARN}" | cut -d/ -f2)
        echo "GET_FSX_ID: ${FSX_ID}"
        echo "export SOCA_FSX_LUSTRE_ID=\"${FSX_ID}\" >> /etc/environment"

        # Retrieve FSX Lustre DNSName
        FSX_DNS=$($AWS fsx describe-file-systems --file-system-ids "${FSX_ID}"  --query 'FileSystems[].DNSName' --output text)

        # Verify if DNS is ready
        CHECK_FSX_STATUS=$($AWS fsx describe-file-systems --file-system-ids "${FSX_ID}"  --query FileSystems[].Lifecycle --output text)
        # Note: We can retrieve FSxL Mount Name even if FSx is not fully ready
        GET_FSX_MOUNT_NAME=$($AWS fsx describe-file-systems --file-system-ids "${FSX_ID}"  --query FileSystems[].LustreConfiguration.MountName --output text)
        LOOP_COUNT=1
        echo "FSX_DNS: ${FSX_DNS}"
        while [[ "$CHECK_FSX_STATUS" != "AVAILABLE" ]] && [[ $LOOP_COUNT -lt 10 ]]
            do
                echo "FSX does not seem to be in AVAILABLE status yet ... waiting 60 secs"
                sleep 60
                CHECK_FSX_STATUS=$($AWS fsx describe-file-systems --file-system-ids "${FSX_ID}"  --query FileSystems[].Lifecycle --output text)
                echo "${CHECK_FSX_STATUS}"
                ((LOOP_COUNT++))
        done

        if [[ "$CHECK_FSX_STATUS" == "AVAILABLE" ]]; then
            echo "FSx is AVAILABLE"
            echo "${FSX_DNS}@tcp:/${GET_FSX_MOUNT_NAME} ${FSX_MOUNTPOINT} lustre defaults,noatime,flock,_netdev 0 0" >> /etc/fstab
        else
            echo "FSx is not available even after 10 minutes timeout, ignoring FSx mount ..."
        fi
    else
        # Using persistent FSX provided by customer
        echo "Detected existing FSx ${SOCA_FSX_LUSTRE_DNS}"
        FSX_ID=$(echo "${SOCA_FSX_LUSTRE_DNS}" | cut -d. -f1)
        GET_FSX_MOUNT_NAME=$($AWS fsx describe-file-systems --file-system-ids "${FSX_ID}"  --query FileSystems[].LustreConfiguration.MountName --output text)
        # Retrieve FSX Lustre DNSName
        FSX_DNS=$($AWS fsx describe-file-systems --file-system-ids "${FSX_ID}"  --query 'FileSystems[].DNSName' --output text)
        echo "${FSX_DNS}@tcp:/${GET_FSX_MOUNT_NAME} ${FSX_MOUNTPOINT} lustre defaults,noatime,flock,_netdev 0 0" >> /etc/fstab
    fi

    echo "Found kernel version: ${KERNEL} running on: ${MACHINE}"
    # Check if Lustre Client is already installed
    if [[ -z "$(rpm -qa lustre-client)" ]]; then
        # Install FSx for Lustre Client
        # https://docs.aws.amazon.com/fsx/latest/LustreGuide/install-lustre-client.html

        if [[ "$SOCA_BASE_OS" == "amazonlinux2" ]]; then
            amazon-linux-extras install -y lustre

        elif [[ "$SOCA_BASE_OS" == "amazonlinux2023" ]]; then
            dnf install -y lustre-client

        elif [[ ${SOCA_BASE_OS} =~ ^(rhel7|centos7)$  ]]; then
            if [[ $KERNEL == *"3.10.0-957"*$MACHINE ]]; then
                yum -y install https://downloads.whamcloud.com/public/lustre/lustre-2.10.8/el7/client/RPMS/x86_64/kmod-lustre-client-2.10.8-1.el7.x86_64.rpm
                yum -y install https://downloads.whamcloud.com/public/lustre/lustre-2.10.8/el7/client/RPMS/x86_64/lustre-client-2.10.8-1.el7.x86_64.rpm
                REQUIRE_REBOOT=1
            elif [[ $KERNEL == *"3.10.0-1062"*$MACHINE ]]; then
                fsx_lustre_driver_installer 7 "s#7#7.7#"
            elif [[ $KERNEL == *"3.10.0-1127"*$MACHINE ]]; then
                fsx_lustre_driver_installer 7 "s#7#7.8#"
            elif [[ $KERNEL == *"3.10.0-1160"*$MACHINE ]]; then
                fsx_lustre_driver_installer 7
            elif [[ $KERNEL == *"4.18.0-193"*$MACHINE ]]; then
                fsx_lustre_driver_installer 7
            else
                echo "ERROR: Can't install FSx for Lustre client as kernel version: ${KERNEL} isn't matching expected versions for EL7"
            fi

        elif [[ ${SOCA_BASE_OS} =~ ^(rhel8|rocky8)$  ]]; then
          if [[ $KERNEL == *"4.18.0-513"*$MACHINE ]]; then
              fsx_lustre_driver_installer 8
              yum install -y kmod-lustre-client lustre-client
          elif [[ $KERNEL == *"4.18.0-477"*$MACHINE ]]; then
              fsx_lustre_driver_installer 8 's#8#8.8#'
              yum install -y kmod-lustre-client lustre-client
          elif [[ $KERNEL == *"4.18.0-425"*$MACHINE ]]; then
              fsx_lustre_driver_installer 8 's#8#8.7#'
          elif [[ $KERNEL == *"4.18.0-372"*$MACHINE ]]; then
              fsx_lustre_driver_installer 8 's#8#8.6#'
          elif [[ $KERNEL == *"4.18.0-348"*$MACHINE ]]; then
              fsx_lustre_driver_installer 8 's#8#8.5#'
          elif [[ $KERNEL == *"4.18.0-305"*$MACHINE ]]; then
              fsx_lustre_driver_installer 8 's#8#8.4#'
          elif [[ $KERNEL == *"4.18.0-240"*$MACHINE ]]; then
              fsx_lustre_driver_installer 8 's#8#8.3#'
          elif [[ $KERNEL == *"4.18.0-193"*$MACHINE ]]; then
              fsx_lustre_driver_installer 8 's#8#8.2#'
          else
              echo "Can't install FSx for Lustre client as kernel version $KERNEL isn't matching expected versions for EL8"
          fi

        elif [[ ${SOCA_BASE_OS} =~ ^(rhel9|rocky9)$  ]]; then
          if [[ $KERNEL == *"5.14.0-362"*$MACHINE ]]; then
              fsx_lustre_driver_installer 9
          elif [[ $KERNEL == *"5.14.0-70"*$MACHINE ]]; then
              fsx_lustre_driver_installer 9 's#9#9.0#'
          else
             echo "Can't install FSx for Lustre client as kernel version $KERNEL isn't matching expected versions for EL9"
          fi
        fi
    fi

    fsx_lustre_client_tuning_prereboot
    echo "[COMPLETED] fsx_lustre"
}
