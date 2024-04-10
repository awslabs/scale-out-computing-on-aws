function system_configure_scratch {
  echo "[BEGIN] system_configure_scratch... "
  mkdir /scratch/
  # Make /scratch R/W/X by everyone. ACL still applies at folder level
  chmod 777 /scratch/

  if [[ $SOCA_SCRATCH_SIZE -ne 0 ]]; then
    LIST_ALL_DISKS=$(lsblk --list | grep disk | awk '{print $1}')
    for disk in $LIST_ALL_DISKS;
    do
        CHECK_IF_PARTITION_EXIST=$(lsblk -b /dev/$disk | grep part | wc -l)
        CHECK_PARTITION_SIZE=$(lsblk -lnb /dev/$disk -o SIZE)
        let SOCA_SCRATCH_SIZE_IN_BYTES=$SOCA_SCRATCH_SIZE*1024*1024*1024
        if [[ $CHECK_IF_PARTITION_EXIST -eq 0 ]] && [[ $CHECK_PARTITION_SIZE -eq $SOCA_SCRATCH_SIZE_IN_BYTES ]]; then
            echo "Detected /dev/$disk with no partition as scratch device"
            mkfs -t ext4 /dev/$disk
            echo "/dev/$disk /scratch ext4 defaults 0 0" >> /etc/fstab
        fi
    done
else
    # Use Instance Store if possible.
    # When instance has more than 1 instance store, raid + mount them as /scratch
    VOLUME_LIST=()
    if [[ ! -z $(ls /dev/nvme[0-9]n1) ]]; then
        echo 'Detected Instance Store: NVME'
        DEVICES=$(ls /dev/nvme[0-9]n1)

    elif [[ ! -z $(ls /dev/xvdc[a-z]) ]]; then
        echo 'Detected Instance Store: SSD'
        DEVICES=$(ls /dev/xvdc[a-z])
    else
        echo 'No instance store detected on this machine.'
    fi

    if [[ ! -z $DEVICES ]]; then
        echo "Detected Instance Store with NVME:" $DEVICES
        # Clear Devices which are already mounted (eg: when customer import their own AMI)
        for device in $DEVICES;
        do
            CHECK_IF_PARTITION_EXIST=$(lsblk -b $device | grep part | wc -l)
            if [[ $CHECK_IF_PARTITION_EXIST -eq 0 ]]; then
                echo "$device is free and can be used"
                VOLUME_LIST+=($device)
            fi
        done

        VOLUME_COUNT=${#VOLUME_LIST[@]}
        if [[ $VOLUME_COUNT -eq 1 ]]; then
            # If only 1 instance store, mfks as ext4
            echo "Detected 1 NVMe device available, formatting as ext4 .."
            mkfs -t ext4 $VOLUME_LIST
            echo "$VOLUME_LIST /scratch ext4 defaults,nofail 0 0" >> /etc/fstab
        elif [[ $VOLUME_COUNT -gt 1 ]]; then
            # if more than 1 instance store disks, raid them !
            echo "Detected more than 1 NVMe device available, creating XFS fs ..."
            DEVICE_NAME="md0"
          for dev in ${VOLUME_LIST[@]} ; do dd if=/dev/zero of=$dev bs=1M count=1 ; done
          echo yes | mdadm --create -f --verbose --level=0 --raid-devices=$VOLUME_COUNT /dev/$DEVICE_NAME ${VOLUME_LIST[@]}
          mkfs -t ext4 /dev/$DEVICE_NAME
          mdadm --detail --scan | tee -a /etc/mdadm.conf
          echo "/dev/$DEVICE_NAME /scratch ext4 defaults,nofail 0 0" >> /etc/fstab
        else
            echo "All volumes detected already have a partition or mount point and can't be used as scratch devices"
        fi
    fi
fi
 echo "[COMPLETED] system_configure_scratch ... "
}

function system_disable_stricthostkeychecking {
  echo "[BEGIN] system_disable_stricthostkeychecking"
  echo "StrictHostKeyChecking no" >> /etc/ssh/ssh_config
  echo "UserKnownHostsFile /dev/null" >> /etc/ssh/ssh_config
  echo "[COMPLETED] system_disable_stricthostkeychecking ... "
}

function system_disable_selinux_firewalld {
    echo "[BEGIN] system_disable_selinux_firewalld"
  if [[ -z $(grep ^SELINUX=disabled /etc/selinux/config) ]]; then
    sed -i 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config
    REQUIRE_REBOOT=1
fi
  systemctl stop firewalld
  systemctl disable firewalld
  echo "[COMPLETED] system_disable_selinux_firewalld"
}

function system_disable_hyperthreading {
  echo "[BEGIN] system_disable_hyperthreading"
  for cpunum in $(awk -F'[,-]' '{print $2}' /sys/devices/system/cpu/cpu*/topology/thread_siblings_list | sort -un);
        do
            echo 0 > /sys/devices/system/cpu/cpu$cpunum/online;
        done
   echo "[COMPLETED] system_disable_hyperthreading"
}