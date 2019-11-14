#!/bin/bash -xe

source /etc/environment
source /root/config.cfg
AWS=$(which aws)
echo "BEGIN"  >> /root/ComputeNodeUserCustomization.log 2>&1

# Make sure system is clean and PBS is stopped
crontab -r
systemctl stop pbs

# Begin USER Customization
$AWS s3 cp s3://$SOCA_INSTALL_BUCKET/$SOCA_INSTALL_BUCKET_FOLDER/scripts/ComputeNodeUserCustomization.sh /root/
/bin/bash /root/ComputeNodeUserCustomization.sh >> /root/ComputeNodeUserCustomization.log 2>&1
rm /root/ComputeNodeUserCustomization.sh
# End USER Customization

# Begin DCV Customization
if [ "$SOCA_JOB_QUEUE" == "desktop" ]; then
    echo "Installing DCV"
    $AWS s3 cp s3://$SOCA_INSTALL_BUCKET/$SOCA_INSTALL_BUCKET_FOLDER/scripts/ComputeNodeInstallDCV.sh /root/
    /bin/bash /root/ComputeNodeInstallDCV.sh >> /root/ComputeNodeInstallDCV.log 2>&1
    rm /root/ComputeNodeInstallDCV.sh
    sleep 30
fi
# End DCV Customization

# Begin EFA Customization
if [ $SOCA_JOB_EFA == "true" ]; then
    echo "Installing EFA"
    cd /root/
    curl --silent -O $EFA_URL
    if [[ $(md5sum $EFA_TGZ | awk '{print $1}') != $EFA_HASH ]];  then
        echo -e "FATAL ERROR: Checksum for EFA failed. File may be compromised." > /etc/motd
        exit 1
    fi
    tar -xf $EFA_TGZ
    cd aws-efa-installer
    /bin/bash efa_installer.sh -y
fi
# End EFA customization

echo -e "
Compute Node Ready for queue: $SOCA_JOB_QUEUE
" > /etc/motd

# Configure FSx if specified by the user.
# Right before the reboot to minimize the time to wait for FSx to be AVAILABLE
if [[ $SOCA_FSX_LUSTRE_BUCKET != 'false' ]] || [[ $SOCA_FSX_LUSTRE_DNS != 'false' ]] ; then
    echo "FSx request detected, installing FSX Lustre client ... "
    FSX_MOUNTPOINT="/fsx"
    mkdir -p $FSX_MOUNTPOINT

    if [[ $SOCA_FSX_LUSTRE_DNS == 'false' ]]; then
        # Retrieve FSX DNS assigned to this job
        FSX_ARN=$($AWS resourcegroupstaggingapi get-resources --tag-filters  "Key=soca:FSx,Values=true" "Key=soca:StackId,Values=$AWS_STACK_ID" --query ResourceTagMappingList[].ResourceARN --output text)
        echo "GET_FSX_ARN: " $FSX_ARN
        FSX_ID=$(echo $FSX_ARN | cut -d/ -f2)
        echo "GET_FSX_ID: " $FSX_ID

        ## UPDATE FSX_DNS VALUE MANUALLY IF YOU ARE USING A PERMANENT FSX
        FSX_DNS=$FSX_ID".fsx."$AWS_DEFAULT_REGION".amazonaws.com"

        # Verify if DNS is ready
        CHECK_FSX_STATUS=$($AWS fsx describe-file-systems --file-system-ids $FSX_ID  --query FileSystems[].Lifecycle --output text)
        LOOP_COUNT=1
        echo "FSX_DNS: " $FSX_DNS
        while [[ $CHECK_FSX_STATUS != "AVAILABLE" ]] && [[ $LOOP_COUNT -lt 10 ]]
            do
                echo "FSX does not seems to be on AVAILABLE status yet ... waiting 60 secs"
                sleep 60
                CHECK_FSX_STATUS=$($AWS fsx describe-file-systems --file-system-ids $FSX_ID  --query FileSystems[].Lifecycle --output text)
                echo $CHECK_FSX_STATUS
                ((LOOP_COUNT++))
        done

        if [[ $CHECK_FSX_STATUS == "AVAILABLE" ]]; then
            echo "FSx is AVAILABLE"
            echo "$FSX_DNS@tcp:/fsx $FSX_MOUNTPOINT lustre defaults,noatime,flock,_netdev 0 0" >> /etc/fstab
        else
            echo "FSx is not available even after 10 minutes timeout, ignoring FSx mount ..."
        fi
    else
        # Using persistent FSX provided by customer
        echo "Detected existing FSx provided by customers " $SOCA_FSX_LUSTRE_DNS
        echo "$SOCA_FSX_LUSTRE_DNS@tcp:/fsx $FSX_MOUNTPOINT lustre defaults,noatime,flock,_netdev 0 0" >> /etc/fstab
    fi

    # Install Clients
    if [[ $SOCA_BASE_OS == "amazonlinux2" ]]; then
        sudo amazon-linux-extras install -y lustre2.10
    else
        sudo yum -y install https://downloads.whamcloud.com/public/lustre/lustre-2.10.6/el7/client/RPMS/x86_64/kmod-lustre-client-2.10.6-1.el7.x86_64.rpm
        sudo yum -y install https://downloads.whamcloud.com/public/lustre/lustre-2.10.6/el7/client/RPMS/x86_64/lustre-client-2.10.6-1.el7.x86_64.rpm
        # Lustre Client 2.10 does not support newer Centos7/RHEL7 kernels so we need do downgrade kernel version to 3.10.0-957
        # Lustre Client 2.12 does support newer kernels but can't get to work with FSx
        KERNEL_COUNT=0
        awk -F\' '/menuentry / {print $2}' /boot/grub2/grub.cfg  > /root/kernel_list
        while read kernel; do
            if [[ $kernel == *"3.10.0-957"* ]]; then
              grub2-reboot $KERNEL_COUNT
              reboot
           fi
           ((KERNEL_COUNT++))
        done < /root/kernel_list
    fi

    # Mount
    mount -a
fi

# Post-Boot routine completed, starting PBS
systemctl start pbs
