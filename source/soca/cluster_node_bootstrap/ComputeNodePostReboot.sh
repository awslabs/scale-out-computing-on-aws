#!/bin/bash -xe

source /etc/environment
source /root/config.cfg
AWS=$(which aws)
REQUIRE_REBOOT=0
echo "SOCA > BEGIN PostReboot setup"

# In case AMI already have PBS installed, force it to stop
service pbs stop

# Make sure system is clean and PBS is stopped
crontab -r
systemctl stop pbs

# Begin DCV Customization
if [[ "$SOCA_JOB_QUEUE" == "desktop" ]]; then
    echo "Installing DCV"
    /bin/bash /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ComputeNodeInstallDCV.sh >> $SOCA_HOST_SYSTEM_LOG/ComputeNodeInstallDCV.log 2>&1
    sleep 30
fi
# End DCV Customization

# Begin EFA Customization
if [[ "$SOCA_JOB_EFA" == "true" ]]; then
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
if [[ "$SOCA_FSX_LUSTRE_BUCKET" != 'false' ]] || [[ "$SOCA_FSX_LUSTRE_DNS" != 'false' ]] ; then
    echo "FSx request detected, installing FSX Lustre client ... "
    FSX_MOUNTPOINT="/fsx"
    mkdir -p $FSX_MOUNTPOINT

    if [[ "$SOCA_FSX_LUSTRE_DNS" == 'false' ]]; then
        # Retrieve FSX DNS assigned to this job
        FSX_ARN=$($AWS resourcegroupstaggingapi get-resources --tag-filters  "Key=soca:FSx,Values=true" "Key=soca:StackId,Values=$AWS_STACK_ID" --query ResourceTagMappingList[].ResourceARN --output text)
        echo "GET_FSX_ARN: " $FSX_ARN
        FSX_ID=$(echo $FSX_ARN | cut -d/ -f2)
        echo "GET_FSX_ID: " $FSX_ID
        echo "export SOCA_FSX_LUSTRE_ID="$FSX_ID" >> /etc/environment"
        ## UPDATE FSX_DNS VALUE MANUALLY IF YOU ARE USING A PERMANENT FSX
        FSX_DNS=$FSX_ID".fsx."$AWS_DEFAULT_REGION".amazonaws.com"

        # Verify if DNS is ready
        CHECK_FSX_STATUS=$($AWS fsx describe-file-systems --file-system-ids $FSX_ID  --query FileSystems[].Lifecycle --output text)
        # Note: We can retrieve FSxL Mount Name even if FSx is not fully ready
        GET_FSX_MOUNT_NAME=$($AWS fsx describe-file-systems --file-system-ids $FSX_ID  --query FileSystems[].LustreConfiguration.MountName --output text)
        LOOP_COUNT=1
        echo "FSX_DNS: " $FSX_DNS
        while [[ "$CHECK_FSX_STATUS" != "AVAILABLE" ]] && [[ $LOOP_COUNT -lt 10 ]]
            do
                echo "FSX does not seems to be on AVAILABLE status yet ... waiting 60 secs"
                sleep 60
                CHECK_FSX_STATUS=$($AWS fsx describe-file-systems --file-system-ids $FSX_ID  --query FileSystems[].Lifecycle --output text)
                echo $CHECK_FSX_STATUS
                ((LOOP_COUNT++))
        done

        if [[ "$CHECK_FSX_STATUS" == "AVAILABLE" ]]; then
            echo "FSx is AVAILABLE"
            echo "$FSX_DNS@tcp:/$GET_FSX_MOUNT_NAME $FSX_MOUNTPOINT lustre defaults,noatime,flock,_netdev 0 0" >> /etc/fstab
        else
            echo "FSx is not available even after 10 minutes timeout, ignoring FSx mount ..."
        fi
    else
        # Using persistent FSX provided by customer
        echo "Detected existing FSx provided by customers " $SOCA_FSX_LUSTRE_DNS
        FSX_ID=$(echo $SOCA_FSX_LUSTRE_DNS | cut -d. -f1)
        GET_FSX_MOUNT_NAME=$($AWS fsx describe-file-systems --file-system-ids $FSX_ID  --query FileSystems[].LustreConfiguration.MountName --output text)
        echo "$SOCA_FSX_LUSTRE_DNS@tcp:/$GET_FSX_MOUNT_NAME $FSX_MOUNTPOINT lustre defaults,noatime,flock,_netdev 0 0" >> /etc/fstab
    fi

    # Install Clients
    if [[ "$SOCA_BASE_OS" == "amazonlinux2" ]]; then
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
              REQUIRE_REBOOT=1
           fi
           ((KERNEL_COUNT++))
        done < /root/kernel_list
    fi

fi

# Tag EBS disks manually as CFN ASG does not support it
AWS_AVAIL_ZONE=$(curl http://169.254.169.254/latest/meta-data/placement/availability-zone)
AWS_REGION="`echo "$AWS_AVAIL_ZONE" | sed "s/[a-z]$//"`"
AWS_INSTANCE_ID=$(curl http://169.254.169.254/latest/meta-data/instance-id)
EBS_IDS=$(aws ec2 describe-volumes --filters Name=attachment.instance-id,Values="$AWS_INSTANCE_ID" --region $AWS_REGION --query "Volumes[*].[VolumeId]" --out text | tr "\n" " ")
LOOP_EBS_TAG=0
$AWS ec2 create-tags --resources $EBS_IDS --region $AWS_REGION --tags Key=Name,Value="EBS for $SOCA_JOB_ID" Key=soca:JobOwner,Value="$SOCA_JOB_OWNER" Key=soca:JobProject,Value="$SOCA_JOB_PROJECT" Key=Name,Value="soca-job-$SOCA_JOB_ID"  Key=soca:JobId,Value="$SOCA_JOB_ID" Key=soca:JobQueue,Value="$SOCA_JOB_QUEUE" Key=soca:ClusterId,Value="$SOCA_CONFIGURATION"
while [[ $? -ne 0 ]] && [[ $LOOP_EBS_TAG -lt 5 ]]
    do
    SLEEP_TIME=$(( RANDOM % 100 ))
    echo "ec2 tag failed due to EC2 API error, retrying in  $SLEEP_TIME seconds  and Loop $LOOP_EBS_TAG/5..."
    sleep $SLEEP_TIME
    ((LOOP_EBS_TAG++))
    $AWS ec2 create-tags --resources $EBS_IDS --region $AWS_REGION --tags Key=Name,Value="EBS for $SOCA_JOB_ID" Key=soca:JobOwner,Value="$SOCA_JOB_OWNER" Key=soca:JobProject,Value="$SOCA_JOB_PROJECT" Key=Name,Value="soca-job-$SOCA_JOB_ID"  Key=soca:JobId,Value="$SOCA_JOB_ID" Key=soca:JobQueue,Value="$SOCA_JOB_QUEUE" Key=soca:ClusterId,Value="$SOCA_CONFIGURATION"
done

# Tag Network Adapter for the Compute Node
ENI_IDS=$(aws ec2 describe-network-interfaces --filters Name=attachment.instance-id,Values="$AWS_INSTANCE_ID" --region $AWS_REGION --query "NetworkInterfaces[*].[NetworkInterfaceId]" --out text | tr "\n" " ")
LOOP_ENI_TAG=0
$AWS ec2 create-tags --resources $ENI_IDS --region $AWS_REGION --tags Key=Name,Value="ENI for $SOCA_JOB_ID" Key=soca:JobOwner,Value="$SOCA_JOB_OWNER" Key=soca:JobProject,Value="$SOCA_JOB_PROJECT" Key=Name,Value="soca-job-$SOCA_JOB_ID"  Key=soca:JobId,Value="$SOCA_JOB_ID" Key=soca:JobQueue,Value="$SOCA_JOB_QUEUE" Key=soca:ClusterId,Value="$SOCA_CONFIGURATION"
while [[ $? -ne 0 ]] && [[ $LOOP_ENI_TAG -lt 5 ]]
    do
    SLEEP_TIME=$(( RANDOM % 100 ))
    echo "ec2 tag failed due to EC2 API error, retrying in  $SLEEP_TIME seconds ... and Loop $LOOP_ENI_TAG/5"
    sleep $SLEEP_TIME
    ((LOOP_ENI_TAG++))
    $AWS ec2 create-tags --resources $ENI_IDS --region $AWS_REGION --tags Key=Name,Value="ENI for $SOCA_JOB_ID" Key=soca:JobOwner,Value="$SOCA_JOB_OWNER" Key=soca:JobProject,Value="$SOCA_JOB_PROJECT" Key=Name,Value="soca-job-$SOCA_JOB_ID"  Key=soca:JobId,Value="$SOCA_JOB_ID" Key=soca:JobQueue,Value="$SOCA_JOB_QUEUE" Key=soca:ClusterId,Value="$SOCA_CONFIGURATION"
done


# Begin USER Customization
/bin/bash /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ComputeNodeUserCustomization.sh >> $SOCA_HOST_SYSTEM_LOG/ComputeNodeUserCustomization.log 2>&1
# End USER Customization

if [[ $REQUIRE_REBOOT -eq 1 ]];
then
    echo "@reboot chmod 777 $FSX_MOUNTPOINT" | crontab -
    reboot
else
    # Mount
    mount -a
    echo "chmod FSX"
    chmod 777 $FSX_MOUNTPOINT
    # Post-Boot routine completed, starting PBS
    systemctl start pbs
fi


