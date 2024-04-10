function tags_ebs_volumes {
  echo "[BEGIN] tags_ebs_volumes"
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
  echo "[COMPLETED] tags_ebs_volumes"
}

function tags_eni {
  echo "[BEGIN] tags_eni"
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
  echo "[COMPLETED] tags_eni"
}