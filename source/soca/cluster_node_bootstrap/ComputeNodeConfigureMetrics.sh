#!/bin/bash -xe

# Make sure to update your ELK Access Policy if you do not use the default environment and have configured multiple NAT gateway


source /etc/environment
source /root/config.cfg
cd /root

# Checks. You can combine with $SOCA_JOB_QUEUE (or other) to specify different periods for different app/queue
SYSTEM_CHECK_PERIOD="3m"  # check system (network, cpus, memory, process) every 3 minutes
FS_CHECK_PERIOD="3m" # check filesystem every 3 minutes
PROCESS_COUNT_TO_TRACK=15 # how many process do you want to return on the web ui

if [[ $SOCA_SYSTEM_METRICS == "true" ]];
then
  echo "Installing and configuring MetricBeat"
  wget $METRICBEAT_URL
  if [[ $(md5sum $METRICBEAST_RPM | awk '{print $1}') != $METRICBEAT_HASH ]];  then
    echo -e "FATAL ERROR: Checksum for metricbeat failed. File may be compromised."
    exit 1
  fi

  sudo rpm -vi $METRICBEAST_RPM
  METRICBEAT=$(which metricbeat)

  # Copy custom SOCA configuration file
  cp /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/metricbeat/system.yml /etc/metricbeat/modules.d/
  sed -i "s/%SYSTEM_CHECK_PERIOD%/$SYSTEM_CHECK_PERIOD/g" /etc/metricbeat/modules.d/system.yml
  sed -i "s/%FS_CHECK_PERIOD%/$FS_CHECK_PERIOD/g" /etc/metricbeat/modules.d/system.yml
  sed -i "s/%PROCESS_COUNT_TO_TRACK%/$PROCESS_COUNT_TO_TRACK/g" /etc/metricbeat/modules.d/system.yml

  # Enable AWS module (only if using commercial binary)
  # $METRICBEAT module enable aws

  # First deployment only. Initialize the dashboard (this will take 2 or 3 minutes max, and it's one time thing)
  if [[ ! -f "/apps/soca/$SOCA_CONFIGURATION/cluster_analytics/metricbeat/.dashboard_initialized" ]];
  then
    echo "No dashboard configured, first installation detected"
    $METRICBEAT setup --dashboards -E "setup.kibana.host='https://$SOCA_ESDOMAIN_ENDPOINT:443/_plugin/kibana'" \
    -E "output.elasticsearch.hosts=['https://$SOCA_ESDOMAIN_ENDPOINT:443']" \
    -E "setup.ilm.enabled='false'"
    touch /apps/soca/$SOCA_CONFIGURATION/cluster_analytics/metricbeat/.dashboard_initialized
  fi

  # Start MetricBeat in background
  $METRICBEAT run -E "setup.kibana.host='https://$SOCA_ESDOMAIN_ENDPOINT:443/_plugin/kibana'" \
      -E "output.elasticsearch.hosts=['https://$SOCA_ESDOMAIN_ENDPOINT:443']" \
      -E "setup.ilm.enabled='false'" \
      -E "fields.job_id='$SOCA_JOB_ID'" \
      -E "fields.job_owner='$SOCA_JOB_OWNER'" \
      -E "fields.job_name='$SOCA_JOB_NAME'" \
      -E "fields.job_project='$SOCA_JOB_PROJECT'" \
      -E "fields.job_queue='$SOCA_JOB_QUEUE'" \
      -E "tags=['$SOCA_JOB_ID','$SOCA_JOB_OWNER','$SOCA_JOB_NAME','$SOCA_JOB_PROJECT', '$SOCA_JOB_QUEUE']" &

else
  echo "MetricBeat disabled for this run "
fi