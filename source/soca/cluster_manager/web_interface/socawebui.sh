#!/usr/bin/bash
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


#
# socawebui.sh start|stop|status|restart
#


source "/etc/environment"
source "/opt/soca/${SOCA_CLUSTER_ID}/python/latest/soca_python.env"
UWSGI_BIN="/opt/soca/${SOCA_CLUSTER_ID}/python/latest/bin/uwsgi"
UWSGI_BIND='0.0.0.0:8443'

UWSGI_PROCESSES=5
UWSGI_THREADS=$(nproc)
UWSGI_FILE='wsgi.py'
BUFFER_SIZE=32768
export PYTHONPATH=/opt/soca/${SOCA_CLUSTER_ID}/cluster_manager/
#
# Select UWSGI options to build the command-line
#
# Stats
UWSGI_OPTIONS+="--stats 127.0.0.1:9191 "
# Produce memory reporting in stats
UWSGI_OPTIONS+="--memory-report "
# Log the X-Forwarded-for instead of the ELB source IP addresses
UWSGI_OPTIONS+="--log-x-forwarded-for "
# Allow offloading threads
UWSGI_OPTIONS+="--offload-threads ${UWSGI_THREADS} "
# Allow logging via threaded logger
UWSGI_OPTIONS+="--threaded-logger "
# Log in microseconds
UWSGI_OPTIONS+="--log-micros "
# Needed for proper shutdown
UWSGI_OPTIONS+="--die-on-term "

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

cd $(dirname "$0")
status ()
    {
    status_check_process=$(ps aux | grep uwsgi | grep $UWSGI_FILE | awk '{print $2}')
    }

if [[ $# -eq 0 ]] ; then
    echo 'Usage: socawebui.sh start|stop|restart|status'
    exit 0
fi

case "$1" in
    ## START
    start)

    ## Create the structure if does not exist
    if [[ ! -d "tmp/" ]]; then
      echo "First configuration: Creating tmp/ folder structure, please wait 10 seconds"
      mkdir -p tmp/ssh
      mkdir -p tmp/zip_downloads
      chmod 700 tmp/
      sleep 10
    fi

    ## Create the structure if does not exist
    if [[ ! -d "logs/" ]]; then
      echo "First configuration: Creating logs/ folder structure, please wait 10 seconds"
      mkdir -p logs/
      chmod 700 logs/
      sleep 10
    fi


    status
    mkdir -p keys
    chmod 600 keys
    if [[ -z $status_check_process ]]; then
        echo 'Starting SOCA'
        if [[ ! -f keys/flask_secret_key.txt ]]; then
            echo 'No Flask Key detected, creating new one ...'
            tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 32 > keys/flask_secret_key.txt
            chmod 600 keys/flask_secret_key.txt
            sleep 5
        fi

        if [[ ! -f keys/dcv_secret_key.txt ]]; then
            echo 'No dcv Key detected, creating new one ...'
            # /!\ ATTENTION
            # DCV Secret Key used to authenticate DCV sessions via /api/system/dcv_authenticator.
            # If you delete/change this value, your existing sessions will become inaccessible and your user must re-create them
            dd if=/dev/urandom bs=32 count=1 2>/dev/null | openssl base64 > keys/dcv_secret_key.txt
            chmod 600 keys/dcv_secret_key.txt
            sleep 5
        fi

        export SOCA_FLASK_SECRET_KEY=$(cat keys/flask_secret_key.txt)
        export SOCA_DCV_TOKEN_SYMMETRIC_KEY=$(cat keys/dcv_secret_key.txt)

        # Creating unique, random and temp credentials
        export SOCA_FLASK_FERNET_KEY=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | openssl base64)
        tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 32 > keys/admin_api_key.txt
        chmod 600 keys/admin_api_key.txt
        export SOCA_FLASK_API_ROOT_KEY=$(cat keys/admin_api_key.txt)

        # Launching process
        $UWSGI_BIN --master --https $UWSGI_BIND,cert.crt,cert.key --wsgi-file $UWSGI_FILE --processes $UWSGI_PROCESSES --log-maxsize 104857600 --threads $UWSGI_THREADS --daemonize logs/uwsgi.log --enable-threads --buffer-size $BUFFER_SIZE --check-static /opt/soca/${SOCA_CLUSTER_ID}/cluster_manager/web_interface/static  --check-static /opt/soca/${SOCA_CLUSTER_ID}/cluster_manager/web_interface/templates ${UWSGI_OPTIONS}

    else
       echo 'SOCA is already running with PIDs: ' $status_check_process
        echo 'Run "socawebui.sh stop" first.'
    fi

    ;;
    ## STOP
    stop)
    status
    if [[ -z $status_check_process ]]; then
           echo 'SOCA is not running'
       else
          kill -9 $status_check_process


       fi
    ;;
    ## RESTART
    restart)
        echo 'Restarting SOCA...'
        $0 stop
        sleep 3
        $0 start
        echo 'SOCA restarted successfully.'
    ;;
    ## STATUS
    status)
        status
        if [[ -z $status_check_process ]]; then
            echo 'SOCA is not running'
        else
           echo 'SOCA is running with PIDs: ' $status_check_process

        fi


     ;;
    *) echo 'Usage: socawebui.sh start|stop|restart|status' ;;
esac