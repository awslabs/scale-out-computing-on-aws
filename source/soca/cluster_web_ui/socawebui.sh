#!/usr/bin/bash

##
#
# socawebui.sh start|stop|status
#
##

source /etc/environment
UWSGI_BIN="/apps/soca/$SOCA_CONFIGURATION/python/latest/bin/uwsgi"
UWSGI_BIND='0.0.0.0:8443'

UWSGI_PROCESSES=5
UWSGI_THREADS=$(cat  /proc/cpuinfo | grep processor | wc -l)
UWSGI_FILE='wsgi.py'
BUFFER_SIZE=32768

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

cd `dirname "$0"`
status ()
    {
    status_check_process=`ps aux | grep uwsgi | grep $UWSGI_FILE | awk '{print $2}'`
    }

if [[ $# -eq 0 ]] ; then
    echo 'Usage: socawebui.sh start|stop|status'
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
        if [[ -z $status_check_process ]]; then
            echo 'Starting SOCA'
            if [[ ! -f flask_secret_key.txt ]]; then
                echo 'No Flask Key detected, creating new one ...'
                cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1 > flask_secret_key.txt
                chmod 600 flask_secret_key.txt
            fi
            if [[ ! -f dcv_secret_key.txt ]]; then
                echo 'No dcv Key detected, creating new one ...'
                # /!\ ATTENTION
                # DCV Secret Key used to authenticate DCV sessions via /api/system/dcv_authenticator.
                # If you delete/change this value, your existing sessions will become inaccessible and your user must re-create them
                dd if=/dev/urandom bs=32 count=1 2>/dev/null | openssl base64 > dcv_secret_key.txt
                chmod 600 dcv_secret_key.txt
            fi

            export SOCA_FLASK_SECRET_KEY=$(cat flask_secret_key.txt)
            export SOCA_DCV_TOKEN_SYMMETRIC_KEY=$(cat dcv_secret_key.txt)

            # Creating unique, random and temp credentials
            export SOCA_FLASK_FERNET_KEY=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | openssl base64)
            export SOCA_FLASK_API_ROOT_KEY=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)

            # Launching process
            $UWSGI_BIN --master --https $UWSGI_BIND,cert.crt,cert.key --wsgi-file $UWSGI_FILE --processes $UWSGI_PROCESSES --threads $UWSGI_THREADS --daemonize logs/uwsgi.log --enable-threads --buffer-size $BUFFER_SIZE --check-static /apps/soca/$SOCA_CONFIGURATION/cluster_web_ui/static

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
    ## STATUS
    status)
        status
        if [[ -z $status_check_process ]]; then
            echo 'SOCA is not running'
        else
           echo 'SOCA is running with PIDs: ' $status_check_process

        fi


     ;;
    *) echo 'Usage: socawebui.sh start|stop|status' ;;
esac