#!/usr/bin/bash

##
#
# aligo.sh start|stop|status
#
##

source /etc/environment
GUNICORN_BIN="/apps/soca/$SOCA_CONFIGURATION/python/latest/bin/gunicorn"
GUNICORN_BIND='0.0.0.0:8443'
GUNICORN_WORKERS=3
GUNICORN_APP='app:app'

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

cd `dirname "$0"`
status ()
    {
    status_check_process=`ps aux | grep gunicorn | grep $GUNICORN_APP | awk '{print $2}'`
    }

if [[ $# -eq 0 ]] ; then
    echo 'Usage: socawebui.sh start|stop|status'
    exit 0
fi

case "$1" in
    ## START
    start)

    ## Create the structure if does not exist
    mkdir -p tmp/ssh
    mkdir -p tmp/dcv_sessions

    status
        if [[ -z $status_check_process ]]; then
            echo 'Starting SOCA'
            if [[ ! -f flask_secret_key.txt ]]; then
                echo 'No Flask Key detected, creating new one ...'
                cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1 > flask_secret_key.txt
                chmod 600 flask_secret_key.txt
            fi
            export FLASK_SECRET_KEY=$(cat flask_secret_key.txt)
            $GUNICORN_BIN $GUNICORN_APP -b $GUNICORN_BIND --workers $GUNICORN_WORKERS --log-level warning --certfile cert.crt --keyfile cert.key --log-file application_output.log --daemon

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