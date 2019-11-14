#!/bin/bash

X=$1
Y=$2
XRANDR=$(which xrandr)
GTF=$(which gtf)
if [ "$#" -ne 2 ]; then
    echo "Usage: change_resolution.sh <horizontal> <vertical>"
    echo "Ex: change_resolution.sh 800 600"
    exit
fi
modeline=$($GTF $X $Y  60 | sed -n 's/^\s*Modeline\s.*"\s\+//p')
$XRANDR --newmode $X_$Y $modeline
$XRANDR --addmode VNC-output-0 $X_$Y
$XRANDR --output VNC-output-0 --mode $X_$Y