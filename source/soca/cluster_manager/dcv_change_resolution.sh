#!/bin/bash

######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

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