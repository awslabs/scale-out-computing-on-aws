#!/apps/python/latest/bin/python3

'''
This hook output resource_user.instance_type_used to the current EC2 instance type to the accounting logs

create hook soca_aws_infos event=execjob_begin
import hook soca_aws_infos application/x-python default /apps/soca/cluster_hooks/execjob_begin/soca_aws_infos.py
'''

import pbs
import sys

if "/apps/python/latest/lib/python3.7/site-packages" not in sys.path:
    sys.path.append("/apps/python/latest/lib/python3.7/site-packages/")

import urllib2
import socket
import re

pbs.logmsg(pbs.LOG_DEBUG, 'soca_aws_infos: start')
instance_type = urllib2.urlopen("http://169.254.169.254/latest/meta-data/instance-type").read()
instance_type = instance_type.replace('.', '_')
pbs.logmsg(pbs.LOG_DEBUG, 'soca_aws_infos: detected instance: ' + str(instance_type))
e = pbs.event()
j = e.job
host = (socket.gethostname()).split('.')[0]
regex_vnode = r'\(.*?\)'
exec_vnode = str(j.exec_vnode)
vnode_list = re.findall('\(.*?\)', exec_vnode)
if host in vnode_list[0]:
    pbs.logmsg(pbs.LOG_DEBUG, 'soca_aws_infos: detected host, about to specify new resource used')
    try:
        j.resources_used["instance_type_used"] = str(instance_type)
        pbs.logmsg(pbs.LOG_DEBUG, 'soca_aws_infos: List all resource used for the job: ' + str(j.resources_used))
    except Exception as e:
        pbs.logmsg(pbs.LOG_DEBUG, 'soca_aws_infos: unable to set up resource instance_type_used: ' +str(e))



