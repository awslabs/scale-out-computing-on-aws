'''
Job submitted MUST have a project defined ( qsub -P <project_name>)

create hook reject_if_no_project event=queuejob
import hook reject_if_no_project application/x-python default </path/to/your/hook.py>
'''

#!/usr/bin/env python

import pbs
import sys

if "/usr/lib/python2.7/site-packages" not in sys.path:
    sys.path.append("/usr/lib/python2.7/site-packages")

if "/usr/lib64/python2.7/site-packages" not in sys.path:
    sys.path.append("/usr/lib64/python2.7/site-packages")


e = pbs.event()
j = e.job
project = j.project
queue = str(j.queue)

if project is None:
    e.reject("No project detected, your job has been cancelled.\n. Please specify a project using -P argument")
