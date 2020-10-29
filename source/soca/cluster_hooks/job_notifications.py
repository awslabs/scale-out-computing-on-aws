'''
Update ses_sender_email with your SES user. https://awslabs.github.io/scale-out-computing-on-aws/tutorials/job-start-stop-email-notification/ for help
If SES verified your domain, you can use any address @yourdomain
If SES verified only some addresses, you can only use these specific addresses
--
Update ses_region with the region where you configured SES (may be different with the region you are launching instances)
****
Scheduler Hook (qmgr):
create hook notify_job_start event=runjob
create hook notify_job_complete event=execjob_end
import hook notify_job_start application/x-python default /apps/soca/%SOCA_CONFIGURATION/cluster_hooks/job_notifications.py
import hook notify_job_complete application/x-python default /apps/soca/%SOCA_CONFIGURATION/cluster_hooks/job_notifications.py
'''

import sys
import pbs

if "/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.7/site-packages" not in sys.path:
    sys.path.append("/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.7/site-packages")

import boto3
import socket
import re
import os


def send_notification(subject, email_message, job_owner_email_address):
    try:
        ses_client = boto3.client('ses', region_name=ses_region)
        ses_client.send_email(
            Source=ses_sender_email,
            Destination={
                'ToAddresses': [
                    job_owner_email_address,
                ]},
            Message={
                'Subject': {
                    'Data': subject,
                },
                'Body': {
                    'Html': {
                        'Data': email_message,
                    }
                }}, )
        pbs.logmsg(pbs.LOG_DEBUG, 'notify_job_status: SES output' + str(ses_client))
    except Exception as err:
        pbs.logmsg(pbs.LOG_DEBUG, 'notify_job_status: Error sending email' + str(err))


def find_email(job_owner):
    # Ideally we should be using python-ldap, but facing some issue importing it with PBS env as PBS py is still py2
    # Will migrate to python-ldap when pbspro supports py3 natively
    cmd = 'ldapsearch -x -b "ou=People,dc=soca,dc=local" -LLL "(uid='+job_owner+')" mail | grep "mail:" | cut -d " " -f 2'
    email_address = os.popen(cmd).read()
    pbs.logmsg(pbs.LOG_DEBUG, 'notify_job: Detected email for ' + job_owner + ' : ' + email_address)
    return email_address.replace('\n', '')


# User Variables
ses_sender_email = '<SES_SENDER_EMAIL_ADDRESS_HERE>'
ses_region = '<YOUR_SES_REGION_HERE>'

# Begin Logic
pbs.logmsg(pbs.LOG_DEBUG, 'notify_job_status: Start')
host = (socket.gethostname()).split('.')[0]
e = pbs.event()
j = e.job
job_owner = str(j.euser)
job_name = str(j.Job_Name)
job_id = str(j.id).split('.')[0]
job_queue = str(j.queue)
ignore = False
job_owner_email_address = find_email(job_owner)

if job_owner_email_address == '':
    ignore = True
    pbs.logmsg(pbs.LOG_DEBUG, 'notify_job_status: Unable to detect email address for ' + job_owner)

if ignore is False:
    if e.type == pbs.RUNJOB:
        pbs.logmsg(pbs.LOG_DEBUG, 'notify_job_status: RUNJOB')
        email_subjet = '[SOCA - Job Started] ' + job_name + ' (' + job_id + ') has started'
        email_message = '''
            Hello ''' + job_owner + ''', <br><br>
            This email is to notify you that your job <strong>''' + job_id + '''</strong> has started.<br>
            You will receive an email once your simulation is complete.
    
            <h3> Job Information </h3>
            <ul>
                <li> Job Id: ''' + job_id + '''</li>
                <li> Job Name: ''' + job_name + '''</li>
                <li> Job Queue: ''' + job_queue + '''</li>
            </ul>
            <hr>
            <i> Automatic email, do not respond. </i>
        '''
        send_notification(email_subjet, email_message, job_owner_email_address)

    if e.type == pbs.EXECJOB_END:
        pbs.logmsg(pbs.LOG_DEBUG, 'notify_job_status: EXECJOB_END')
        regex_vnode = r'\(.*?\)'
        exec_vnode = str(j.exec_vnode)
        vnode_list = re.findall('\(.*?\)', exec_vnode)
        if host in vnode_list[0]:
            # execjob_end is executed on all execution host. To prevent multiple submissions, we simply execute the job only on the first host
            email_subjet = '[SOCA - Job Completed] ' + job_name + ' (' + job_id + ')'
            email_message = '''
                Hello ''' + job_owner + ''', <br><br>
                This email is to notify you that your job <strong>''' + job_id + '''</strong> has completed.<br>
                
                <h3> Job Information </h3>
                <ul>
                    <li> Job Id: ''' + job_id + '''</li>
                    <li> Job Name: ''' + job_name + '''</li>
                    <li> Job Queue: ''' + job_queue + '''</li>
                </ul>
    
                <hr>
                <i> Automatic email, do not respond.</i>
            '''
            send_notification(email_subjet, email_message, job_owner_email_address)
