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

"""
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
"""

import sys
import pbs

if (
    "/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.9/site-packages"
    not in sys.path
):
    sys.path.append(
        "/apps/soca/%SOCA_CONFIGURATION/python/latest/lib/python3.9/site-packages"
    )

import boto3
import socket
import re
import os

# User Variables - Change them
ses_sender_email = "<SES_SENDER_EMAIL_ADDRESS_HERE>"
ses_region = "<YOUR_SES_REGION_HERE>"


def send_notification(subject, email_message, job_owner_email_address):
    try:
        ses_client = boto3.client("ses", region_name=ses_region)
        ses_client.send_email(
            Source=ses_sender_email,
            Destination={
                "ToAddresses": [
                    job_owner_email_address,
                ]
            },
            Message={
                "Subject": {
                    "Data": subject,
                },
                "Body": {
                    "Html": {
                        "Data": email_message,
                    }
                },
            },
        )
        pbs.logmsg(pbs.LOG_DEBUG, "notify_job_status: SES output" + str(ses_client))
    except Exception as err:
        pbs.logmsg(pbs.LOG_DEBUG, "notify_job_status: Error sending email" + str(err))


def find_email(job_owner):
    # Ideally we should be using python-ldap, but facing some issue importing it with PBS env as PBS py is still py2
    # Will migrate to python-ldap when pbspro supports py3 natively
    if os.path.isdir(
        "/apps/soca/%SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation"
    ):
        pbs.logmsg(
            pbs.LOG_DEBUG,
            "queue_acl: find_users_in_ldap_group: Detected Active Directory",
        )
        # Active Directory
        with open(
            "/apps/soca/%SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain_user.cache",
            "r",
        ) as f:
            ad_user = f.read()
        with open(
            "/apps/soca/%SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/join_domain.cache",
            "r",
        ) as f:
            ad_password = f.read()
        with open(
            "/apps/soca/%SOCA_CONFIGURATION/cluster_node_bootstrap/ad_automation/domain_name.cache",
            "r",
        ) as f:
            domain_name = f.read()
            search_base = "DC=" + ",DC=".join(domain_name.split("."))

        get_email = (
            'ldapsearch -x -h "'
            + domain_name
            + '" -D "'
            + ad_user
            + "@"
            + domain_name
            + '" -w "'
            + ad_password
            + '" -b "'
            + search_base
            + '" "cn='
            + job_owner
            + '" | grep "mail:" | cut -d " " -f2'
        )
        pbs.logmsg(
            pbs.LOG_DEBUG,
            "notify_job_status: generated get_email command: "
            + get_email.replace(ad_password, "<REDACTED_PASSWORD>"),
        )
    else:
        # OpenLdap
        pbs.logmsg(
            pbs.LOG_DEBUG, "queue_acl: find_users_in_ldap_group: Detected OpenLDAP"
        )
        get_email = (
            "ldapsearch -x -LLL uid=" + job_owner + ' | grep "mail:" | cut -d " " -f2'
        )
        pbs.logmsg(
            pbs.LOG_DEBUG,
            "notify_job_status: generated get_email command: " + get_email,
        )

    email_address = os.popen(get_email).read()  # nosec
    pbs.logmsg(
        pbs.LOG_DEBUG,
        "notify_job: Detected email for " + job_owner + " : " + email_address,
    )
    return email_address.replace("\n", "")


# Begin Logic
pbs.logmsg(pbs.LOG_DEBUG, "notify_job_status: Start")
host = (socket.gethostname()).split(".")[0]
e = pbs.event()
j = e.job
job_owner = str(j.euser)
job_name = str(j.Job_Name)
job_id = str(j.id).split(".")[0]
job_queue = str(j.queue)
ignore = False
job_owner_email_address = find_email(job_owner)

if job_owner_email_address == "":
    ignore = True
    pbs.logmsg(
        pbs.LOG_DEBUG,
        "notify_job_status: Unable to detect email address for " + job_owner,
    )

if ignore is False:
    if e.type == pbs.RUNJOB:
        pbs.logmsg(pbs.LOG_DEBUG, "notify_job_status: RUNJOB")
        email_subject = (
            "[SOCA - Job Started] " + job_name + " (" + job_id + ") has started"
        )
        email_message = (
            """
            Hello """
            + job_owner
            + """, <br><br>
            This email is to notify you that your job <strong>"""
            + job_id
            + """</strong> has started.<br>
            You will receive an email once your simulation is complete.
    
            <h3> Job Information </h3>
            <ul>
                <li> Job Id: """
            + job_id
            + """</li>
                <li> Job Name: """
            + job_name
            + """</li>
                <li> Job Queue: """
            + job_queue
            + """</li>
            </ul>
            <hr>
            <i> Automatic email, do not respond. </i>
        """
        )
        send_notification(email_subject, email_message, job_owner_email_address)

    if e.type == pbs.EXECJOB_END:
        pbs.logmsg(pbs.LOG_DEBUG, "notify_job_status: EXECJOB_END")
        regex_vnode = r"\(.*?\)"
        exec_vnode = str(j.exec_vnode)
        vnode_list = re.findall(r"\(.*?\)", exec_vnode)
        if host in vnode_list[0]:
            # execjob_end is executed on all execution host. To prevent multiple submissions, we simply execute the job only on the first host
            email_subject = "[SOCA - Job Completed] " + job_name + " (" + job_id + ")"
            email_message = (
                """
                Hello """
                + job_owner
                + """, <br><br>
                This email is to notify you that your job <strong>"""
                + job_id
                + """</strong> has completed.<br>
                
                <h3> Job Information </h3>
                <ul>
                    <li> Job Id: """
                + job_id
                + """</li>
                    <li> Job Name: """
                + job_name
                + """</li>
                    <li> Job Queue: """
                + job_queue
                + """</li>
                </ul>
    
                <hr>
                <i> Automatic email, do not respond.</i>
            """
            )
            send_notification(email_subject, email_message, job_owner_email_address)
