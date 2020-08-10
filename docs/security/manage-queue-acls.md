---
title: Manage Access Lists at queue level
---

You can manage ACLs for each queue by configuring both `allowed_users` or `excluded_users`. 

These parameters can be configured as:

 - List of allowed/excluded users: `allowed_users: ["user1", "user2"]`
 - List of LDAP groups: `allowed_users: ["cn=mynewgroup,ou=Group,dc=soca,dc=local"]`
 - List of username and LDAP groups: `allowed_users: ["user1", "cn=mynewgroup,ou=Group,dc=soca,dc=local", "user2"]`

## Restrict queue for some users

Considering `/apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml`
```
queue_type:
  compute:
    queues: ["normal"]
    allowed_users: [] # empty list = all users can submit job 
    excluded_users: [] # empty list = no restriction, ["*"] = only allowed_users can submit job
    ... 
  test:
    queues: ["high", "low"]
    allowed_users: [] 
    excluded_users: ["user1"] 
```

In this example, `user1` can submit a job to "normal" queue but not on "high" or "low" queues.

~~~console
# Job submission does not work on "high" queue because user1 is on the excluded_users list pattern
qsub -q high -- /bin/sleep 60
qsub: user1 is not authorized to use submit this job on the queue high. Contact your HPC admin and update /apps/soca/$SOCA_CONFIGURATION/cluster_manager/settings/queue_mapping.yml

# Job submission is ok on "normal" queue
qsub -q normal -- /bin/sleep 60
19.ip-30-0-2-29
~~~

!!!note "`allowed_users` overrides `excluded_users`"
    Job will go through if a user is present is both `allowed_users` and `excluded_users` lists.

## Restrict the queue for everyone except `allowed_users`

`excluded_users: ["*"]` will prevent anyone to use the queue except for the list of `allowed_users`. 

In the example below, `user1` is the only user authorized to submit job.

```
queue_type:
  compute:
    queues: ["normal"]
    allowed_users: ["user1"]
    excluded_users: ["*"]
```


## Manage ACLs using LDAP groups

SOCA will consider `allowed_users` or `excluded_users` as LDAP group if you did not specify them as list.

Create a text file `mynewgroup.ldif` and add the following content (note we are adding our `user1` as a group member)

~~~console hl_lines="6"
dn: cn=mynewgroup,ou=Group,dc=soca,dc=local
objectClass: top
objectClass: posixGroup
cn: mynewgroup
gidNumber: 6000
memberUid: user1
~~~

Create the group using `ldapadd` command

~~~console
~ ldapadd -x -D cn=admin,dc=soca,dc=local -y /root/OpenLdapAdminPassword.txt -f mynewgroup.ldif
adding new entry "cn=mynewgroup,ou=Group,dc=soca,dc=local"
~~~

Run `ldapsearch` command to confirm your group has been created correctly and your `user1` is part of it

~~~console hl_lines="7"
~ ldapsearch -x -b cn=mynewgroup,ou=Group,dc=soca,dc=local -LLL
dn: cn=mynewgroup,ou=Group,dc=soca,dc=local
objectClass: top
objectClass: posixGroup
cn: mynewgroup
gidNumber: 6000
memberUid: user1
~~~

Let's configure our queue to reject all users:

~~~console
allowed_users: []
excluded_users: ["*"]
~~~

Confirm `user1` can't submit any job:

~~~console
qsub -q high -- /bin/sleep 60
qsub: user1 is not authorized to use submit this job on the queue high. Contact your HPC admin and update /apps/soca/cluster_manager/settings/queue_mapping.yml
~~~

Edit your `allowed_users` and specify your LDAP group:

~~~
allowed_users: ["cn=mynewgroup,ou=Group,dc=soca,dc=local"]
excluded_users: ["*"]
~~~

Verify `user1` can submit job:
~~~
qsub -q high -- /bin/sleep 60
22.ip-30-0-2-29
~~~

Let's now assume you have a `user2`. Confirm this user can't submit job

~~~
qsub -q high -- /bin/sleep 60
qsub: user2 is not authorized to use submit this job on the queue high. Contact your HPC admin and update /apps/soca/cluster_manager/settings/queue_mapping.yml
~~~

Create a new ldif file (add_new_user.ldif) and add `user2` to your group
~~~ hl_lines="3 4"
dn: cn=mynewgroup,ou=Group,dc=soca,dc=local
changetype: modify
add: memberUid
memberUid: user2
~~~

Execute the command
~~~console
~ ldapadd -x -D cn=admin,dc=soca,dc=local -y /root/OpenLdapAdminPassword.txt -f add_new_user.ldif
modifying entry "cn=mynewgroup,ou=Group,dc=soca,dc=local
~~~

Confirm both users are part of the group:
~~~console hl_lines="7 8"
ldapsearch -x -b cn=mynewgroup,ou=Group,dc=soca,dc=local -LLL
dn: cn=mynewgroup,ou=Group,dc=soca,dc=local
objectClass: top
objectClass: posixGroup
cn: mynewgroup
gidNumber: 6000
memberUid: user1
memberUid: user2
~~~

Finally, confirm `user2` is now authorized to submit job:
~~~
qsub -q high -- /bin/sleep 60
23.ip-30-0-2-29
~~~

On the other side, you can also prevent users from a LDAP group to use the queue by specifying the ldap group as "excluded_users"
~~~
allowed_users: []
excluded_users: ["cn=mynewgroup,ou=Group,dc=soca,dc=local"]
~~~

## Check the logs
Scheduler hooks are located on /var/spool/pbs/server_logs/

## Code
The hook file can be found under `/apps/soca/cluster_hooks/$SOCA_CONFIGURATION/queuejob/check_queue_acls.py` on your Scale-Out Computing on AWS cluster)

## Disable the hook
You can disable the hook by running the following command on the scheduler host (as root):

~~~bash
user@host: qmgr -c "delete hook check_queue_acls event=queuejob"
~~~