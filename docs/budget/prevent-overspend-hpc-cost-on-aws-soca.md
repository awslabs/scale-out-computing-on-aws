---
title: Keep control of your HPC cost on AWS
---

Scale-Out Computing on AWS offers multiple ways to make sure you will stay within budget while running your HPC workloads on AWS

## Limit who can submit jobs

Only allow specific individual users or/and LDAP groups to submit jobs. [Refer to this page for examples and documentation](../../security/manage-queue-acls/)


## Limit what type of EC2 instance can be provisioned 

Control what type of EC2 instances can be provisioned for any given queue. [Refer to this page for examples and documentation](../../security/manage-queue-instance-types/)

!!!info "Accelerated Computing Instances"
    Unless required for your workloads, it's recommended to exclude "p2", "p3", "g2", "g3", "p3dn" or other GPU instances type. 

## Create a budget

Creating an AWS Budget will ensure jobs can't be submitted if the budget allocated to the team/queue/project has exceeded the authorized amount.
[Refer to this page for examples and documentation](../../analytics/set-up-budget-project/)

## Review your HPC cost in a central dashboard

Stay on top of your AWS costs in real time. Quickly visualize your overall usage and find answers to your most common questions:

- Who are my top users?

- How much money did we spend for Project A?

- How much storage did we use for Queue B?

- Where my money is going (storage, compute ...)

- Etc ...
  
[Refer to this page for examples and documentation](../../analytics/review-hpc-costs/)

## Best practices

Assuming you are on-boarding a new team, here are our recommend best practices:

1 - [Create LDAP account for all users](../../tutorials/manage-ldap-users/#add-users)

2 - [Create LDAP group for the team. Add all users to the group](../../tutorials/manage-ldap-users/#other-ldap-operations)

3 - [Create a new queue](../../tutorials/create-your-own-queue/#queue-with-automatic-instance-provisioning)

4 - [Limit the queue to the LDAP group you just created](../../security/manage-queue-acls/#manage-acls-using-ldap-groups)

5 - [Limit the type of EC2 instances your users can provision](../../security/manage-queue-instance-types/)

6 - [If needed, configure restricted parameters](../../security/manage-queue-restricted-parameters/)

7 - [Create a Budget to make sure the new team won't spend more than what's authorized](../../analytics/set-up-budget-project/)