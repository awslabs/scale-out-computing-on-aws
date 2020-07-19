---
title: Knowledge Base - List all Errors
---

This page only list errors related to CloudFormation. [Submit a ticket if your error is not listed here](https://github.com/awslabs/scale-out-computing-on-aws/issues)

!!!note "CloudFormation troubleshooting"
    We recommend to [disable "RollBack on Failure"](https://aws.amazon.com/premiumsupport/knowledge-center/cloudformation-prevent-rollback-failure/) to simplify CloudFormation debugging/troubleshooting
    
### Errors during Stack Creation

#### C1: The following resource(s) failed to create: CheckSOCAPreRequisite.
    - Stack: Primary Template
    - Event: Failed to create resource. See the details in CloudWatch Log Stream: 2020/03/17/[$LATEST]xxxxx
    - Resolution: Refer to the Physical ID message. It's could be because you used uppercase in the stack name, have a stack name longer than 20 chars or use a non-supported AWS region


### Errors during Stack Deletion

#### D1: Cannot delete entity, must delete policies first.
    - Stack: Security
    - Event:  Cannot delete entity, must delete policies first. (Service: AmazonIdentityManagement; Status Code: 409; Error Code: DeleteConflict; Request ID: x)
    - Resolution: You have added extra policies to the IAM roles created by SOCA. Remove the policy or delete the role entirely

#### D2: Backup vault cannot be deleted (contains <NUMBER> recovery points) 
    - Stack: Configuration
    - Event: Backup vault cannot be deleted (contains 3 recovery points) (Service: AWSBackup; Status Code: 400; Error Code: InvalidRequestException; Request ID:  x)
    - Resolution: You must manually remove the recovery points from your SOCA Backup Vault
    

### Errors Post Deployment

#### P1: Why do I see "502 Bad Gateway" when I try to log into the SOCA web UI?
    - Resolution: This error indicates that they web server is not running on the scheduler server.  If you just installed SOCA, wait until you can log into the scheduler server before trying to access the management web UI.


