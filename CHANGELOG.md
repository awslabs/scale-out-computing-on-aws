# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2020-03-18
### Added

- Support for MixedInstancePolicy and InstanceDistribution
- Support for non-EBS optimized instances such as t2
- Integration of AWS Session Manager
- Integration of AWS Backup
- Integration of AWS Cognito
- Integration of Troposphere
- Admins can now manage ACL (individual/LDAP groups) at queue level
- Admins can now restrict specific type/family of instance at queue level
- Admins can now prevent users to change specific EC2 parameters
- Users can now install SOCA using existing resources such as VPC, Security Groups ...
- Users now have the ability to retain EBS disks associated to a simulation for debugging purposes
- SOCA now prevent jobs to be submitted if .yaml configuration files are malformed
- Scheduler Root EBS is now tagged with cluster ID 
- Scheduler Network Interface is now tagged with cluster ID 
- Scheduler and Compute hosts are now sync with Chrony (Amazon Time Sync)
- Support for FSx for Lustre new Scratch2/Scratch1 and Persistent mode
- Added Compute nodes logs on EFS (/apps/soca/<cluster_id>/cluster_node_bootstrap/logs/<job_id>/<host>/*.log) for easy debugging

### Changed

- Ignore installation if PBSPro is already configured on the AMI
- Fixed bug when stack name only use uppercase
- ComputeNode bootstrap scripts are now loaded from EFS
- Users can now open a SSH session using SSM Session Manager
- Processes are now automatically launched upon scheduler reboot 
- Spot price now default to the OD price
- Default admin password now supports special characters
- Ulimit is now disabled by default on all compute nodes
- Dispatcher automatically append "s3://" if not present when using FSx For Lustre
- Updated default ElasticSeach instance to m5.large to support encryption at rest
- SOCA libraries are now installed under /apps/soca/<CLUSTER_ID> location to support multi SOCA environments 
- Web UI now display the reason when a DCV job can't be submitted
- Customers can now provision large number of EC2 hosts accross multiple subnets using a single API call 
- Smart detection of Placement Group requirement when using more than 1 subnet
- Added retry mechanism for some AWS API calls which throttled when provisioning > 1000 nodes in a single API call
- ALB Target Groups are now correctly deleted once the DCV sessions is terminated
- SOCA version is now displayed on the web interface
- Updated EFA version to 1.8.3

## [1.0.0] - 2019-11-20
- Release Candidate

