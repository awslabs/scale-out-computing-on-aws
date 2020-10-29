# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.6.0] - 2020-10-29
### Added
- Users can now launch Windows instances with DCV
- Users can now configure their DCV sessions based on their own schedule
- Users can stop/hibernate DCV sessions
- Users can change the hardware of their DCV sessions after the initial launch
- Admins can create DCV AMI with pre-configured applications
- Added support for DCV session storage. Upload/download data to SOCA directly from your DCV desktop (C:\storage-root for windows and $HOME/storage-root for linux)
- Admins can now prevent users to download the files via the web ui
- SOCA automatically enable/disable EFS provisioned throughput based on current I/O activity

### Changed
- Removed deprecated `soca_aws_infos` hook
- Fixed an issue that caused the web interface to become unresponsive after an API reset
- Users can now easily import/export application profiles
- Fixed an issue that caused Nvidia Tesla drivers to be incorrectly installed on P3 instances
- Manual_build.py now automatically upload the installer to your S3 bucket
- Upgraded to PBS v20
- Upgraded DCV to 2020.1-9012


## [2.5.0] - 2020-07-17
### Added
- Support for Elastic MetricBeat
- Added HTTP REST API to interact with SOCA
- Users can now decide to restrict a job to Reserved Instances
- Revamped Web Interface
  - Added filesystem explorer
  - Users can upload files/folders via drag & drop interface
  - Users can edit files directly on SOCA using a cloud text editor
  - Users can now manage membership of their own LDAP group via web
  - Users can now understand why they job is not started  (eg: instance issue, misconfiguration, AWS limit, license limit) directly on the UI
  - Users can kill their job via the web
  - Admins can manage SOCA LDAP via web (create group, user, manage ownership and permissions)
  - Admins can creates application profiles and let user submit job via web interface
  - Ability to trigger Linux commands via HTML form
- Admins can now limit the number of running jobs per queue
- Admins can now limit the number of running instances per queue
- Admins can now specify the idle timeout value for any DCV sessions. Inactive DCV sessions will be automatically terminated after this period
- Job selection can now configured at queue level (FIFO or fair share)
- Dry run now supports vCpus limit
- Support for custom shells

### Changed
- Updated Troposphere to 2.6.1
- Updated EFA to 1.9.3
- Updated Nice DCV to 2020.0-8428
- Updated ElasticSearch to 7.4
- You can specify a name for your DCV sessions 
- You can now specify custom AMI, base OS or storage options for your DCV sessions
- Project assigned to DCV jobs has been renamed to "remotedesktop" (previously "gui")
- Dispatcher script is now running every minute
- SOCA now deploys 2 instances for ElasticSearch for high availability
- Users can now specify DEPLOYMENT_TYPE for their FSX for Lustre filesystems
- Users can specify PerUnitThroughput when FSx for Lustre deployment type is set to PERSISTENT
- DCV now supports G4 instance type (#24)
- X11 is now configured correctly for ALI 3D DCV session (#23)


## [2.0.1] - 2020-04-20
### Added
- Support for SpotFleet

### Changed
- NVIDIA drivers are now automatically installed when a GPU instance is provisioned
- Deployed MATE Desktop for DCV for Amazon Linux 2

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

