# Change Log
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.7.5] - 2024-04-10

### Features
- Support for [Amazon Linux 2023](https://aws.amazon.com/linux/amazon-linux-2023/) as a BaseOS for compute nodes
  - eVDI on Amazon Linux 2023 is not currently supported
- Support for `5 new AWS Regions`: `ap-northeast-3`, `ap-southeast-4`, `eu-central-2`, `eu-south-2`, and  `il-central-1`. 
  - Note that not all Base OSes are available in All regions
- Support for `RHEL8`, `RHEL9`, `Rocky8`, and `Rocky9` operating systems for both DCV and compute nodes
- Support for newer AWS Instance types/families. This includes `hpc7a`, `hpc7g`, `r7iz`, `g6`, `gr6`, `g5`, `g5g`, `c7i`, `p5`, and many more (where supported in the region)
- Support for [AWS GovCloud](https://aws.amazon.com/govcloud-us/) Partition installation by default
  - Include AMIs for regions `us-gov-west-1` and `us-gov-east-1`
  - Note that not all Base OSes are available in All regions within GovCloud
  - Set environment variable `AWS_DEFAULT_REGION` to a GovCloud region prior to invoking `soca_installer.sh`
- Improve compatibility and support SOCA deployments on `AWS Outposts` (compute, eVDI)
  - The default `VolumeType` in Secrets Manager needs to be configured to reflect the AWS Outposts `gp2` support
- Support has been added for multi-interface EFA instances such as the `p5.48xlarge`. For compute instances that support multiple EFA interfaces - all EFA interfaces will be created during provisioning.
- The SOCA Administrator can now define the list of approved eVDI instances via new configuration parameters:
  - `DCVAllowedInstances` - A list of patterns for allowed instance names. For example `["m7i-flex.*", "m7i.*", "m6i.*", "m5.*", "g6.*", "gr6.*", "g5.*", "g5g.*", "g4dn.*", "g4ad.*"]`
  - (Optional) `DCVAllowBareMetal` (defaults to `False`) - Allow listing of Bare Metal instances for eVDI
  - (Optional) `DCVAllowPreviousGenerations` (defaults to `False`) - Allow listing of previous generation(s) of instances for eVDI

### Changed
- Improved user experience using `soca_installer.sh` in high-density VPC/subnet environments
- Improved the log message for an Invalid `subnet_id` during job submission to include the specific `subnet_id` that triggered the error
- Updated Python from `3.9.16` to `3.9.19`
- Updated AWS Boto3/botocore from `1.26.91` to `1.34.71`
- Updated OpenMPI from `4.1.5` to `5.0.2`
- Updated OpenPBS from `22.05.11` to `23.06.06`
- Updated Monaco-Editor from `0.36.1` to `0.46.0`
- Updated AWS EFA installer from `1.22.1` to `1.31.0`
- Updated NICE DCV from `2023.0-14852` to `2023.1-16388`
- Update NVM from `0.39.3` to `0.39.7`
- Updated Node from `16.15.0` to `16.20.2`
- Updated Lambda Runtimes to Python `3.11` where applicable
- Misc Python 3rd party module version updates
- Refactor installation items for newer AWS CDK methods
- Updated default `OpenSearch` engine version to `2.11` when creating an OpenSearch deployment
- The use of `add_nodes.py` to add `AlwaysOn` nodes now allows the parameter `--instance_ami` to be optional and will default to the `CustomAMI` in the cluster configuration
- Download/install/configure `Redis` version `7.2.4` for new SOCA cache backend
- The SOCA ELB/ALB is now created with the option `drop_invalid_headers` set to `True` by default.
- Several UWSGI application server adjustments
  - Activate UWSGI `stats` server on `127.0.0.1:9191`
  - Activate UWSGI `offload-threads`
  - Activate UWSGI `threaded-logger`
  - Activate UWSGI `memory-report`
  - Activate UWSGI `microsecond logging`
  - Activate UWSGI logging of the `X-Forwarded-For` headers so that the client IP address is captured versus the ELB IP Address
  - Added `uwsgitop` to assist in UWSGI performance investigations. This can be accessed via the command `uwsgitop localhost:9191` from the scheduler.
  - Adjusted Flask session backend from `SQLite` to `redis`. This results in a much faster WebUI/session handling.
  - **NOTE** - Upgrade scenarios should take UWSGI changes into account and manually perform Redis installation/configuration and session migration.
- `Launch Tenancy` and `Launch Host` have been added as options when registering an AMI in SOCA. These will be used during DCV session creation.
  - For more information on launch tenancy - see the [documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/dedicated-instance.html).
- Updated default OpenSearch instance from `m5.large.search` to `m6g.large.search`
- Updated default VDI choices from `m5` to `m6i` instance family
- `instance_ami` is no longer mandatory when specifying a custom `base_os`. SOCA will determine which default AMI to use automatically via the `CustomAMIMap` configuration stored on Secrets Manager.  
- Changed default `instance_type` for all base HPC queues from `c5` to `c6i` instance family
- Updated DCV Session default `Storage Size` to `40GB` to accommodate additional locally installed software such as GPU drivers, libs, etc.

### Fixes
- `DryRun` job submission was not taking into account the `IMDS` settings for the cluster. This could cause job submission to fail `DryRun` and not be submitted.
- Installation using an existing `OpenSearch` / `ElasticSearch` domain was not working as expected. This has been fixed.
- Avoid sending `CpuOptions` with `hpc7a`, `hpc7g`, `g5`, `g5g` instances. This will fix launching on these instance families.
- Properly detect newer AWS metal instances for determining if `CpuOptions` is supported during instance launch. This will allow launching `c7i.metal-24xl`, `c7i.metal-48xl` (and others) to function properly
- On the `scheduler` Post-Install - extract/compile `OpenMPI` on a local EBS volume instead of EFS (can reduce compile time by `50%+`)
- During HPC Job submission within the WebUI - the multi-select UI element `Checkbox Group` was not passed correctly to the underlying job scripting
  - `Checkbox Group` element values will be delimited by comma by default (e.g. `option1,option2`).
  - Care should be taken to not have option values contain the delimiter character. This can be updated in `submit_job.py` as needed. (Option name fields can contain the delimiter character)
- During DCV Session creation - the user was allowed to enter a session name that exceeded the allowable length for a CloudFormation stack name. This has been adjusted to trim the session name to appropriate length (32 characters).
- During DCV Session creation - if the session contained an underscore (_) the session would produce an error and not be created.
- During DCV Session creation - The `Storage Size` was allowed to be lower than a stored AMI. This will now default / auto-size to the AMI specification.
- Bootstrap tooltips are now displayed using the correct CSS in the Remote Desktop pages
- Previously during invocation of `soca_installer.sh` with existing resources - only VPCs and Subnets with AWS `Name` tags would be selectable. This restriction has been eased to allow resources without `Name` tags to be selectable.
- Under certain conditions in an Active Directory (AD) environment - the `scheduler` computer object could be mistakenly replaced in AD by an incoming compute or VDI node. This was due to NetBIOS name length restrictions causing name conflicts. This has been corrected.

### Known Caveats
- Web Sessions can be stored in the back-end (redis) that relate to API calls or other situations where return of the session is not expected. These sessions will be cleaned up automatically by Redis when the TTL expires (24hours).
- On the Remote Desktop selection for Instance Types - sorting, grouping, and custom names of the AWS instances is not configurable by the SOCA Administrator for wildcard instances allowed via wildcard (e.g. `g5.*`).
  - This can cause 'selection fatigue' for end-users when a large number of instances types are allowed.
  - The SOCA Administrator can configure the static list at the top before the generated list appears. See the `cluster_web_ui/templates/remote_desktop.html` (Linux) and `cluster_web_ui/templates/remote_desktop_windows.html` (Windows) files for examples/defaults.
  - The SOCA Administrator can reduce the default instances allowed by editing the AWS Secrets Manager configuration entry for the cluster and refreshing the configuration on the cluster.



## [2.7.4] - 2023-05-08

### Features
- Support for newer AWS EC2 instances since the last release.
  - HPC family (in supported regions): `hpc6a.48xlarge`, `hpc6id.32xlarge`
- Updated Region support list with new regions for SOCA deployment
- Updated all AMIs to point to newer versions
- Added support for OpenSearch. 
  - OpenSearch will be the default option in the future release and will replace ElasticSearch
  - MetricBeat will be sunset once OpenSearch replace ElasticSearch
- The SOCA head node can now be installed onto an AWS Graviton processors(`arm64`) in regions where available. The `scheduler/instance_type` will have the architecture determined at installation time for selecting the correct AMI.
- IMDSv2 metadata is now enforced for all EC2 hosts. This setting change be changed on the config file. (contributor: @sebastiangrimberg [#84](https://github.com/awslabs/scale-out-computing-on-aws/pull/84)

### Changed
- boto3 updated from `1.17.49` to `1.26.61`
- botocore updated from `1.20.49` to `1.29.61`
- troposphere requirements are now `>= 4.3.0`. Updated from `2.7.1` to `4.3.2`
- Python updated from `3.7.9` to `3.9.16`
- OpenPBS updated from `20.0.1` to `22.05.11`
- AWS EFA installer updated from `1.13.0` to `1.22.1`
- OpenMPI updated from `4.1.1` to `4.1.5`
- NICE DCV framework updated from `2021.2` to `2023.0-14852`
- NVM updated from `0.38.0` to `0.39.3`
- Update Monaco-editor from `` to `0.36.1`
- EPEL RPM updated to `-9`
- Updates to several downstream python requirements/modules
- Added support for `Version`, `Region`, `Misc` in anonymous metrics
- Changed default OpenPBS Job History Duration (`job_history_duration`) to `72-hours` (from `1-hour`)
- Improved Python/OpenPBS compilation to make consistent use of `nproc` CPUs/jobs (`make -j N`)
- Upgraded Amazon Cloud Development Kit (CDK) to `v2`
- Added `skip_quota` flag to disable quota checks when using subnets with no egress
- The default queues that are created will now default to using the instance type of the scheduler instance. This is to align CPU architectures and the selected BaseOS AMI.
- Upgraded Jquery to `3.6.4`
- Upgraded Bootstrap to `4.6.3`
- Updated lustre client installation for Amazon Linux 2 enabling installation of lustre2.12 client required for FSx File Cache

### Fixes
- Fixed instances matching the incorrect Service Quota and preventing job execution under some circumstances (contributor: @nfahlgren [#81](https://github.com/awslabs/scale-out-computing-on-aws/pull/81)).
- Fixed anonymous metric submission during job delete.
- Fixed detection of IP address during `soca_installer.sh` by using https://checkip.amazonaws.com
- Fix attempt to set `CpuOptions` on instance types that do not support `CpuOptions`
- Additional exception handling during installation when the ALB is not ready yet and emits a connection refused.
- Added PBS_LEAF_NAME in ComputeNode.sh pbs.conf section to address pbs_mom to pbs_comm communication when there are multiple network interfaces in the AMI
- Added REQUIRE_REBOOT logic in ComputeNode.sh to skip instance reboot if not needed (mostly when using a customized AMI)


## [2.7.3] - 2022-08-20
### Changed
- Bumped Lambda Python Runtime to 3.7

## [2.7.2] - 2022-04-25
### Changed
- Fix node version to v8.7.0 (later versions need updated versions of GLIBC that are not available for AL2/CentOS7/RHEL7)
- Update RHEL7 AMI IDs to RHEL7.9
- Update AL2 AMI IDs

## [2.7.1] - 2022-02-15
### Changed
- NodeJS/npm is now managed via NVM (#64: Contributor @cfsnate)
- Fixed IAM policies required to install SOCA and added support for cdk boostrap (#64: Contributor @cfsnate)
- More consistent way to install EPEL repository across distros
- Better way to install SSM on the Scheduler host (similar to what we are already doing with ComputeNodes)
- Updated remote job submission to fix error with group ownership when using a remote input file
- DCV desktops now honor correct subnet when specified
- Fix issue causing installer to crash when using IPv6-only VPC subnets
- Fix logger issue on DCV instance lifecycle (#67, contributor @tammy-ruby-cherry)

## [2.7.0] - 2021-11-18
### Added
- SOCA installer is managed by CDK (https://aws.amazon.com/cdk/)
- Enabled full WSGI debug mode for SOCA Web UI
- Added support for WeightedCapacity enabling add_nodes.py to launch capacity based on vCPUs or cores
- CDK: Added support for Active Directory via AWS Directory Service
- CDK: Users can now re-use their existing AWS resources (VPC, subnets, security groups, FSxL, EFS, Directory Services ...) when installing SOCA
- CDK: Users can extend the base installer with their own code (see cdk_construct_user_customization)
- CDK: /apps & /data partition can now be configured to use EFS or FSxL as storage provider
- CDK: Users can now use your own CMK (Customer Managed Key) to encrypt your EFS, FSxL, EBS or SecretsManager
- CDK: Users can configure the number of NAT gateways to be deployed when installing a new cluster
- CDK: Users can customize your OpenSearch (formerly Elasticsearch) domain (number of nodes, type of instance)
- CDK: Users can configure the backup retention time (default to 7 days)
- CDK: Users can now deploy SOCA in private subnets only
- CDK: Added support for VPC endpoints creation
- Users can now specify up to 4 additional security groups for compute nodes assigned to their simulations
- Users can now specific a custom IAM instance profile for compute nodes assigned to their simulations
- Deprecated ldap_manager.py in favor of the native REST API
- Added a custom path for Windows DCV logs 
- Name of the SOCA cluster is now accessible on the Web interface
- DCV session management is now available via REST API
- Customer EC2 AMI management is now available via REST API
- Added job-shared queue enabling multiple jobs to run on the same EC2 instance for jobs with similar requirements
- Desktops sessions are now tracked on OpenSearch (formerly Elasticsearch) via "soca_desktops" index

### Changed
- Upgraded DCV to 2021.2
- Upgraded EFA to 1.13.0
- Upgraded OpenMPI to 4.1.1  
- Auto-Terminate stopped DCV instances now delete the associated cloudformation stack
- Fixed #55 (bug and bug fix: automatic hibernation (Linux desktops))
- Prevent system accounts (ec2-user/centos) to submit jobs
- OpenMPI is now installed under /apps/openmpi
- Changed default OpenSearch (formerly Elasticsearch) indexes to "soca_jobs" and "soca_nodes" (previously "jobs" and "pbsnodes")



## [2.6.1] - 2021-03-22
### Added
- Added Name tag to EIPNat in Network.template
- Added support for Milan and Cape Town
- EBS volumes provisioned for DCV sessions (Windows/Linux) are now tagged properly
- Support for Graviton2 instances
- Ability to disable web APIs via @disabled decorator

### Changed
- Updated EFA to 1.11.1
- Updated Python 3.7.1 to Python 3.7.9
- Update DCV version to 2020.2
- Updated awscli, boto3, and botocore to support instances announced at Re:Invent 2020
- Use new gp3 volumes instead of gp2 since they're more cost effective and provide 3000 IOPS baseline
- Removed SchedulerPublicIPAllocation from Scheduler.template as it's no longer used
- Updated CentOS, ALI2 and RHEL76 AMI IDs
- Instances with NVME instance store don't become unresponsive post-restart due to filesystem checks enforcement
- OpenSearch (formerly Elasticsearch) is now deployed in private subnets

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
- Updated OpenSearch (formerly Elasticsearch) to 7.4
- You can specify a name for your DCV sessions
- You can now specify custom AMI, base OS or storage options for your DCV sessions
- Project assigned to DCV jobs has been renamed to "remotedesktop" (previously "gui")
- Dispatcher script is now running every minute
- SOCA now deploys 2 instances for OpenSearch (formerly Elasticsearch) for high availability
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
- Max Spot price now default to the OD price
- Default admin password now supports special characters
- Ulimit is now disabled by default on all compute nodes
- Dispatcher automatically append "s3://" if not present when using FSx For Lustre
- Updated default OpenSearch (formerly Elasticsearch) instance to m5.large to support encryption at rest
- SOCA libraries are now installed under /apps/soca/<CLUSTER_ID> location to support multi SOCA environments
- Web UI now display the reason when a DCV job can't be submitted
- Customers can now provision large number of EC2 hosts across multiple subnets using a single API call
- Smart detection of Placement Group requirement when using more than 1 subnet
- Added retry mechanism for some AWS API calls which throttled when provisioning > 1000 nodes in a single API call
- ALB Target Groups are now correctly deleted once the DCV sessions is terminated
- SOCA version is now displayed on the web interface
- Updated EFA version to 1.8.3

## [1.0.0] - 2019-11-20
- Release Candidate
