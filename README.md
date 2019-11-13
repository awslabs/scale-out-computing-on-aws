# Scale Out Computing on AWS (SOCA)

## :wrench: How to install SOCA
### 1) 1-Click installer

Visit [https://aws.amazon.com/solutions/scale-out-computing-on-aws](https://aws.amazon.com/solutions/scale-out-computing-on-aws)

:rotating_light: 1-Click installer is only great for PoC or demos. For production workload, it's recommended you go with option 2 instead.

### 2) Build and install SOCA on your own AWS account

+ 1\) Clone this git repository
```bash
git clone https://github.com/awslabs/scale-out-computing-on-aws
```
+ 2\) Run the following command to create your build (support Python2 and Python3):
```bash
python source/manual_build.py
```
+ 3\) Output will be created under `source/dist/<build_id>`

+ 4\) Upload `source/dist/<build_id>` folder to your own S3 bucket

+ 5\) Launch CloudFormation and use `for-scale-out-computing-on-aws.template` as base template

## :book: Documentation

### New User Guide
[https://soca.dev](https://soca.dev)

### Implementation Guide
[https://aws.amazon.com/solutions/scale-out-computing-on-aws](https://aws.amazon.com/solutions/scale-out-computing-on-aws)

## :pencil2: File Structure
The AWS SOCA project consists in a collection of CloudFormation templates, Shell scripts and Python code.

```bash
.
├── scale-out-computing-on-aws.template                 [ Soca Install Template ]
├── soca                           
│   ├── cluster_analytics                               [ Scripts to ingest cluster/job data into ELK ]
│   ├── cluster_hooks                                   [ Scheduler Hooks ]
│   ├── cluster_logs_management                         [ Scripts to manage cluster log rotation ]
│   ├── cluster_manager                                 [ Scripts to control Soca cluster ]
│   └── cluster_web_ui                                  [ Web Interface ]
├── scripts                                             
│   ├── ComputeNode.sh                                  [ Configure Compute Node ]
│   ├── ComputeNodeInstallDCV.sh                        [ Configure DCV Host ]
│   ├── ComputeNodePostReboot.sh                        [ Post Reboot Compute Node actions ]
│   ├── ComputeNodeUserCustomization.sh                 [ User customization ]
│   ├── config.cfg                                      [ List of all packages to install ]
│   ├── Scheduler.sh                                    [ Configure Schedule Node ]
│   └── SchedulerPostReboot.sh                          [ Post Reboot Scheduler Node actions ]
└── templates                              
    ├── Analytics.template                              [ Manage ELK stack for your cluster ]
    ├── ComputeNode.template                            [ Manage simulation nodes ]
    ├── Configuration.template                          [ Centralize cluster configuration ]
    ├── Network.template                                [ Manage VPC configuration ]
    ├── Scheduler.template                              [ Manage Scheduler host ]
    ├── Security.template                               [ Manage ACL, IAM and SGs ]
    ├── Storage.template                                [ Manage backend storage ]
    └── Viewer.template                                 [ Manage DCV sessions ]
```

***

Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.