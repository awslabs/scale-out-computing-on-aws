# Scale-Out Computing on AWS - HPC made easy :palm_tree:

## :book: Documentation

[https://awslabs.github.io/scale-out-computing-on-aws/](https://awslabs.github.io/scale-out-computing-on-aws/)

## :rocket: How to install Scale-Out Computing on AWS

Refer to [https://awslabs.github.io/scale-out-computing-on-aws/tutorials/install-soca-cluster/](https://awslabs.github.io/scale-out-computing-on-aws/tutorials/install-soca-cluster/) for installation instructions.

## :pencil2: File Structure
Scale-Out Computing on AWS project consists in a collection of CloudFormation templates, Shell scripts and Python code.
```bash
.
├── soca
│   ├── cluster_analytics                               [ Scripts to ingest cluster/job data into ELK ]
│   ├── cluster_hooks                                   [ Scheduler Hooks ]
│   ├── cluster_logs_management                         [ Scripts to manage cluster log rotation ]
│   ├── cluster_manager                                 [ Scripts to control Soca cluster ]
│   ├── cluster_web_ui                                  [ Web Interface ]
│   └── cluster_node_bootstrap                          [ Script to configure compute nodes]
└── scripts
   ├── config.cfg                                      [ List of all packages to install ]
   ├── Scheduler.sh                                    [ Configure Schedule Node ]
   └── SchedulerPostReboot.sh                          [ Post Reboot Scheduler Node actions ]

```

This solution collects anonymous operational metrics to help AWS improve the quality of features of the solution. For more information, including how to disable this capability, please see the [https://docs.aws.amazon.com/solutions/latest/scale-out-computing-on-aws/appendix-d.html](https://docs.aws.amazon.com/solutions/latest/scale-out-computing-on-aws/appendix-d.html).

***

Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.