# System Settings
MACHINE=$(uname -m)
KERNEL=$(uname -r)
NCPUS=$(nproc)
SERVER_IP=$(hostname -I)
SERVER_HOSTNAME=$(hostname)
SERVER_HOSTNAME_ALT=$(echo $SERVER_HOSTNAME | cut -d. -f1)

# AWS Settings
AWS=$(command -v aws)
IMDS_TOKEN=$(curl --silent -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
INSTANCE_FAMILY=$(curl --silent -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" --silent http://169.254.169.254/latest/meta-data/instance-type | cut -d. -f1)
AWS_AVAIL_ZONE=$(curl --silent -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/placement/availability-zone)
AWS_INSTANCE_ID=$(curl --silent -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
AWS_REGION=$(curl --silent -H "X-aws-ec2-metadata-token: $IMDS_TOKEN" http://169.254.169.254/latest/meta-data/placement/region)
EBS_IDS=$(aws ec2 describe-volumes --filters Name=attachment.instance-id,Values="$AWS_INSTANCE_ID" --region $AWS_REGION --query "Volumes[*].[VolumeId]" --out text | tr "\n" " ")

# GPU Settings
NVIDIA_GPU_INSTANCE_FAMILY=(p2 p3 p4d p4de g2 g3 g4dn g5 g5g g6 gr6)
AMD_GPU_INSTANCE_FAMILY=(g4ad)
GPU_INSTANCE_FAMILY=("${AMD_GPU_INSTANCE_FAMILY[@]}" "${NVIDIA_GPU_INSTANCE_FAMILY[@]}")
GPU_DRIVER_NVIDIA_S3_BUCKET_URL="https://ec2-linux-nvidia-drivers.s3.amazonaws.com"
GPU_DRIVER_NVIDIA_S3_BUCKET_PATH="s3://ec2-linux-nvidia-drivers/latest/"
GPU_DRIVER_AMD_S3_BUCKET_URL="https://ec2-amd-linux-drivers.s3.amazonaws.com"
GPU_DRIVER_AMD_S3_BUCKET_PATH="s3://ec2-amd-linux-drivers/latest/"
GPU_DRIVER_AMD_EL8_INSTALLER_URL="https://repo.radeon.com/amdgpu-install/23.20/rhel/8.8/amdgpu-install-5.7.50700-1.el8.noarch.rpm"
GPU_DRIVER_AMD_EL9_INSTALLER_URL="https://repo.radeon.com/amdgpu-install/23.20/rhel/9.2/amdgpu-install-5.7.50700-1.el9.noarch.rpm"

# DCV Settings
## DCV Centos7/RHEL7/Amazon Linux2
DCV_7_X86_64_VERSION="2023.1-16388-el7-x86_64"
DCV_7_X86_64_TGZ="nice-dcv-2023.1-16388-el7-x86_64.tgz"
DCV_7_X86_64_URL="https://d1uj6qtbmh3dt5.cloudfront.net/2023.1/Servers/nice-dcv-2023.1-16388-el7-x86_64.tgz"
DCV_7_X86_64_HASH="eb88acd9bb487c9f453d41258ce4135e"
DCV_7_AARCH64_VERSION="2023.1-16388-el7-aarch64"
DCV_7_AARCH64_TGZ="nice-dcv-2023.1-16388-el7-aarch64.tgz"
DCV_7_AARCH64_URL="https://d1uj6qtbmh3dt5.cloudfront.net/2023.1/Servers/nice-dcv-2023.1-16388-el7-aarch64.tgz"
DCV_7_AARCH64_HASH="dbed36aa5e06deee59188242fda6d9bd"

## DCV Centos8/RHEL8/Rocky8
DCV_8_X86_64_VERSION="2023.1-16388-el8-x86_64"
DCV_8_X86_64_TGZ="nice-dcv-2023.1-16388-el8-x86_64.tgz"
DCV_8_X86_64_URL="https://d1uj6qtbmh3dt5.cloudfront.net/2023.1/Servers/nice-dcv-2023.1-16388-el8-x86_64.tgz"
DCV_8_X86_64_HASH="6f3cdaad178be44d175fb44d8f0bcd60"
DCV_8_AARCH64_VERSION="2023.1-16388-el8-aarch64"
DCV_8_AARCH64_TGZ="nice-dcv-2023.1-16388-el8-aarch64.tgz"
DCV_8_AARCH64_URL="https://d1uj6qtbmh3dt5.cloudfront.net/2023.1/Servers/nice-dcv-2023.1-16388-el8-aarch64.tgz"
DCV_8_AARCH64_HASH="1fc6df072b33315191a9ef05c69bf1aa"

## DCV RHEL9/Rocky9
DCV_9_X86_64_VERSION="2023.1-16388-el9-x86_64"
DCV_9_X86_64_TGZ="nice-dcv-2023.1-16388-el9-x86_64.tgz"
DCV_9_X86_64_URL="https://d1uj6qtbmh3dt5.cloudfront.net/2023.1/Servers/nice-dcv-2023.1-16388-el9-x86_64.tgz"
DCV_9_X86_64_HASH="7972c0469590d7d998d7c5ac65e67de7"
DCV_9_AARCH64_VERSION="2023.1-16388-el9-aarch64"
DCV_9_AARCH64_TGZ="nice-dcv-2023.1-16388-el9-aarch64.tgz"
DCV_9_AARCH64_URL="https://d1uj6qtbmh3dt5.cloudfront.net/2023.1/Servers/nice-dcv-2023.1-16388-el9-aarch64.tgz"
DCV_9_AARCH64_HASH="c2eaec9c22e457a80c094fc9d8e53e5f"

# EFA
EFA_VERSION="1.31.0"
EFA_TGZ="aws-efa-installer-1.31.0.tar.gz"
EFA_URL="https://efa-installer.amazonaws.com/aws-efa-installer-1.31.0.tar.gz"
EFA_HASH="856352f12bef2ccbadcd75e35aa52aaf"