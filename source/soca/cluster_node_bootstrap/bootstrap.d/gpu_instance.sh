function gpu_instance_disable_nouveau_driver {
  echo "[BEGIN] gpu_instance_disable_nouveau_driver.. "
  if [[ ${SOCA_BASE_OS} == "rocky9" ]]; then
    cat << EOF > /etc/modprobe.d/blacklist-nouveau.conf
blacklist nouveau
options nouveau modeset=0
EOF
    dracut --force
  else
    cat << EOF | sudo tee --append /etc/modprobe.d/blacklist.conf
  blacklist vga16fb
  blacklist nouveau
  blacklist rivafb
  blacklist nvidiafb
  blacklist rivatv
EOF
    echo GRUB_CMDLINE_LINUX="rdblacklist=nouveau" >> /etc/default/grub
    grub2-mkconfig -o /boot/grub2/grub.cfg
  fi
  echo "[COMPLETED] gpu_instance_disable_nouveau_driver .. "
}

function gpu_instance_install_nvidia_driver {
  echo "[BEGIN] gpu_instance_install_nvidia_driver.. "
  echo "Detected GPU instance .. installing NVIDIA Drivers"
  rm -f NVIDIA-Linux-x86_64*.run
  # Determine the S3 bucket AWS region for the drivers
  DRIVER_BUCKET_REGION=$(curl -s --head ${GPU_DRIVER_NVIDIA_S3_BUCKET_URL} | grep bucket-region | awk '{print $2}' | tr -d '\r\n')
  $AWS --region ${DRIVER_BUCKET_REGION} s3 cp --quiet --recursive ${GPU_DRIVER_NVIDIA_S3_BUCKET_PATH} .
  rm -rf /tmp/.X*
  /bin/sh NVIDIA-Linux-x86_64*.run -q -a -n -X -s
  local NVIDIAXCONFIG=$(which nvidia-xconfig)
  $NVIDIAXCONFIG --preserve-busid --enable-all-gpus
  echo "[COMPLETED] gpu_instance_install_nvidia_driver .. "
}

function gpu_instance_install_amd_driver {
  echo "[BEGIN] gpu_instance_install_amd_driver.. "
  echo "Detected GPU instance .. installing AMD Drivers"
  which -s /opt/amdgpu-pro/bin/clinfo
  if [[ "$?" == "0" ]]; then
    echo "GPU driver already installed. Skip."
  else
    if [[ ${SOCA_BASE_OS} =~ ^(rhel7|centos7|amazonlinux2)$ ]]; then
      DRIVER_BUCKET_REGION=$(curl -s --head ${GPU_DRIVER_AMD_S3_BUCKET_URL} | grep bucket-region | awk '{print $2}' | tr -d '\r\n')
      $AWS --region ${DRIVER_BUCKET_REGION} s3 cp --quiet --recursive ${GPU_DRIVER_AMD_S3_BUCKET_PATH} .
      tar -xf amdgpu-pro-*rhel*.tar.xz
      cd $(find . -maxdepth 1 -mindepth 1 -type d -name "amdgpu-pro*rhel*")
      rpm --import RPM-GPG-KEY-amdgpu
      /bin/sh ./amdgpu-pro-install -y --opencl=pal,legacy
    elif [[ ${SOCA_BASE_OS} =~ ^(rhel8|rocky8)$ ]]; then
      yum localinstall -y ${GPU_DRIVER_AMD_EL8_INSTALLER_URL}
      /bin/amdgpu-install --usecase=workstation --vulkan=pro --opencl=rocr,legacy --accept-eula -y
    elif [[ ${SOCA_BASE_OS} =~ ^(rhel9|rocky9)$ ]]; then
      yum localinstall -y ${GPU_DRIVER_AMD_EL9_INSTALLER_URL}
      /bin/amdgpu-install --usecase=workstation --vulkan=pro --opencl=rocr,legacy --accept-eula -y
    fi
  fi
  echo "[COMPLETED] gpu_instance_install_amd_driver.. "
}

function gpu_instance_optimize_gpu_clock_speed_nvidia {
  # https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/optimize_gpu.html
  echo "[BEGIN] gpu_instance_optimize_gpu_clock_speed_nvidia.. "
  if [[ ${INSTANCE_FAMILY}  == "g3" ]]; then
    nvidia-smi -ac 2505,1177
  elif [[ ${INSTANCE_FAMILY}  == "g4dn" ]]; then
    nvidia-smi -ac 5001,1590
  elif [[ ${INSTANCE_FAMILY}  == "g5" ]]; then
    nvidia-smi -ac 6250,1710
  elif [[ ${INSTANCE_FAMILY}  == "p2" ]]; then
    nvidia-smi -ac 2505,875
  elif [[ ${INSTANCE_FAMILY} =~ ^(p3|p3dn)$ ]]; then
    nvidia-smi -ac 877,1530
  elif [[ ${INSTANCE_FAMILY}  == "p4d" ]]; then
    nvidia-smi -ac 1215,1410
  elif [[ ${INSTANCE_FAMILY}  == "p4de" ]]; then
    nvidia-smi -ac 1593,1410
  elif [[ ${INSTANCE_FAMILY}  == "p5" ]]; then
    nvidia-smi -ac 2619,1980
  else
    echo "Unknown instance family for optimizations - ${INSTANCE_FAMILY} . May not run at maximum performance"
  fi

  echo "[COMPLETED] gpu_instance_optimize_gpu_clock_speed_nvidia.. "

}