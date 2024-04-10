function amazon_ssm_agent_install {
  echo "[BEGIN] amazon_ssm_agent_install  ... "
  if ! systemctl status amazon-ssm-agent; then
    if [[ $MACHINE == "x86_64" ]]; then
        yum install -y $SSM_X86_64_URL
    elif [[ $MACHINE == "aarch64" ]]; then
        yum install -y $SSM_AARCH64_URL
    fi
    systemctl enable amazon-ssm-agent || true
    systemctl restart amazon-ssm-agent
fi
  echo "[COMPLETED]  amazon_ssm_agent_install ... "
}