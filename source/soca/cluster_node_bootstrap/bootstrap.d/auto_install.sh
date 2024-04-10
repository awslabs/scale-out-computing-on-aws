function auto_install {
  # Now perform the installs on the potentially updated package lists
  MAX_INSTALL_ATTEMPTS=10
  ATTEMPT_NUMBER=1
  SUCCESS=false

  if [[ $# -eq 0 ]]; then
    echo "No package list to install. Exiting... "
    exit 1
  fi

  while  [ $SUCCESS = false ] &&  [ $ATTEMPT_NUMBER -le $MAX_INSTALL_ATTEMPTS ]; do
    echo "Attempting to install packages (Attempt ${ATTEMPT_NUMBER}/${MAX_INSTALL_ATTEMPTS})"

    yum install -y $*
    if [[ $? -eq 0 ]]; then
      echo "Successfully installed packages on Attempt ${ATTEMPT_NUMBER}/${MAX_INSTALL_ATTEMPTS}"
      SUCCESS=true
    else
      echo "Failed to install packages on Attempt ${ATTEMPT_NUMBER}/${MAX_INSTALL_ATTEMPTS} . Sleeping for 60sec for retry"
      sleep 60
      ((ATTEMPT_NUMBER++))
    fi
  done

}
