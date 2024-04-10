function ulimits_disable {
  echo "[BEGIN] ulimits_disable ... "
  LIMITS=(
      #"fsize" # maximum filesize (KB)
      "memlock"  # max locked-in-memory address space (KB)
      "stack" # max stack size (KB)
      # Uncomment below as needed
      #"core" # limits the core file size (KB)
      #"dat" # max data size (KB)
      #"rss" # max resident set size (KB)
      #"cpu" # max CPU time (MIN)
      #"nproc" # max number of processes
      #"as" # address space limit (KB)
      #"maxlogins" # max number of logins for this user
      #"maxsyslogins" # max number of logins on the system
      #"priority" # the priority to run user process with
      #"locks" # max number of file locks the user can hold
      #"sigpending" # max number of pending signals
      #"msgqueue" # max memory used by POSIX message queues (bytes)
      #"nice" # max nice priority allowed to raise to values: [-20, 19]
      #"rtprio" # max realtime priority
  )

  #Note:
  # "nofile"  # max number of open file descriptors
  # Be careful when you set this, see https://unix.stackexchange.com/questions/432057/pam-limits-so-making-problems-for-sudo
  # It's recommended to not set this value to unlimited and instead pick a lower value otherwise you may run into authentication issues.

  for item in ${LIMITS[@]}; do
    echo -e "
* hard $item unlimited
* soft $item unlimited
" >> /etc/security/limits.conf
  done
  echo "[COMPLETED] ulimits_disable... "
}