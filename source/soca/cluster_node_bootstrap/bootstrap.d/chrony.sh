function chrony_configure {
  echo "[BEGIN] chrony_configure... "
  yum remove -y ntp
  mv /etc/chrony.conf  /etc/chrony.conf.original
  echo -e """
  # use the local instance NTP service, if available
  server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4

  # Use public servers from the pool.ntp.org project.
  # Please consider joining the pool (http://www.pool.ntp.org/join.html).
  # !!! [BEGIN] SOCA REQUIREMENT
  # You will need to open UDP egress traffic on your security group if you want to enable public pool
  #pool 2.amazon.pool.ntp.org iburst
  # !!! [END] SOCA REQUIREMENT
  # Record the rate at which the system clock gains/losses time.
  driftfile /var/lib/chrony/drift

  # Allow the system clock to be stepped in the first three updates
  # if its offset is larger than 1 second.
  makestep 1.0 3

  # Specify file containing keys for NTP authentication.
  keyfile /etc/chrony.keys

  # Specify directory for log files.
  logdir /var/log/chrony

  # save data between restarts for fast re-load
  dumponexit
  dumpdir /var/run/chrony
  """ > /etc/chrony.conf
  systemctl enable chronyd
  echo "[COMPLETED] chrony_configure ... "
}