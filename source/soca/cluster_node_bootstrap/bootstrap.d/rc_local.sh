function rc_local_after_final_reboot {
   echo "source /etc/environment

while [ ! -d \$SOCA_HOST_SYSTEM_LOG ]
do
  sleep 1
done

for i in /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/bootstrap.d/*.sh ; do
  echo \"Source \$i ...\" >> $SOCA_HOST_SYSTEM_LOG/rc_local.log 2>&1
  . \$i
done

openpbs_stop >> $SOCA_HOST_SYSTEM_LOG/rc_local.log 2>&1

DCVGLADMIN=$(which dcvgladmin)
if [[ -z \"$DCVGLADMIN\" ]]; then
 $DCVGLADMIN enable >> $SOCA_HOST_SYSTEM_LOG/rc_local.log 2>&1

fi

# Post-Mount FSxL perf tuning
if [[ \"$SOCA_FSX_LUSTRE_BUCKET\" != \"false\" ]] || [[ \"$SOCA_FSX_LUSTRE_DNS\" != \"false\" ]]; then
  fsx_lustre_client_tuning_postmount
fi


# Disable HyperThreading
if [[ \"$SOCA_INSTANCE_HYPERTHREADING\" == \"false\" ]]; then
  system_disable_hyperthreading \$SOCA_HOST_SYSTEM_LOG/rc_local.log 2>&1
fi

/bin/bash /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ComputeNodeUserCustomization.sh >> $SOCA_HOST_SYSTEM_LOG/ComputeNodeUserCustomization.log 2>&1

/bin/bash /apps/soca/$SOCA_CONFIGURATION/cluster_node_bootstrap/ComputeNodeConfigureMetrics.sh >> $SOCA_HOST_SYSTEM_LOG/ComputeNodeConfigureMetrics.log 2>&1

openpbs_start >> $SOCA_HOST_SYSTEM_LOG/rc_local.log 2>&1

" >> /etc/rc.local
  chmod +x /etc/rc.d/rc.local
  systemctl enable rc-local
}