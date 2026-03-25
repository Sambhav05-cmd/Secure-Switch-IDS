#!/bin/bash
set -e

# Start OVS daemons
/etc/init.d/openvswitch-switch start
sleep 2

# Create bridge
ovs-vsctl add-br br0
ovs-vsctl set bridge br0 protocols=OpenFlow13

# Point to os-ken controller (service name from docker-compose)
ovs-vsctl set-controller br0 tcp:controller:6633

echo "OVS bridge br0 ready, connected to controller"

# Keep container alive
tail -f /dev/null
