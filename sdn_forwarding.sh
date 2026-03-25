# Show empty flow table
docker exec ovs-switch ovs-ofctl -O OpenFlow13 dump-flows br0

# Ping to trigger MAC learning
docker exec node1 ping -c 4 10.0.0.2

# Show flows got installed by controller
docker exec ovs-switch ovs-ofctl -O OpenFlow13 dump-flows br0
