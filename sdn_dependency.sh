# Stop controller
docker compose stop controller

# Flush all flows
docker exec ovs-switch ovs-ofctl -O OpenFlow13 del-flows br0

# Ping fails — switch has no rules
docker exec node1 ping -c 2 10.0.0.2

# Restart controller
docker compose start controller
sleep 3

# Ping works again — controller reprogrammed the switch
docker exec node1 ping -c 4 10.0.0.2
