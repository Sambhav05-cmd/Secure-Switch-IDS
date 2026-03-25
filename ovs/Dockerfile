FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    openvswitch-switch \
    net-tools iputils-ping \
    && rm -rf /var/lib/apt/lists/*

COPY setup_ovs.sh /setup_ovs.sh
RUN chmod +x /setup_ovs.sh

CMD ["/setup_ovs.sh"]
