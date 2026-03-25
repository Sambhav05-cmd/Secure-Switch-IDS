FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    snort \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/log/snort

COPY snort.conf /etc/snort/snort.conf
COPY local.rules /etc/snort/rules/local.rules
COPY start.sh /start.sh
RUN chmod +x /start.sh

CMD ["/start.sh"]