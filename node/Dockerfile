FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    net-tools iputils-ping iproute2 \
    && rm -rf /var/lib/apt/lists/*

CMD ["tail", "-f", "/dev/null"]
