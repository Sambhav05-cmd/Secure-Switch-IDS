FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    iputils-ping \
    iproute2 \
    net-tools \
    hping3 \
    python3 \
    && rm -rf /var/lib/apt/lists/*

COPY scanner.py /app/scanner.py

CMD ["tail", "-f", "/dev/null"]
