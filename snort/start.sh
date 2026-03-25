#!/bin/bash

echo "[*] Snort container started. Waiting for snort0 interface to be moved in by run.sh..."
echo "[*] This is expected — snort0 is wired in AFTER containers start."

while ! ip link show snort0 > /dev/null 2>&1; do
    echo "[*] snort0 not found yet, retrying in 2s..."
    sleep 2
done

echo "[✔] snort0 found! Bringing interface up..."
ip link set snort0 up

echo "[✔] Starting Snort on snort0..."

while true; do
    snort -i snort0 -c /etc/snort/snort.conf -A fast -l /var/log/snort
    EXIT_CODE=$?
    echo "[!] Snort exited with code $EXIT_CODE. Restarting in 3s..."
    sleep 3
done