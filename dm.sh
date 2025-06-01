#!/bin/bash

while true; do
    if grep -q "172.31.0.2" /etc/resolv.conf; then
        sed -i 's/172.31.0.2/1.1.1.1/g' /etc/resolv.conf
        systemctl restart systemd-resolved
    fi
    sleep 2
done
