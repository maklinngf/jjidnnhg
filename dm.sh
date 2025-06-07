#!/bin/bash

while true; do
    if grep -Eq "10\.0\.0\.2|172\.31\.0\.2" /etc/resolv.conf; then
        sed -i 's/10\.0\.0\.2/1.1.1.1\nnameserver 8.8.8.8/g; s/172\.31\.0\.2/1.1.1.1\nnameserver 8.8.8.8/g' /etc/resolv.conf
        systemctl restart systemd-resolved
    fi
    sleep 2
done
