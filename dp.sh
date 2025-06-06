#!/bin/bash

while true; do
    if grep -Eq "10\.0\.0\.2|172\.31\.0\.2" /etc/resolv.conf; then
        sed -i 's/10\.0\.0\.2/181.197.49.122/g; s/172\.31\.0\.2/181.197.49.122/g' /etc/resolv.conf
        systemctl restart systemd-resolved
    fi
    sleep 2
done
