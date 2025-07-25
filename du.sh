#!/bin/bash

while true; do
    if grep -Eq "127\.0\.0\.53|172\.31\.0\.2" /etc/resolv.conf; then
        sed -i 's/127\.0\.0\.53/4.2.2.2\nnameserver 4.2.2.4/g; s/172\.31\.0\.2/4.2.2.2\nnameserver 4.2.2.4/g' /etc/resolv.conf
        systemctl restart systemd-resolved
    fi
    sleep 2
done
