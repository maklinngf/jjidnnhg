#!/bin/bash
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
rm -rf /usr/local/etc/xray/config.json
wget -P /usr/local/etc/xray https://raw.githubusercontent.com/maklinngf/jjidnnhg/refs/heads/main/config.json
systemctl restart xray
