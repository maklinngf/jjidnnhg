enen#!/bin/bash


PORT="${1:-23100}"

DOH=()
DOH+=("1.1.1.1")
DOH+=("8.8.8.8")
DOH+=("https://doh.opendns.com/dns-query")
DOH+=("https://cloudflare-dns.com/dns-query")
DOH+=("https://doh.dns.sb/dns-query")
DOH+=("https://doh.cleanbrowsing.org/doh/family-filter/")
DOH+=("https://doh.mullvad.net/dns-query")
DOH+=("https://dns.alidns.com/dns-query")
DOH+=("https://doh.pub/dns-query")
DOH+=("https://dns.nextdns.io/")


[ -f "/usr/bin/gost" ] || {
  which wget >/dev/null 2>&1
  [ "$?" -eq 0 ] || exit 1
  wget -qO- "https://github.com/ginuerzh/gost/releases/download/v2.12.0/gost_2.12.0_linux_amd64.tar.gz" |tar -C /usr/bin -zxv gost && chmod -R 777 /usr/bin/gost || exit 1
}

i=0;
for doh in "${DOH[@]}"; do
  port=$((PORT+i))
  echo "${port} --> ${doh}"
  /usr/bin/gost -L="socks5://:${port}?dns=${doh}" >/dev/null 2>&1 &
  i=$((i+1))
done
