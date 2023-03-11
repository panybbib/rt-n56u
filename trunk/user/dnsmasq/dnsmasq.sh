#!/bin/sh

min_ttl=`nvram get dhcp_min_ttl`
sed -i '/min-ttl/d' /etc/storage/dnsmasq/dnsmasq.conf
cat >>/etc/storage/dnsmasq/dnsmasq.conf <<EOF
min-ttl=$min_ttl
EOF
