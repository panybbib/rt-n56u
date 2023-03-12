#!/bin/sh

filter_aaaa=`nvram get dhcp_filter_aaaa`
if [ $filter_aaaa = 0 ]; then
	sed -i '/filter-aaaa/d' /etc/storage/dnsmasq/dnsmasq.conf
else 
	sed -i '/filter-aaaa/d' /etc/storage/dnsmasq/dnsmasq.conf
	cat >>/etc/storage/dnsmasq/dnsmasq.conf <<-EOF
	filter-aaaa
EOF
fi
min_ttl=`nvram get dhcp_min_ttl`
sed -i '/min-ttl/d' /etc/storage/dnsmasq/dnsmasq.conf
cat >>/etc/storage/dnsmasq/dnsmasq.conf <<EOF
min-ttl=$min_ttl
EOF

