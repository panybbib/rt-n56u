#!/bin/sh
#mount -t tmpfs -o remount,rw,size=40M tmpfs /tmp

getconfig() {
adg_file="/etc/storage/adg.sh"

cat > "$adg_file" <<-\EEE
bind_host: 0.0.0.0
bind_port: 3030
auth_name: admin
auth_pass: admin
language: zh-cn
rlimit_nofile: 0
dns:
  bind_host: 0.0.0.0
  port: 5335
  protection_enabled: true
  filtering_enabled: true
  blocking_mode: nxdomain
  blocked_response_ttl: 10
  querylog_enabled: true
  ratelimit: 20
  ratelimit_whitelist: []
  refuse_any: true
  bootstrap_dns:
  - 223.5.5.5
  - 119.29.29.29
  all_servers: true
  allowed_clients: []
  disallowed_clients: []
  blocked_hosts: []
  parental_sensitivity: 0
  parental_enabled: false
  safesearch_enabled: false
  safebrowsing_enabled: false
  resolveraddress: ""
  upstream_dns:
  - 114.114.114.114
  - https://dns.alidns.com/dns-query
  - tls://dns.alidns.com:853
  - quic://i.passcloud.xyz:784
tls:
  enabled: false
  server_name: ""
  force_https: false
  port_https: 443
  port_dns_over_tls: 853
  certificate_chain: ""
  private_key: ""
filters:
- enabled: true
  url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
  name: AdGuard Simplified Domain Names filter
  id: 1
- enabled: true
  url: https://adaway.org/hosts.txt
  name: AdAway
  id: 2
- enabled: true
  url: https://anti-ad.net/easylist.txt
  name: anti-AD
  id: 3
- enabled: false
  url: https://www.malwaredomainlist.com/hostslist/hosts.txt
  name: MalwareDomainList.com Hosts List
  id: 4
user_rules: []
dhcp:
  enabled: false
  interface_name: ""
  gateway_ip: ""
  subnet_mask: ""
  range_start: ""
  range_end: ""
  lease_duration: 86400
  icmp_timeout_msec: 1000
clients: []
log_file: ""
verbose: false
schema_version: 3
EEE

chmod 755 "$adg_file"
}

dl_adg() {
[ -d "/tmp/AdGuardHome" ] || mkdir -p /tmp/AdGuardHome
chmod 777 /tmp/AdGuardHome/
if [ ! -f "/tmp/AdGuardHome/AdGuardHome" ]; then
	if [ -f "/etc_ro/AdGuardHome.tar.bz2" ]; then
		tar -jxvf /etc_ro/AdGuardHome.tar.bz2 -C /tmp/AdGuardHome/
	else
		logger -t "AdGuardHome" "下载AdGuardHome"
		url="https://raw.githubusercontent.com/panybbib/rt-n56u/master/trunk/user/adguardhome/AdGuardHome"

		wget --no-check-certificate -q -t 3 -O /tmp/AdGuardHome/AdGuardHome $url
		#curl -k -s -o /tmp/AdGuardHome/AdGuardHome --connect-timeout 10 --retry 3 $url
	fi
fi

if [ ! -f "/tmp/AdGuardHome/AdGuardHome" ]; then
	logger -t "AdGuardHome" "AdGuardHome加载失败，请检查是否能正常访问github!程序将退出。"
	nvram set adg_enable=0
	exit 1
else
	logger -t "AdGuardHome" "AdGuardHome加载成功。"
	chmod 755 /tmp/AdGuardHome/AdGuardHome
fi
}

rst_adg() {
if [ "$(nvram get sdns_enable)" -eq 1 ]; then
	/usr/bin/smartdns.sh start &
else
	/sbin/restart_dhcpd &
fi
}

case $1 in
conf)
	getconfig
	;;
dl)
	dl_adg
	;;
rst)
	rst_adg
	;;
*)
	echo "check"
	;;
esac
