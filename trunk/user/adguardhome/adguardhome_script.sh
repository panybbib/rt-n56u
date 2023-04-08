#!/bin/sh

getconfig() {
adg_file="/etc/storage/adg.sh"

cat > "$adg_file" <<-\EEE
bind_host: 0.0.0.0
bind_port: 3030
auth_name: admin
auth_pass: admin
web_session_ttl: 168
language: zh-cn
rlimit_nofile: 0
dns:
  bind_host: 0.0.0.0
  port: 5335
  protection_enabled: true
  filtering_enabled: true
  parental_sensitivity: 0
  parental_enabled: false
  safesearch_enabled: false
  safebrowsing_enabled: false
  querylog_enabled: true
  querylog_interval: 7
  statistics_interval: 7
  ratelimit: 20
  ratelimit_whitelist: []
  refuse_any: true
  bootstrap_dns:
  - 223.5.5.5
  - 119.29.29.29
  all_servers: true
  fastest_addr: false
  upstream_dns:
  - 114.114.114.114
  - https://dns.alidns.com/dns-query
  - tls://dns.alidns.com:853
  - quic://i.passcloud.xyz:784
  blocking_mode: nxdomain
  blocked_response_ttl: 10
  edns_client_subnet: false
  enable_dnssec: false
  aaaa_disabled: false
  cache_size: 4194304
  cache_ttl_min: 60
  cache_ttl_max: 86400
  cache_optimistic: true
  allowed_clients: []
  disallowed_clients: []
  blocked_hosts: []
  resolveraddress: ""
tls:
  enabled: false
  server_name: ""
  force_https: false
  port_https: 443
  port_dns_over_tls: 853
  port_dns_over_quic: 853
  certificate_chain: ""
  private_key: ""
filters:
- enabled: false
  url: https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt
  name: AdGuard Simplified Domain Names filter
  id: 1
- enabled: false
  url: https://adaway.org/hosts.txt
  name: AdAway
  id: 2
- enabled: true
  url: https://anti-ad.net/easylist.txt
  name: anti-AD
  id: 3
- enabled: true
  url: https://cdn.jsdelivr.net/gh/o0HalfLife0o/list@master/ad.txt
  name: HalfLife
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
schema_version: 11
EEE

chmod 755 "$adg_file"
}

ro_adg() {
if [ -f "/etc_ro/AdGuardHome.tar.bz2" ]; then
	logger -t "AdGuardHome" "使用内置AdGuardHome程序"
	tar -jxvf /etc_ro/AdGuardHome.tar.bz2 -C /tmp/AdGuardHome/
	return 0
else
	return 1
fi
}

dl_adg() {
[ -d "/tmp/AdGuardHome" ] || mkdir -p /tmp/AdGuardHome
chmod 777 /tmp/AdGuardHome/
if [ ! -x "/tmp/AdGuardHome/AdGuardHome" ]; then
	if [ ! -s "/tmp/AdGuardHome/AdGuardHome" ]; then
		if [ "$(ping 114.114.114.114 -c 1 -w 10 | grep -o ttl)" ] || [ "$(ping 8.8.8.8 -c 1 -w 10 | grep -o ttl)" ]; then
			logger -t "AdGuardHome" "下载AdGuardHome"
			ver="v0.107.27"
			url="https://github.com/AdguardTeam/AdGuardHome/releases/download/$ver/AdGuardHome_linux_mipsle_softfloat.tar.gz"

			wget --no-check-certificate -q -t 3 -O "/tmp/AdGuardHome.tar.gz" $url
			#curl -k -s -o /tmp/AdGuardHome/AdGuardHome --connect-timeout 10 --retry 3 $url
			if [ $? -ne 0 ]; then
				logger -t "AdGuardHome" "网络URL连接受阻，AdGuardHome下载失败" && dlerr=1
			else
				logger -t "AdGuardHome" "AdGuardHome下载完成" && dlerr=0
			fi
		else
			logger -t "AdGuardHome" "设备未联网，无法下载程序,请检查网络连接后再尝试!" && dlerr=1
		fi
		if [ $dlerr -eq 0 ]; then
			tar -zxvf /tmp/AdGuardHome.tar.gz -C /tmp
			rm -f /tmp/AdGuardHome.tar.gz
		else
			ro_adg
			if [ $? -ne 0 ]; then
				logger -t "AdGuardHome" "无法加载AdGuardHome程序,请尝试手动加载!" && exit 1
			fi

		fi
	fi
	chmod 755 /tmp/AdGuardHome/AdGuardHome
fi
}

case $1 in
conf)
	getconfig
	;;
dl)
	dl_adg
	;;
*)
	echo "check"
	;;
esac
