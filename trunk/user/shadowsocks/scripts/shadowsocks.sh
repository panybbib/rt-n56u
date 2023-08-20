#!/bin/sh
#
# Copyright (C) 2017 openwrt-ssr
# Copyright (C) 2017 yushi studio <ywb94@qq.com>
# Copyright (C) 2018 lean <coolsnowwolf@gmail.com>
# Copyright (C) 2019 chongshengB <bkye@vip.qq.com>
#
# This is free software, licensed under the GNU General Public License v3.
# See /LICENSE for more information.
#

NAME=shadowsocksr
trojan_local=`nvram get trojan_local`
trojan_link=`nvram get trojan_link`
v2ray_local=`nvram get v2_local`
v2ray_link=`nvram get v2_link`
http_username=`nvram get http_username`
CONFIG_FILE=/tmp/${NAME}.json
CONFIG_UDP_FILE=/tmp/${NAME}_u.json
CONFIG_SOCK5_FILE=/tmp/${NAME}_s.json
v2_json_file="/tmp/v2-redir.json"
trojan_json_file="/tmp/tj-redir.json"
server_count=0
redir_tcp=0
trojan_enable=0
v2ray_enable=0
redir_udp=0
tunnel_enable=0
local_enable=0
pdnsd_enable_flag=0
chinadnsng_enable_flag=0
wan_bp_ips="/tmp/whiteip.txt"
wan_fw_ips="/tmp/blackip.txt"
lan_fp_ips="/tmp/lan_ip.txt"
lan_gm_ips="/tmp/lan_gmip.txt"
run_mode=`nvram get ss_run_mode`
ss_turn=`nvram get ss_turn`
lan_con=`nvram get lan_con`
GLOBAL_SERVER=`nvram get global_server`
socks=""

log() {
	logger -t "$NAME" "$@"
	echo "$(date "+%Y-%m-%d %H:%M:%S") $@" >> "/tmp/ssrplus.log"
}

find_bin() {
	case "$1" in
	ss) ret="/usr/bin/ss-redir" ;;
	ss-local) ret="/usr/bin/ss-local" ;;
	ssr) ret="/usr/bin/ssr-redir" ;;
	ssr-local) ret="/usr/bin/ssr-local" ;;
	ssr-server) ret="/usr/bin/ssr-server" ;;
	socks5) ret="/usr/bin/ipt2socks" ;;
	trojan)
		if [ -f "/usr/bin/trojan" ] ; then
			ret="/usr/bin/trojan"
		else
			ret="$trojan_local"
		fi
	;;
	v2ray|xray)
		bin2=$(echo -e "v2ray\nxray" | grep -v $1)
		if [ -f "/usr/bin/$1" ]; then
			ret="/usr/bin/$1"
		elif [ -f "/usr/bin/$bin2" ]; then
			ret="/usr/bin/$bin2"
		else
			ret="$v2ray_local"
		fi
	;;
	esac
	echo $ret
}

gen_config_file() {

	fastopen="false"
	case "$2" in
	0) config_file=$CONFIG_FILE && local stype=$(nvram get d_type) ;;
	1) config_file=$CONFIG_UDP_FILE && local stype=$(nvram get ud_type) ;;
	*) config_file=$CONFIG_SOCK5_FILE && local stype=$(nvram get s5_type) ;;
	esac
	local type=$stype
	case "$type" in
	ss)
		lua /etc_ro/ss/genssconfig.lua $1 $3 >$config_file
		sed -i 's/\\//g' $config_file
		;;
	ssr)
		lua /etc_ro/ss/genssrconfig.lua $1 $3 >$config_file
		sed -i 's/\\//g' $config_file
		;;
	trojan)
		if [ ! -f "/usr/bin/trojan" ]; then
			if [ ! -s "$trojan_local" ]; then
				curl -k -s -o $trojan_local --connect-timeout 10 --retry 3 $trojan_link
				if [ -s "$trojan_local" ] && [ `grep -c "404 Not Found" "$trojan_local"` == '0' ]; then
                			chmod -R 777 $trojan_local
					log "trojan二进制文件下载成功"
				else
					log "trojan二进制文件下载失败，可能是地址失效或者网络异常！"
					rm -f $trojan_local
					ssp_close && exit 1
				fi
			fi
		fi
		trojan_enable=1
		if [ "$2" = "0" ]; then
			lua /etc_ro/ss/gentrojanconfig.lua $1 nat 1080 >$trojan_json_file
			sed -i 's/\\//g' $trojan_json_file
		else
			lua /etc_ro/ss/gentrojanconfig.lua $1 client 10801 >/tmp/trojan-ssr-reudp.json
			sed -i 's/\\//g' /tmp/trojan-ssr-reudp.json
		fi
		;;
	v2ray)
		if [ ! -f "/usr/bin/v2ray" ]; then
			if [ ! -s "$v2ray_local" ];then
				curl -k -s -o $v2ray_local --connect-timeout 10 --retry 3 $v2ray_link
				if [ -s "$v2ray_local" ] && [ `grep -c "404 Not Found" "$v2ray_local"` == '0' ]; then
                			chmod -R 777 $v2ray_local
					log "v2ray二进制文件下载成功"
				else
					log "v2ray二进制文件下载失败，可能是地址失效或者网络异常！"
					rm -f $v2ray_local
					ssp_close && exit 1
				fi
			fi
		fi
		v2ray_enable=1
		if [ "$2" = "1" ]; then
			lua /etc_ro/ss/genv2config.lua $1 udp 1080 >/tmp/v2-ssr-reudp.json
			sed -i 's/\\//g' /tmp/v2-ssr-reudp.json
		else
			lua /etc_ro/ss/genv2config.lua $1 tcp 1080 >$v2_json_file
			sed -i 's/\\//g' $v2_json_file
		fi
		;;
	xray)
		v2ray_enable=1
		if [ "$2" = "1" ]; then
			lua /etc_ro/ss/genxrayconfig.lua $1 udp 1080 >/tmp/v2-ssr-reudp.json
			sed -i 's/\\//g' /tmp/v2-ssr-reudp.json
		else
			lua /etc_ro/ss/genxrayconfig.lua $1 tcp 1080 >$v2_json_file
			sed -i 's/\\//g' $v2_json_file
		fi
		;;
	esac
}

get_arg_out() {
	router_proxy="1"
	case "$router_proxy" in
	1) echo "-o" ;;
	2) echo "-O" ;;
	esac
}

start_rules() {
    log "正在添加防火墙规则..."
	lua /etc_ro/ss/getconfig.lua $GLOBAL_SERVER > /tmp/server.txt
	server=`cat /tmp/server.txt` 
	cat /etc/storage/ss_ip.sh | grep -v '^!' | grep -v "^$" >$wan_fw_ips
	cat /etc/storage/ss_wan_ip.sh | grep -v '^!' | grep -v "^$" >$wan_bp_ips
	#resolve name
	if echo $server | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" >/dev/null; then
		server=${server}
	elif [ "$server" != "${server#*:[0-9a-fA-F]}" ]; then
		server=${server}
	else
		server=$(resolveip -4 -t 3 $server | awk 'NR==1{print}')
		if echo $server | grep -E "^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$" >/dev/null; then
			echo $server >/etc/storage/ssr_ip
		else
			server=$(cat /etc/storage/ssr_ip)
		fi
	fi
	local_port="1080"
	lan_ac_ips=$lan_ac_ips
	lan_ac_mode="b"
	#if [ "$GLOBAL_SERVER" == "$UDP_RELAY_SERVER" ]; then
	#	ARG_UDP="-u"
	if [ "$UDP_RELAY_SERVER" != "nil" ]; then
		ARG_UDP="-U"
		lua /etc_ro/ss/getconfig.lua $UDP_RELAY_SERVER > /tmp/userver.txt
	    udp_server=`cat /tmp/userver.txt` 
		udp_local_port="1080"
	fi
	if [ -n "$lan_ac_ips" ]; then
		case "$lan_ac_mode" in
		w | W | b | B) ac_ips="$lan_ac_mode$lan_ac_ips" ;;
		esac
	fi
	#ac_ips="b"
	gfwmode=""
	if [ "$run_mode" = "gfw" ]; then
		gfwmode="-g"
	elif [ "$run_mode" = "router" ]; then
		gfwmode="-r"
	elif [ "$run_mode" = "oversea" ]; then
		gfwmode="-c"
	elif [ "$run_mode" = "all" ]; then
		gfwmode="-z"
	fi
	if [ "$lan_con" = "0" ]; then
		rm -f $lan_fp_ips
		lancon="all"
		lancons="全部IP走代理"
		cat /etc/storage/ss_lan_ip.sh | grep -v '^!' | grep -v "^$" >$lan_fp_ips
	elif [ "$lan_con" = "1" ]; then
		rm -f $lan_fp_ips
		lancon="bip"
		lancons="指定IP走代理,请到规则管理页面添加需要走代理的IP。"
		cat /etc/storage/ss_lan_bip.sh | grep -v '^!' | grep -v "^$" >$lan_fp_ips
	fi
	rm -f $lan_gm_ips
	cat /etc/storage/ss_lan_gmip.sh | grep -v '^!' | grep -v "^$" >$lan_gm_ips
	dports=$(nvram get s_dports)
	if [ $dports = "0" ]; then
		proxyport="--syn"
	else
		proxyport="-m multiport --dports 22,53,587,465,995,993,143,80,443,3389 --syn"
	fi
	/usr/bin/ss-rules \
		-s "$server" \
		-l "$local_port" \
		-S "$udp_server" \
		-L "$udp_local_port" \
		-a "$ac_ips" \
		-i "" \
		-b "$wan_bp_ips" \
		-w "$wan_fw_ips" \
		-p "$lan_fp_ips" \
		-G "$lan_gm_ips" \
		-G "$lan_gm_ips" \
		-D "$proxyport" \
		-k "$lancon" \
		$(get_arg_out) $gfwmode $ARG_UDP
	return $?
}

start_redir_tcp() {
	ARG_OTA=""
	gen_config_file $GLOBAL_SERVER 0 1080
	stype=$(nvram get d_type)
	local bin=$(find_bin $stype)
	[ ! -f "$bin" ] && log "Main node:Can't find $bin program, can't start!" && return 1
	if [ "$(nvram get ss_threads)" = "0" ]; then
		threads=$(cat /proc/cpuinfo | grep 'processor' | wc -l)
	else
		threads=$(nvram get ss_threads)
	fi
	log "启动 $stype 主服务器..."
	case "$stype" in
	ss | ssr)
		last_config_file=$CONFIG_FILE
		pid_file="/tmp/ssr-retcp.pid"
		for i in $(seq 1 $threads); do
			$bin -c $CONFIG_FILE $ARG_OTA -f /tmp/ssr-retcp_$i.pid >/dev/null 2>&1
			usleep 500000
		done
		redir_tcp=1
		log "Shadowsocks/ShadowsocksR $threads 线程启动成功!"
		;;
	trojan)
		for i in $(seq 1 $threads); do
			$bin --config $trojan_json_file >>/tmp/ssrplus.log 2>&1 &
			usleep 500000
		done
		log "$($bin --version 2>&1 | head -1) 启动成功!"
		;;
	v2ray)
		$bin -config $v2_json_file >/dev/null 2>&1 &
		log "$($bin -version | head -1) 启动成功!"
		;;
	xray)
		$bin -config $v2_json_file >/dev/null 2>&1 &
		log "$($bin -version | head -1) 启动成功!"
		;;	
	socks5)
		for i in $(seq 1 $threads); do
			lua /etc_ro/ss/gensocks.lua $GLOBAL_SERVER 1080 >/dev/null 2>&1 &
			usleep 500000
		done
	    ;;
	esac
	return 0
}

start_redir_udp() {
	if [ "$UDP_RELAY_SERVER" != "nil" ]; then
		redir_udp=1
		utype=$(nvram get ud_type)
		log "启动 $utype 游戏 UDP 中继服务器"
		local bin=$(find_bin $utype)
		[ ! -f "$bin" ] && log "UDP TPROXY Relay:Can't find $bin program, can't start!" && return 1
		case "$utype" in
		ss | ssr)
			ARG_OTA=""
			gen_config_file $UDP_RELAY_SERVER 1 1080
			last_config_file=$CONFIG_UDP_FILE
			pid_file="/var/run/ssr-reudp.pid"
			$bin -c $last_config_file $ARG_OTA -U -f /var/run/ssr-reudp.pid >/dev/null 2>&1
			;;
		v2ray)
			gen_config_file $UDP_RELAY_SERVER 1
			$bin -config /tmp/v2-ssr-reudp.json >/dev/null 2>&1 &
			;;
		xray)
			gen_config_file $UDP_RELAY_SERVER 1
			$bin -config /tmp/v2-ssr-reudp.json >/dev/null 2>&1 &
			;;	
		trojan)
			gen_config_file $UDP_RELAY_SERVER 1
			$bin --config /tmp/trojan-ssr-reudp.json >/dev/null 2>&1 &
			ipt2socks -U -b 0.0.0.0 -4 -s 127.0.0.1 -p 10801 -l 1080 >/dev/null 2>&1 &
			;;
		socks5)
			echo "1"
		    ;;
		esac
	fi
	return 0
	}
	ss_switch=$(nvram get backup_server)
	if [ $ss_switch != "nil" ]; then
		switch_time=$(nvram get ss_turn_s)
		switch_timeout=$(nvram get ss_turn_ss)
		#/usr/bin/ssr-switch start $switch_time $switch_timeout &
		socks="-o"
	fi
	#return $?

sdns_on () {
if [ "$(nvram get sdns_enable)" = 1 ]; then
	sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
	sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
	sdns_port=`nvram get sdns_port`
	cat >> /etc/storage/dnsmasq/dnsmasq.conf << EOF
no-resolv
server=127.0.0.1#$sdns_port
EOF
	logger -t "SmartDNS" "添加DNS转发到$sdns_port端口"
	[ "$(nvram get sdns_enable)" = 1 ] && /usr/bin/smartdns.sh restart
	[ "$(nvram get adg_enable)" = 1 ] && /usr/bin/adguardhome.sh dnss
fi
}

sdns_off () {
	sdns_process=`pidof smartdns`
	if [ -n "$sdns_process" ]; then
		rm -f /tmp/whitelist.conf
		rm -f /tmp/blacklist.conf
		killall smartdns >/dev/null 2>&1
		kill -9 "$sdns_process" >/dev/null 2>&1
		ipset -X smartdns 2>/dev/null
		sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
		sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
		sdns_port=`nvram get sdns_port`
		sdns_ipv6_server=`nvram get sdns_ipv6_server`
		clear_iptable $sdns_port $sdns_ipv6_server
		/sbin/restart_dhcpd
	fi
}

clear_iptable () {
	local OLD_PORT="$1"
	local ipv6_server=$2
	IPS="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
	for IP in $IPS
	do
		iptables -t nat -D PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
		iptables -t nat -D PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
	done

	if [ "$ipv6_server" == 0 ]; then
		return
	fi

	IPS="`ifconfig | grep "inet6 addr" | grep -v " fe80::" | grep -v " ::1" | grep "Global" | awk '{print $3}'`"
	for IP in $IPS
	do
		ip6tables -t nat -D PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
		ip6tables -t nat -D PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
	done
}

stop_dns_proxy() {
	pgrep dns2tcp | args kill
	pgrep dnsproxy | args kill	
}

start_dns_proxy() {
	pdnsd_enable="$(nvram get pdnsd_enable)" # 1: dnsproxy , 2: dns2tcp
	pdnsd_enable_flag=$pdnsd_enable
	dnsstr="$(nvram get tunnel_forward)"
	dnsserver=$(echo "$dnsstr" | awk -F '#' '{print $1}')
	if [ $pdnsd_enable = 2 ]; then
	    log "启动 dns2tcp：5353 端口..."
		# 将dnsserver (上游国外DNS: 比如 8.8.8.8) 放入ipset:gfwlist，强制走SS_SPEC_WAN_FW代理
		ipset add gfwlist $dnsserver 2>/dev/null
		dns2tcp -L"127.0.0.1#5353" -R"$dnsserver" >/dev/null 2>&1 &
	elif [ $pdnsd_enable = 1 ]; then
		log "启动 dnsproxy：5353 端口..."
		# 将dnsserver (上游国外DNS: 比如 8.8.8.8) 放入ipset:gfwlist，强制走SS_SPEC_WAN_FW代理
		ipset add gfwlist $dnsserver 2>/dev/null
		dnsproxy -d -p 5353 -R $dnsserver >/dev/null 2>&1 &
	else
		log "DNS解析方式不支持该选项: $pdnsd_enable , 请手动选择其他DNS"
	fi
}

start_dns() {
	echo "create china hash:net family inet hashsize 1024 maxelem 65536" >/tmp/china.ipset
	awk '!/^$/&&!/^#/{printf("add china %s'" "'\n",$0)}' /etc/storage/chinadns/chnroute.txt >>/tmp/china.ipset
	ipset -! flush china
	ipset -! restore </tmp/china.ipset 2>/dev/null
	rm -f /tmp/china.ipset
	start_chinadns() {
		ss_chdns=$(nvram get ss_chdns)
		if [ $ss_chdns = 1 ]; then
			chinadnsng_enable_flag=1
			local_chnlist_file='/etc/storage/chinadns/chnlist_mini.txt'
			if [ -f "$local_chnlist_file" ]; then
			  log "启动chinadns分流，仅国外域名走DNS代理..."
			  chinadns-ng -b 0.0.0.0 -l 65353 -c $(nvram get china_dns) -t 127.0.0.1#5353 -4 china -M -m $local_chnlist_file >/dev/null 2>&1 &
			else
			  log "启动chinadns分流，全部域名走DNS代理...本次不使用本地cdn域名文件$local_chnlist_file, 下次你自已可以创建它，文件中每行表示一个域名（不用要子域名）"
			  chinadns-ng -b 0.0.0.0 -l 65353 -c $(nvram get china_dns) -t 127.0.0.1#5353 -4 china >/dev/null 2>&1 &
			fi
			# adding upstream chinadns-ng 
			sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
			sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
			cat >> /etc/storage/dnsmasq/dnsmasq.conf << EOF
no-resolv
server=127.0.0.1#65353
EOF
		fi
		# dnsmasq optimization
		sed -i '/min-cache-ttl/d' /etc/storage/dnsmasq/dnsmasq.conf
		cat >> /etc/storage/dnsmasq/dnsmasq.conf << EOF
min-cache-ttl=1800
EOF
		# restart dnsmasq
		killall dnsmasq
		/user/sbin/dnsmasq >/dev/null 2>&1 &
	}
 
 	dnsstr="$(nvram get tunnel_forward)"
	dnsserver=$(echo "$dnsstr" | awk -F '#' '{print $1}')
	#dnsport=$(echo "$dnsstr" | awk -F '#' '{print $2}')
  	case "$run_mode" in
	router)
		if [ "$(nvram get pdnsd_enable)" != 0 ]; then
		sdns_off
		# 不论chinadns-ng打开与否，都重启dns_proxy 
		# 原因是针对gfwlist ipset有一个专有的dnsmasq配置表（由ss-rule创建放在/tmp/dnsmasq.dom/gfwlist_list.conf)
		# 需要查询上游dns_proxy在本地5353端口
		stop_dns_proxy
		start_dns_proxy
		start_chinadns
		else
		sdns_on
		fi
	;;
	gfw)
		if [ "$(nvram get pdnsd_enable)" != 0 ]; then
		sdns_off
		ipset add gfwlist $dnsserver 2>/dev/null
		stop_dns_proxy
		start_dns_proxy
		start_chinadns
		log "开始处理 gfwlist..."
		else
		sdns_on
		fi
	;;
	oversea)
		ipset add gfwlist $dnsserver 2>/dev/null
		mkdir -p /etc/storage/dnsmasq.oversea
		sed -i '/dnsmasq-ss/d' /etc/storage/dnsmasq/dnsmasq.conf
		sed -i '/dnsmasq.oversea/d' /etc/storage/dnsmasq/dnsmasq.conf
		cat >>/etc/storage/dnsmasq/dnsmasq.conf <<EOF
conf-dir=/etc/storage/dnsmasq.oversea
EOF
	;;
	*)
		ipset -N ss_spec_wan_ac hash:net 2>/dev/null
		ipset add ss_spec_wan_ac $dnsserver 2>/dev/null
	;;
	esac
	/sbin/restart_dhcpd
}

start_AD() {
	mkdir -p /tmp/dnsmasq.dom
	curl -k -s -o /tmp/adnew.conf --connect-timeout 10 --retry 3 $(nvram get ss_adblock_url)
	if [ ! -f "/tmp/adnew.conf" ]; then
		log "AD文件下载失败，可能是地址失效或者网络异常！"
	else
		log "AD文件下载成功"
		if [ -f "/tmp/adnew.conf" ]; then
			check = `grep -wq "address=" /tmp/adnew.conf`
	  		if [ ! -n "$check" ] ; then
	    		cp /tmp/adnew.conf /tmp/dnsmasq.dom/ad.conf
	  		else
			    cat /tmp/adnew.conf | grep ^\|\|[^\*]*\^$ | sed -e 's:||:address\=\/:' -e 's:\^:/0\.0\.0\.0:' > /tmp/dnsmasq.dom/ad.conf
			fi
		fi
	fi
	rm -f /tmp/adnew.conf
}

# ================================= 启动 Socks5代理 ===============================
start_local() {
	local s5_port=$(nvram get socks5_port)
	local local_server=$(nvram get socks5_enable)
	[ "$local_server" == "nil" ] && return 1
	[ "$local_server" == "same" ] && local_server=$GLOBAL_SERVER
	local type=$(nvram get s5_type)
	local bin=$(find_bin $type)
	[ ! -f "$bin" ] && log "Global_Socks5:Can't find $bin program, can't start!" && return 1
	case "$type" in
	ss | ssr)
		local name="Shadowsocks"
		local bin=$(find_bin ss-local)
		[ ! -f "$bin" ] && log "Global_Socks5:Can't find $bin program, can't start!" && return 1
		[ "$type" == "ssr" ] && name="ShadowsocksR"
		gen_config_file $local_server 3 $s5_port
		$bin -c $CONFIG_SOCK5_FILE -u -f /var/run/ssr-local.pid >/dev/null 2>&1
		log "Global_Socks5:$name Started!"
		;;
	v2ray)
		lua /etc_ro/ss/genv2config.lua $local_server tcp 0 $s5_port >/tmp/v2-ssr-local.json
		sed -i 's/\\//g' /tmp/v2-ssr-local.json
		$bin -config /tmp/v2-ssr-local.json >/dev/null 2>&1 &
		log "Global_Socks5:$($bin -version | head -1) Started!"
		;;
	xray)
		lua /etc_ro/ss/genxrayconfig.lua $local_server tcp 0 $s5_port >/tmp/v2-ssr-local.json
		sed -i 's/\\//g' /tmp/v2-ssr-local.json
		$bin -config /tmp/v2-ssr-local.json >/dev/null 2>&1 &
		log "Global_Socks5:$($bin -version | head -1) Started!"
		;;
	trojan)
		lua /etc_ro/ss/gentrojanconfig.lua $local_server client $s5_port >/tmp/trojan-ssr-local.json
		sed -i 's/\\//g' /tmp/trojan-ssr-local.json
		$bin --config /tmp/trojan-ssr-local.json >/dev/null 2>&1 &
		log "Global_Socks5:$($bin --version 2>&1 | head -1) Started!"
		;;
	*)
		[ -e /proc/sys/net/ipv6 ] && local listenip='-i ::'
		microsocks $listenip -p $s5_port ssr-local >/dev/null 2>&1 &
		log "Global_Socks5:$type Started!"
		;;
	esac
	local_enable=1
	return 0
}

rules() {
	[ "$GLOBAL_SERVER" = "nil" ] && return 1
	UDP_RELAY_SERVER=$(nvram get udp_relay_server)
	if [ "$UDP_RELAY_SERVER" = "same" ]; then
		UDP_RELAY_SERVER=$GLOBAL_SERVER
	fi
	if start_rules; then
		return 0
	else
		return 1
	fi
}

start_watchcat() {
	if [ $(nvram get ss_watchcat) = 1 ]; then
		let total_count=server_count+redir_tcp+redir_udp+tunnel_enable+trojan_enable+v2ray_enable+local_enable+pdnsd_enable_flag+chinadnsng_enable_flag
		if [ $total_count -gt 0 ]; then
			#param:server(count) redir_tcp(0:no,1:yes)  redir_udp tunnel kcp local gfw
			/usr/bin/ssr-monitor $server_count $redir_tcp $redir_udp $tunnel_enable $trojan_enable $v2ray_enable $local_enable $pdnsd_enable_flag $chinadnsng_enable_flag >/dev/null 2>&1 &
		fi
	fi
}

auto_update() {
	sed -i '/update_chnroute/d' /etc/storage/cron/crontabs/$http_username
	sed -i '/update_gfwlist/d' /etc/storage/cron/crontabs/$http_username
	sed -i '/ss-watchcat/d' /etc/storage/cron/crontabs/$http_username
	if [ $(nvram get ss_update_chnroute) = "1" ]; then
		cat >>/etc/storage/cron/crontabs/$http_username <<EOF
0 8 */10 * * /usr/bin/update_chnroute.sh > /dev/null 2>&1
EOF
	fi
	if [ $(nvram get ss_update_gfwlist) = "1" ]; then
		cat >>/etc/storage/cron/crontabs/$http_username <<EOF
0 7 */10 * * /usr/bin/update_gfwlist.sh > /dev/null 2>&1
EOF
	fi
}

# ================================= 启动 SS ===============================
ssp_start() { 
    ss_enable=`nvram get ss_enable`
	if rules; then
		if start_redir_tcp; then
			start_redir_udp
        	#start_rules
			#start_AD
			start_dns
		fi
	fi
	start_local
	start_watchcat
	auto_update
	ENABLE_SERVER=$(nvram get global_server)
	[ "$ENABLE_SERVER" = "nil" ] && return 1
	log "启动成功。"
	log "内网IP控制为: $lancons"
	nvram set check_mode=0
}

# ================================= 关闭SS ===============================

ssp_close() {
	rm -rf /tmp/cdn
	/usr/bin/ss-rules -f
	kill -9 $(ps | grep ssr-switch | grep -v grep | awk '{print $1}') >/dev/null 2>&1
	kill -9 $(ps | grep ssr-monitor | grep -v grep | awk '{print $1}') >/dev/null 2>&1
	kill_process
	sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
	sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
	sed -i '/cdn/d' /etc/storage/dnsmasq/dnsmasq.conf
	sed -i '/gfwlist/d' /etc/storage/dnsmasq/dnsmasq.conf
	sed -i '/dnsmasq.oversea/d' /etc/storage/dnsmasq/dnsmasq.conf
	if [ -f "/etc/storage/dnsmasq-ss.d" ]; then
		rm -f /etc/storage/dnsmasq-ss.d
	fi
	clear_iptable
	/sbin/restart_dhcpd
	[ -z "$(pidof smartdns)" ] && sdns_on
}


clear_iptable() {
	s5_port=$(nvram get socks5_port)
	iptables -t filter -D INPUT -p tcp --dport $s5_port -j ACCEPT
	iptables -t filter -D INPUT -p tcp --dport $s5_port -j ACCEPT
	ip6tables -t filter -D INPUT -p tcp --dport $s5_port -j ACCEPT
	ip6tables -t filter -D INPUT -p tcp --dport $s5_port -j ACCEPT
}

kill_process() {
	v2ray_process=$(pidof v2ray || pidof xray)
	if [ -n "$v2ray_process" ]; then
		log "关闭 V2Ray 进程..."
		killall v2ray xray >/dev/null 2>&1
		kill -9 "$v2ray_process" >/dev/null 2>&1
	fi
	ssredir=$(pidof ss-redir)
	if [ -n "$ssredir" ]; then
		log "关闭 ss-redir 进程..."
		killall ss-redir >/dev/null 2>&1
		kill -9 "$ssredir" >/dev/null 2>&1
	fi

	rssredir=$(pidof ssr-redir)
	if [ -n "$rssredir" ]; then
		log "关闭 ssr-redir 进程..."
		killall ssr-redir >/dev/null 2>&1
		kill -9 "$rssredir" >/dev/null 2>&1
	fi
	
	sslocal_process=$(pidof ss-local)
	if [ -n "$sslocal_process" ]; then
		log "关闭 ss-local 进程..."
		killall ss-local >/dev/null 2>&1
		kill -9 "$sslocal_process" >/dev/null 2>&1
	fi

	trojandir=$(pidof trojan)
	if [ -n "$trojandir" ]; then
		log "关闭 trojan 进程..."
		killall trojan >/dev/null 2>&1
		kill -9 "$trojandir" >/dev/null 2>&1
	fi
	
	ipt2socks_process=$(pidof ipt2socks)
	if [ -n "$ipt2socks_process" ]; then
		log "关闭 ipt2socks 进程..."
		killall ipt2socks >/dev/null 2>&1
		kill -9 "$ipt2socks_process" >/dev/null 2>&1
	fi

	socks5_process=$(pidof srelay)
	if [ -n "$socks5_process" ]; then
		log "关闭 socks5 进程..."
		killall srelay >/dev/null 2>&1
		kill -9 "$socks5_process" >/dev/null 2>&1
	fi

	ssrs_process=$(pidof ssr-server)
	if [ -n "$ssrs_process" ]; then
		log "关闭 ssr-server 进程..."
		killall ssr-server >/dev/null 2>&1
		kill -9 "$ssrs_process" >/dev/null 2>&1
	fi
	
	cnd_process=$(pidof chinadns-ng)
	if [ -n "$cnd_process" ]; then
		log "关闭 chinadns-ng 进程..."
		killall chinadns-ng >/dev/null 2>&1
		kill -9 "$cnd_process" >/dev/null 2>&1
	fi

	dns2tcp_process=$(pidof dns2tcp)
	if [ -n "$dns2tcp_process" ]; then
		log "关闭 dns2tcp 进程..."
		killall dns2tcp >/dev/null 2>&1
		kill -9 "$dns2tcp_process" >/dev/null 2>&1
	fi
	
	dnsproxy_process=$(pidof dnsproxy)
	if [ -n "$dnsproxy_process" ]; then
		log "关闭 dnsproxy 进程..."
		killall dnsproxy >/dev/null 2>&1
		kill -9 "$dnsproxy_process" >/dev/null 2>&1
	fi
	
	microsocks_process=$(pidof microsocks)
	if [ -n "$microsocks_process" ]; then
		log "关闭 socks5 服务端进程..."
		killall microsocks >/dev/null 2>&1
		kill -9 "$microsocks_process" >/dev/null 2>&1
	fi
}

# ================================= 重启 SS ===============================
ressp() {
	BACKUP_SERVER=$(nvram get backup_server)
	start_redir $BACKUP_SERVER
	start_rules $BACKUP_SERVER
	start_dns
	start_local
	start_watchcat
	auto_update
	ENABLE_SERVER=$(nvram get global_server)
	log "备用服务器启动成功"
	log "内网IP控制为: $lancons"
}

case $1 in
start)
	ssp_start
	;;
stop)
	killall -q -9 ssr-switch
	ssp_close
	;;
restart)
	ssp_close
	ssp_start
	;;
reserver)
	ssp_close
	ressp
	;;
*)
	echo "check"
	#exit 0
	;;
esac
