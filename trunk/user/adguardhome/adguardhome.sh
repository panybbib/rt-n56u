#!/bin/sh

NAME=AdGuardHome

change_dns() {
	if [ "$(nvram get adg_redirect)" = 1 ]; then
		sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
		sed -i '/server=127.0.0.1/d' /etc/storage/dnsmasq/dnsmasq.conf
		cat >> /etc/storage/dnsmasq/dnsmasq.conf <<-EOF
		no-resolv
		server=127.0.0.1#5335
		EOF
		/sbin/restart_dhcpd
		logger -t "AdGuardHome" "添加DNS转发到5335端口"
	fi
}

del_dns() {
	sed -i '/no-resolv/d' /etc/storage/dnsmasq/dnsmasq.conf
	sed -i '/server=127.0.0.1#5335/d' /etc/storage/dnsmasq/dnsmasq.conf
	/sbin/restart_dhcpd
}

set_iptable() {
	if [ "$(nvram get adg_redirect)" = 2 ]; then
		IPS="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
		for IP in $IPS
		do
			iptables -t nat -A PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
			iptables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
		done

		IPS="`ifconfig | grep "inet6 addr" | grep -v " fe80::" | grep -v " ::1" | grep "Global" | awk '{print $3}'`"
		for IP in $IPS
		do
			ip6tables -t nat -A PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
			ip6tables -t nat -A PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports 5335 >/dev/null 2>&1
		done
		logger -t "AdGuardHome" "重定向53端口"
	fi
}

clear_iptable() {
	OLD_PORT="5335"
	IPS="`ifconfig | grep "inet addr" | grep -v ":127" | grep "Bcast" | awk '{print $2}' | awk -F : '{print $2}'`"
	for IP in $IPS
	do
		iptables -t nat -D PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
		iptables -t nat -D PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
	done

	IPS="`ifconfig | grep "inet6 addr" | grep -v " fe80::" | grep -v " ::1" | grep "Global" | awk '{print $3}'`"
	for IP in $IPS
	do
		ip6tables -t nat -D PREROUTING -p udp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
		ip6tables -t nat -D PREROUTING -p tcp -d $IP --dport 53 -j REDIRECT --to-ports $OLD_PORT >/dev/null 2>&1
	done
}

start_adg() {
	if [ -z "$(pidof $NAME)" ]; then
		logger -t "AdGuardHome" "程序加载中，请稍等..."
		/etc/storage/adguardhome_script.sh
		if [ $? -ne 0 ]; then
			logger -t "AdGuardHome" "加载失败，可能是程序下载出错！"
			stop_adg
			exit 1
		fi
	fi
	change_dns
	set_iptable
	logger -t "AdGuardHome" "运行AdGuardHome"
	eval "/tmp/AdGuardHome/AdGuardHome -c /etc/storage/adg.sh -w /tmp/AdGuardHome -v" &
	sleep 10
	[ "$(nvram get sdns_enable)" -eq 1 ] && /usr/bin/smartdns.sh start &
}

stop_adg() {
	adg_process=$(pidof $NAME)
	if [ -n "$adg_process" ]; then
		logger -t "AdGuardHome" "关闭程序..."
		killall -q $NAME >/dev/null 2>&1
		kill -9 "$adg_process" >/dev/null 2>&1
	fi
	[ -z "$(pidof $NAME)" ] && rm -rf /tmp/AdGuardHome
	del_dns
	clear_iptable
}
	
case $1 in
start)
	start_adg
	;;
stop)
	stop_adg
	;;
*)
	echo "check"
	;;
esac
