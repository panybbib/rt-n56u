#!/bin/sh

adgscp=/etc/storage/adguardhome_script.sh

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
	if [ "$(nvram get adg_enable)" = 1 ]; then
		if [ -z "$(pidof AdGuardHome)" ]; then
			logger -t "AdGuardHome" "程序加载中，请稍等..."
			$adgscp dl
			if [ $? -ne 0 ]; then
				stop_adg
				nvram set adg_enable=0 && exit 1
			else
				$adgscp conf
				set_iptable
				change_dns
				logger -t "AdGuardHome" "运行AdGuardHome"
				eval "/tmp/AdGuardHome/AdGuardHome -c /etc/storage/adg.sh -w /tmp/AdGuardHome -v" &
			fi
		fi
	fi
}

stop_adg() {
	logger -t "AdGuardHome" "关闭程序..."
	killall -q AdGuardHome >/dev/null 2>&1
	adg_process=$(pidof AdGuardHome)
	if [ -n "$adg_process" ]; then
		kill -9 "$adg_process" >/dev/null 2>&1
	fi
	clear_iptable
	del_dns
}
	
case $1 in
start)
	start_adg
	;;
stop)
	stop_adg
	[ -d "/tmp/AdGuardHome/data" ] && /rm -rf /tmp/AdGuardHome
	;;
dnss)
	change_dns
	;;
*)
	echo "check"
	;;
esac
