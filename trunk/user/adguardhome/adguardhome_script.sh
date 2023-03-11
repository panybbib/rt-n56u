#!/bin/sh

[ -d "/tmp/AdGuardHome" ] || mkdir -p /tmp/AdGuardHome
[ -d "/etc/storage/AdGuardHome" ] || mkdir -p /etc/storage/AdGuardHome
  
if [ ! -f "/tmp/AdGuardHome/AdGuardHome" ]; then
	logger -t "AdGuardHome" "下载AdGuardHome"
	url="https://raw.githubusercontent.com/panybbib/rt-n56u/master/trunk/user/adguardhome/AdGuardHome"
	wget --no-check-certificate -q -t 3 -O "/tmp/AdGuardHome/AdGuardHome" $url
fi

if [ ! -f "/tmp/AdGuardHome/AdGuardHome" ]; then
	logger -t "AdGuardHome" "AdGuardHome下载失败，请检查是否能正常访问github!程序将退出。"
	nvram set adg_enable=0
	exit 1
else
	logger -t "AdGuardHome" "AdGuardHome加载成功。"
	chmod +x /tmp/AdGuardHome/AdGuardHome
fi

