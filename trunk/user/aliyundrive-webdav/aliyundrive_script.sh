#!/bin/sh

enable=$(nvram get aliyundrive_enable)
refresh_token=$(nvram get ald_refresh_token)
aliyundrive_dir=$(nvram get aliyundrive_dir)
read_buffer_size=$(nvram get ald_read_buffer_size)
cache_size=$(nvram get ald_cache_size)
cache_ttl=$(nvram get ald_cache_ttl)
host=$(nvram get ald_host)
port=$(nvram get ald_port)
root=$(nvram get ald_root)
auth_user=$(nvram get ald_auth_user)
auth_pswd=$(nvram get ald_auth_password)
upload_buffer_size=$(nvram get ald_upload_buffer_size)
domain_id=$(nvram get ald_domain_id)

NAME=aliyundrive-webdav
app_dir="$aliyundrive_dir/aliyun"
alibin="$app_dir/$NAME"
if [ ! -f $alibin ];then
	[ ! -d "$app_dir" ] && mkdir -p $app_dir
	logger -t "【阿里云webdav】" "未发现程序，稍后自动下载，不同网络情况所需时长不同，请耐心等待!"
	if [ ! -f /tmp/ald_webdav.tar.gz ]; then
		if [ "$(ping 114.114.114.114 -c 1 -w 10 | grep -o ttl)" ] || [ "$(ping 8.8.8.8 -c 1 -w 10 | grep -o ttl)" ];then
			logger -t "【阿里云webdav】" "网络已联接，正在下载程序，请稍后..."
			ver="v1.10.4"
			url="https://github.com/messense/$NAME/releases/download/$ver/$NAME-$ver.mipsel-unknown-linux-musl.tar.gz"
			wget --no-check-certificate -q -t 3 -O "/tmp/ald_webdav.tar.gz" $url
			if [ $? -ne 0 ]; then
				logger -t "【阿里云webdav】" "目标URL连接受阻，无法下载程序,请检查网络连接后再尝试!" && exit 1
			fi
		else
			logger -t "【阿里云webdav】" "设备未联网，无法下载程序,请检查网络连接后再尝试!" && exit 1
		fi
	fi
	if [ -s /tmp/ald_webdav.tar.gz ]; then
		tar -zxvf /tmp/ald_webdav.tar.gz -C $app_dir && rm -f /tmp/ald_webdav.tar.gz
		[ -f $alibin ] && [ ! -x $alibin ] &&  chmod +x $alibin	
		[ -x $alibin ] && logger -t "【阿里云webdav】" "程序下载完成，保存程序文件..."
	else
		rm -f /tmp/ald_webdav.tar.gz
		logger -t "【阿里云webdav】" "无法解压程序，请手动下载或检查网络连接后再尝试!" && exit 1
	fi
fi

if [ `echo -n $refresh_token | sed 's/^app://' | wc -c` != "32" ];then
	logger -t "【阿里云webdav】" "refresh_token 参数有误，请检查后重启路由器！" && exit 1
fi

extra_options="-I"
if [ "$domain_id" = "99999" ]; then
	extra_options="$extra_options --domain-id $domain_id"
else
	case "$(nvram get ald_skip_upload)" in
	1|on|true|yes|enabled)
		extra_options="$extra_options --skip-upload-same-size"
		;;
	*)	;;
	esac

	case "$(nvram get ald_no_trash)" in
	1|on|true|yes|enabled)
		extra_options="$extra_options --no-trash"
		;;
	*)	;;
	esac

        case "$(nvram get ald_read_only)" in
	1|on|true|yes|enabled)
		extra_options="$extra_options --read-only"
		;;
	*)	;;
        esac
fi

case "$enable" in
1|on|true|yes|enabled)
	logger -t "【阿里云webdav】" "正在启动，请稍等..."
	[ ! -d /var/run/aliyun/ ] && mkdir -p /var/run/aliyun/
	options="--host $host --port $port --root $root --refresh-token $refresh_token -S $read_buffer_size --cache-size $cache_size --cache-ttl $cache_ttl \
	--upload-buffer-size $upload_buffer_size --workdir /var/run/aliyun/"
	if [ -n "$auth_user" -a -n "$auth_pswd" ]; then
		$alibin $extra_options -U $auth_user -W $auth_pswd $options >/dev/null 2>&1 &
	else
		$alibin $extra_options $options >/dev/null 2>&1 &
	fi
	;;
*)	;;
esac
