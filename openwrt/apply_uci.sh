#!/bin/sh
set -eu

CFG_SECTION="main"
UCI_PKG="dou"
INIT_SRC="./openwrt/dou.init"
INIT_DST="/etc/init.d/dou"
CFG_DST="/etc/config/dou"

if [ ! -f "$INIT_SRC" ]; then
	echo "Run this script from the DoU project directory."
	exit 1
fi

mkdir -p /etc/config
cp ./openwrt/dou.uci "$CFG_DST"
cp "$INIT_SRC" "$INIT_DST"
chmod +x "$INIT_DST"

server="$(uci -q get ${UCI_PKG}.${CFG_SECTION}.server || true)"
peer_ip="$(uci -q get ${UCI_PKG}.${CFG_SECTION}.peer_ip || true)"
local_dns_ip="$(uci -q get ${UCI_PKG}.${CFG_SECTION}.local_dns_ip || echo 127.0.0.1)"
local_dns_port="$(uci -q get ${UCI_PKG}.${CFG_SECTION}.local_dns_port || echo 4333)"
dnsmasq_forwarding="$(uci -q get ${UCI_PKG}.${CFG_SECTION}.dnsmasq_forwarding || echo 1)"

if [ -z "$server" ] && [ -n "$peer_ip" ]; then
	server="$peer_ip"
	uci set ${UCI_PKG}.${CFG_SECTION}.server="$peer_ip"
	uci commit ${UCI_PKG}
fi

if [ -z "$server" ]; then
	echo "DoU UCI config installed, but server is empty."
	echo "Fill it first, for example:"
	echo "  uci set dou.main.server='YOUR_SERVER_IP_OR_DOMAIN'"
	echo "  uci commit dou"
fi

if [ "$dnsmasq_forwarding" = "1" ]; then
	uci -q delete dhcp.@dnsmasq[0].noresolv || true
	uci set dhcp.@dnsmasq[0].noresolv='1'
	uci -q del_list dhcp.@dnsmasq[0].server="${local_dns_ip}#${local_dns_port}" || true
	uci add_list dhcp.@dnsmasq[0].server="${local_dns_ip}#${local_dns_port}"
	uci commit dhcp
fi

/etc/init.d/dou enable
/etc/init.d/dou restart || true
/etc/init.d/dnsmasq restart || true

echo "DoU UCI + init script installed."
