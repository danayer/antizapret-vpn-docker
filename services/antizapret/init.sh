#!/bin/bash

set -e
set -x

# Docker restarts preserve the container filesystem. Remove all previous runtime
# state, including hidden healthcheck and doall files, while keeping /tmp itself.
find /tmp -mindepth 1 -delete

# run commands after start
function postrun () {
    nohup bash -c "$@" &
}

DOCKER_SUBNET="$(ipcalc "$(ip -4 addr show dev eth0 | awk '$1=="inet" {print $2; exit}')" | awk '/Network:/ {print $2}')"

# save DNS variables to /etc/default/antizapret
# in order to systemd services can access them
cat << EOF | sponge /etc/default/antizapret
PYTHONUNBUFFERED=1
DOCKER_SUBNET=${DOCKER_SUBNET}
DNS=${DNS:-"127.0.0.1"}
CLIENT=${CLIENT:-"az-local"}
DOALL_DISABLED=${DOALL_DISABLED:-""}
IPTABLES_SAVE_DISABLED=${IPTABLES_SAVE_DISABLED:-""}
ZAPRET_ENABLED=${ZAPRET_ENABLED:-"0"}
export ZAPRET_CONFIG='${ZAPRET_CONFIG:-"/opt/zapret2/config/zapret.conf"}'
IPS_URL='${IPS_URL:-""}'
IPS_WORLD_URL='${IPS_WORLD_URL:-""}'
ASN_URL='${ASN_URL:-""}'
ASN_WORLD_URL='${ASN_WORLD_URL:-""}'
AZ_SUBNET=${AZ_SUBNET:-"14.16.0.0/15"}
AZ_SUBNET_V6=${AZ_SUBNET_V6:-"fdcc:ad94:bacf:61a4::/64"}
AZ_FAKE_IPV6_SUBNET=${AZ_FAKE_IPV6_SUBNET:-"fdcc:ad94:bacf:61a5::/64"}
LC_ALL=C.UTF-8
EOF
source /etc/default/antizapret
# autoload vars when logging in into shell with 'bash -l'
ln -sf /etc/default/antizapret /etc/profile.d/antizapret.sh


# creating custom hosts files if they have not yet been initialized
for file in $(echo {exclude,include}-{hosts,ips,ips-world,asn,asn-world}-custom.txt); do
    path=/root/antizapret/config/custom/$file
    [ ! -f $path ] && touch $path
done

# creating custom IPv6 hosts files if they have not yet been initialized
for file in $(echo {exclude,include}-{hosts-v6,hosts-v6-world}-custom.txt); do
    path=/root/antizapret/config/custom/$file
    [ ! -f $path ] && touch $path
done

# creating custom ASN IPv6 files if they have not yet been initialized
for file in $(echo {exclude,include}-{asn-v6,asn-v6-world}-custom.txt); do
    path=/root/antizapret/config/custom/$file
    [ ! -f $path ] && touch $path
done

mkdir -p /root/antizapret/result
for file in ips ips-world asn asn-world; do
    path=/root/antizapret/result/$file.txt
    [ ! -f $path ] && touch $path
done

DOALL_OWNER_FILE="/root/antizapret/result/.doall_owner"
DOALL_LOCAL_OWNER_FILE="/tmp/.doall_owner"
DOALL_OWNER_ID="$(date +%s%N)-$(head -c 8 /dev/urandom | od -An -tx1 | tr -d ' \n')"

function configure_doall_owner () {
    [ -n "$DOALL_DISABLED" ] && return 0

    echo "$DOALL_OWNER_ID $CLIENT" > "$DOALL_LOCAL_OWNER_FILE"

    owner="$(awk '{print $2}' "$DOALL_OWNER_FILE" 2>/dev/null || true)"
    if [ -z "$owner" ] || [ "$owner" = "$CLIENT" ]; then
        cp -f "$DOALL_LOCAL_OWNER_FILE" "$DOALL_OWNER_FILE"
        return 0
    fi

    echo "DoAll result volume is owned by $owner. This container will reload dnsmap only."
}

function cleanup_doall_owner () {
    if [ -f "$DOALL_LOCAL_OWNER_FILE" ] && [ "$(cat "$DOALL_OWNER_FILE" 2>/dev/null || true)" = "$(cat "$DOALL_LOCAL_OWNER_FILE" 2>/dev/null || true)" ]; then
        rm -f "$DOALL_OWNER_FILE"
    fi
    rm -f "$DOALL_LOCAL_OWNER_FILE" /tmp/.doall_lock
}

configure_doall_owner
trap cleanup_doall_owner EXIT HUP INT QUIT PIPE TERM

( cat /root/antizapret/result/* /root/antizapret/config/custom/* 2>/dev/null | md5sum ) > /.config_md5

# Prepare iptables for dnsmap.py
CHAIN=dnsmap
iptables -t nat -N "$CHAIN"
iptables -t nat -A PREROUTING -d "${AZ_SUBNET}" -j "$CHAIN"
iptables -t nat -A OUTPUT -d "${AZ_SUBNET}" -j "$CHAIN"
for eth in $(ip link | grep -oE "eth[0-9]"); do
    iptables -t nat -A POSTROUTING -o "$eth" -j MASQUERADE
done

# Prepare ip6tables for IPv6 support
if [ "$DISABLE_IPV6" != "true" ]; then
    ip6tables -t nat -N "$CHAIN" 2>/dev/null || true
    ip6tables -t nat -A PREROUTING -d "${AZ_SUBNET_V6:-fdcc:ad94:bacf:61a4::/64}" -j "$CHAIN" 2>/dev/null || true
    ip6tables -t nat -A OUTPUT -d "${AZ_SUBNET_V6:-fdcc:ad94:bacf:61a4::/64}" -j "$CHAIN" 2>/dev/null || true
    
    # Prepare ip6tables for fake IPv6 subnet (split-routing)
    FAKE_IPV6_CHAIN="dnsmap6"
    ip6tables -t nat -N "$FAKE_IPV6_CHAIN" 2>/dev/null || true
    ip6tables -t nat -A PREROUTING -d "${AZ_FAKE_IPV6_SUBNET:-fdcc:ad94:bacf:61a5::/64}" -j "$FAKE_IPV6_CHAIN" 2>/dev/null || true
    ip6tables -t nat -A OUTPUT -d "${AZ_FAKE_IPV6_SUBNET:-fdcc:ad94:bacf:61a5::/64}" -j "$FAKE_IPV6_CHAIN" 2>/dev/null || true
    
    for eth in $(ip link | grep -oE "eth[0-9]"); do
        ip6tables -t nat -A POSTROUTING -o "$eth" -j MASQUERADE 2>/dev/null || true
    done
fi

HOSTNAME=$(hostname -s)
IPTABLES_SAVE="/root/antizapret/iptables/$HOSTNAME.rules"

set +x
if [ "$IPTABLES_SAVE_DISABLED" != "1" ] && [ -f "$IPTABLES_SAVE" ]; then
  LINES=$(wc -l < "$IPTABLES_SAVE")
  echo "restoring iptables rules: $LINES"
  if [ "$LINES" -gt 130000 ]; then
    echo "iptables-save too big. removing old file."
    rm -rf "$IPTABLES_SAVE"
  else
    IPTABLES_RESTORE_FILE=$(mktemp)
    {
      printf '*nat\n'
      grep -E "^-A $CHAIN " "$IPTABLES_SAVE" || true
      printf 'COMMIT\n'
    } > "$IPTABLES_RESTORE_FILE"

    if iptables-restore --noflush "$IPTABLES_RESTORE_FILE"; then
      echo "iptables rules restored"
    else
      echo "cant restore iptables rules"
    fi
    rm -f "$IPTABLES_RESTORE_FILE"
  fi
fi

# Restore ip6tables rules if IPv6 is enabled
if [ "$DISABLE_IPV6" != "true" ] && [ -f "${IPTABLES_SAVE}.v6" ]; then
  LINES=$(wc -l < "${IPTABLES_SAVE}.v6")
  echo "restoring ip6tables rules: $LINES"
  if [ "$LINES" -gt 130000 ]; then
    echo "ip6tables-save too big. removing old file."
    rm -rf "${IPTABLES_SAVE}.v6"
  else
    IP6TABLES_RESTORE_FILE=$(mktemp)
    {
      printf '*nat\n'
      grep -E "^-A $CHAIN " "${IPTABLES_SAVE}.v6" || true
      printf 'COMMIT\n'
    } > "$IP6TABLES_RESTORE_FILE"

    if ip6tables-restore --noflush "$IP6TABLES_RESTORE_FILE"; then
      echo "ip6tables rules restored"
    else
      echo "cant restore ip6tables rules"
    fi
    rm -f "$IP6TABLES_RESTORE_FILE"
  fi
fi

# Restore ip6tables fake IPv6 chain rules if IPv6 is enabled
if [ "$DISABLE_IPV6" != "true" ] && [ -f "${IPTABLES_SAVE}.v6.fake" ]; then
  LINES=$(wc -l < "${IPTABLES_SAVE}.v6.fake")
  echo "restoring ip6tables fake IPv6 chain rules: $LINES"
  if [ "$LINES" -gt 130000 ]; then
    echo "ip6tables fake IPv6 chain save too big. removing old file."
    rm -rf "${IPTABLES_SAVE}.v6.fake"
  else
    IP6TABLES_FAKE_RESTORE_FILE=$(mktemp)
    {
      printf '*nat\n'
      grep -E "^-A dnsmap6 " "${IPTABLES_SAVE}.v6.fake" || true
      printf 'COMMIT\n'
    } > "$IP6TABLES_FAKE_RESTORE_FILE"

    if ip6tables-restore --noflush "$IP6TABLES_FAKE_RESTORE_FILE"; then
      echo "ip6tables fake IPv6 chain rules restored"
    else
      echo "cant restore ip6tables fake IPv6 chain rules"
    fi
    rm -f "$IP6TABLES_FAKE_RESTORE_FILE"
  fi
fi
set -x

function save_iptables () {
    [ "$IPTABLES_SAVE_DISABLED" = "1" ] && return 0
    echo "saving iptables..."
    iptables-save -t "nat" | grep -E "^-A $CHAIN " > /tmp/iptables.rules && mv -f /tmp/iptables.rules "$IPTABLES_SAVE" && echo "iptables saved"
    if [ "$DISABLE_IPV6" != "true" ]; then
        echo "saving ip6tables..."
        ip6tables-save -t "nat" | grep -E "^-A $CHAIN " > /tmp/ip6tables.rules && mv -f /tmp/ip6tables.rules "${IPTABLES_SAVE}.v6" && echo "ip6tables saved"
        echo "saving ip6tables fake IPv6 chain..."
        ip6tables-save -t "nat" | grep -E "^-A dnsmap6 " > /tmp/ip6tables_fake.rules && mv -f /tmp/ip6tables_fake.rules "${IPTABLES_SAVE}.v6.fake" && echo "ip6tables fake IPv6 chain saved"
    fi
}

ZAPRET_STARTED=0
function stop_services () {
    trap - EXIT HUP INT QUIT PIPE TERM
    cleanup_doall_owner
    if [ "$ZAPRET_STARTED" = "1" ]; then
        /opt/zapret2/init.d/sysv/zapret2 stop || true
    fi
    save_iptables || true
}

trap stop_services EXIT HUP INT QUIT PIPE TERM

if [ "$ZAPRET_ENABLED" = "1" ]; then
    if [ ! -s "$ZAPRET_CONFIG" ]; then
        mkdir -p "$(dirname "$ZAPRET_CONFIG")"
        cp /root/zapret2/config.default "$ZAPRET_CONFIG"
    fi
    /opt/zapret2/init.d/sysv/zapret2 start
    ZAPRET_STARTED=1
fi

routes &

timeout 5m /usr/bin/doall || echo 'doall failed during startup, continuing with existing lists'

postrun 'while true; do /opt/api/app; done'
postrun 'while true; do sleep 6h; timeout 10m /usr/bin/doall; done'
postrun 'while true; do /usr/bin/iperf3 -s -1; done'

ASN_RESULT="/root/antizapret/result/asn.txt"
[ "$CLIENT" = "az-world" ] && ASN_RESULT="/root/antizapret/result/asn-world.txt"
/usr/bin/dnsmap -a 0.0.0.0 --iprange "$AZ_SUBNET" --asn-file "$ASN_RESULT"
