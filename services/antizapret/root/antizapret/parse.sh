#!/bin/bash
set -ex

HERE="$(dirname "$(readlink -f "${0}")")"
cd "$HERE"
export LC_ALL=C.UTF-8

(cat "config/custom/include-ips-custom.txt"; echo ""; cat "config/include-ips-dist.txt") | awk -f scripts/sanitize-lists.awk | (grep -v -E -f config/custom/exclude-ips-custom.txt || echo "") | sort | uniq > temp/ips.txt
(cat "config/custom/include-ips-world-custom.txt"; echo ""; cat "config/include-ips-world-dist.txt") | awk -f scripts/sanitize-lists.awk | (grep -v -E -f config/custom/exclude-ips-world-custom.txt || echo "") | sort | uniq > temp/ips-world.txt
(cat "config/custom/include-asn-custom.txt"; echo ""; cat "config/include-asn-dist.txt") | awk -f scripts/sanitize-lists.awk | (grep -v -i -F -x -f config/custom/exclude-asn-custom.txt || echo "") | sort -f | uniq -i > temp/asn.txt
(cat "config/custom/include-asn-world-custom.txt"; echo ""; cat "config/include-asn-world-dist.txt") | awk -f scripts/sanitize-lists.awk | (grep -v -i -F -x -f config/custom/exclude-asn-world-custom.txt || echo "") | sort -f | uniq -i > temp/asn-world.txt

# Process IPv6 host lists for per-domain IPv6 routing
# These generate AdGuard rules with client=az-local-v6 or client=az-world-v6
(cat "config/custom/include-hosts-v6-custom.txt"; echo "") | awk -f scripts/sanitize-lists.awk | (grep -v -E -f config/custom/exclude-hosts-v6-custom.txt || echo "") | sort | uniq > temp/hosts-v6.txt
(cat "config/custom/include-hosts-v6-world-custom.txt"; echo "") | awk -f scripts/sanitize-lists.awk | (grep -v -E -f config/custom/exclude-hosts-v6-world-custom.txt || echo "") | sort | uniq > temp/hosts-v6-world.txt

# Process ASN IPv6 lists for per-ASN IPv6 routing
# These generate AdGuard rules with client=az-local-v6 or client=az-world-v6
(cat "config/custom/include-asn-v6-custom.txt"; echo ""; cat "config/include-asn-dist.txt") | awk -f scripts/sanitize-lists.awk | (grep -v -i -F -x -f config/custom/exclude-asn-v6-custom.txt || echo "") | sort -f | uniq -i > temp/asn-v6.txt
(cat "config/custom/include-asn-v6-world-custom.txt"; echo ""; cat "config/include-asn-world-dist.txt") | awk -f scripts/sanitize-lists.awk | (grep -v -i -F -x -f config/custom/exclude-asn-v6-world-custom.txt || echo "") | sort -f | uniq -i > temp/asn-v6-world.txt

# Generate IPv6 IP lists for routing (using the same IPs but for IPv6 routing)
# For now, we'll use the same IP lists but they'll be routed via IPv6
cp temp/ips.txt temp/ips-v6.txt
cp temp/ips-world.txt temp/ips-v6-world.txt

# Generate fake IPv6 subnet list for split-routing
# This is the fake IPv6 subnet that dnsmap.py uses for AAAA query mappings
echo "fdcc:ad94:bacf:61a5::/64" > temp/ips-fake-v6.txt

# Generate OpenVPN route file
echo -n > temp/openvpn-blocked-ranges.txt
set +x
while read -r line
do
    [ -z "$line" ] && continue
    C_NET="$(echo $line | awk -F '/' '{print $1}')"
    C_NETMASK="$(sipcalc -- "$line" | awk '/Network mask/ {print $4; exit;}')"
    echo $"push \"route ${C_NET} ${C_NETMASK}\"" >> temp/openvpn-blocked-ranges.txt
done < <( cat temp/ips*; echo "$DOCKER_SUBNET" )
set -x


(GLOBIGNORE="temp/.*"; mv -f temp/* result)

exit 0
