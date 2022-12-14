#!/bin/bash

# -- Flush iptables --
#
iptables -F

# -- Set default rules for chains --
#
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

# -- Firewall can be tested by toggling (comment/uncomment) below two lines --
#
# iptables -A OUTPUT -t filter -p icmp -j ACCEPT
# iptables -A INPUT -t filter -p icmp -j ACCEPT
#
# By only allowing web traffic, we can test the efficiency of our iptables
# configuration by attempting to use the ping command on an arbitrary IP address.
# If the above commands are not executed in the script, we will not be able to receive
# or send packets through ICMP protocol. We will however be able to use DNS services
# and web services including HTTP/HTTPS.
#
# ----------------------------------------------------------------------------

# -- Allow incoming/outgoing connections with source/destination ports 80,443 for protocol TCP --
#
iptables -A INPUT -p tcp -m multiport --sports 80,443 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT

# -- Allow incoming/outgoing connections with source/destination port 53 for protocol UDP (port 53 for DNS) --
#
iptables -A INPUT -p udp --sport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

echo "Configured firewall to only allow HTTP/HTTPS + DNS traffic (TCP/UDP)"
