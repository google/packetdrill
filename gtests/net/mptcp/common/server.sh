#!/bin/bash
# Assign an additional (advertised) address to the local device,
# accept advertised addresses and allow additional subflows.

ip mptcp endpoint flush

if [[ $OPT_IP_VERSION = "ipv6" ]]; then
    if [[ $OPT_LOCAL_IP =~ (.*):([0-9a-f]+) ]]; then
	network=${BASH_REMATCH[1]%%::*}
	network=${network//[0-9a-f]}
	let network=(${#network}+1)*16
	let next=$(printf "%d" "0x${BASH_REMATCH[2]}")+1
	host=$(printf "%s:%x" ${BASH_REMATCH[1]} $next)
    else
	echo "Failed to parse ipv6 address: $OPT_LOCAL_IP"
	exit 1
    fi

else # ipv4 or ipv4-mapped-ipv6
    if [[ $OPT_LOCAL_IP =~ ([0-9]+[.][0-9]+[.][0-9]+[.])([0-9]+) ]];then
	let next=${BASH_REMATCH[2]}+1
	host="${BASH_REMATCH[1]}$next"
    else
	echo "Failed to parse ipv4 address: $OPT_LOCAL_IP"
	exit 1
    fi

    if [[ $OPT_NETMASK_IP = "255.0.0.0" ]];then
	network=8
    elif [[ $OPT_NETMASK_IP = "255.255.0.0" ]];then
	network=16
    elif [[ $OPT_NETMASK_IP = "255.255.255.0" ]];then
	network=24
    else
	echo "Failed to parse netmask: $OPT_NETMASK_IP"
	exit 1
    fi
fi

ip addr add $host/$network dev $OPT_LOCAL_DEV
ip mptcp endpoint add $host signal

ip mptcp limits set add_addr_accepted 8 subflows 8
