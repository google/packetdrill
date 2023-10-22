#!/bin/sh
#
# Execute a subprocess in a network namespace

set -e

readonly NETNS="ns-$(mktemp -u XXXXXX)"

TCPDUMP_PID=

setup() {
	ip netns add "${NETNS}"
	ip -netns "${NETNS}" link set lo up
	if [ -n "${TCPDUMP_OUTPUT}" ]; then
		mkdir -p "$(dirname "${TCPDUMP_OUTPUT}")"

		ip netns exec "${NETNS}" tcpdump -i any -s 150 --immediate-mode --packet-buffered -w "${TCPDUMP_OUTPUT}" &
		TCPDUMP_PID=$!

		# give some time to TCPDump to start
		for _ in $(seq 10); do
			[ -s "${TCPDUMP_OUTPUT}" ] && break
			# BusyBox's sleep doesn't support float numbers, just wait 1 sec
			if ! sleep 0.1 2>/dev/null; then
				sleep 1
				break
			fi
		done
	fi
}

cleanup() {
	if [ -n "${TCPDUMP_PID}" ]; then
		# give some time to TCPDump to get the last packets
		sleep 0.1 2>/dev/null || sleep 1
		kill "${TCPDUMP_PID}"
		wait "${TCPDUMP_PID}" 2>/dev/null || true
	fi
	ip netns del "${NETNS}"
}

trap cleanup EXIT
setup

ip netns exec "${NETNS}" "$@"
exit "$?"
