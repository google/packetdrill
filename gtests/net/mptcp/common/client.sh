#!/bin/bash
# Accept advertised addresses and allow additional subflows.

ip mptcp endpoint flush

ip mptcp limits set add_addr_accepted 8 subflows 8
