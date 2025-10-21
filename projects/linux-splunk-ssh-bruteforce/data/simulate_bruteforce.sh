#!/bin/bash
# Usage: sudo bash simulate_bruteforce.sh <attempts> [ip]
ATTEMPTS=${1:-20}
IP=${2:-127.0.0.1}
USER="invaliduser"

for (( i=1; i<=ATTEMPTS; i++ )); do
  MSG="sshd[$$]: Failed password for invalid user ${USER} from ${IP} port $((1024 + RANDOM % 40000)) ssh2"
  logger -p authpriv.notice -t sshd "$MSG"
  sleep 0.2
done

echo "Simulated $ATTEMPTS failed SSH attempts from $IP"
