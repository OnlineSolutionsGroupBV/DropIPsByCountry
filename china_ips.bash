#!/bin/bash
# Blokkeer China IP-ranges in UFW

CN_IP_LIST="china_ips.txt"

while read -r ip; do
    ufw deny from "$ip"
done < "$CN_IP_LIST"


# UFW herladen
ufw reload
echo "China IP-ranges en specifiek IP zijn geblokkeerd."

