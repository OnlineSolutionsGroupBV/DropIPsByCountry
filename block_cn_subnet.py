import json
import subprocess
import os

# Path to your geo_data.json file
geo_data_file = "aggregated_cn_subnets.json"
blocked_ips_file = "blocked_cn_ips.txt"


# Stap 1: Lees bestaande geo_data.json
geo_data = {}
if os.path.exists(geo_data_file):
    with open(geo_data_file, "rb") as file:
        try:
            geo_data = json.load(file)
        except ValueError:
            geo_data = {}

# Stap 2: Lees eerder geblokkeerde/verwerkte IPs
blocked_ips = set()
if os.path.exists(blocked_ips_file):
    with open(blocked_ips_file, "r") as file:
        blocked_ips = set(file.read().splitlines())


# Stap 3: Filter Chinese IPs die nog niet in blocked_ips staan
cn_ips = set(ip for ip in geo_data)
new_cn_ips = cn_ips - blocked_ips  # Alleen nieuwe IP's


print(len(new_cn_ips))
import pdb;pdb.set_trace()
# Apply UFW rules
# Stap 4: Pas UFW regels toe
for ip in new_cn_ips:
    try:
        command = "ufw insert 1 deny from {}".format(ip)
        subprocess.call(command, shell=True)
        print "Blocked IP:", ip
    except Exception as e:
        print "Failed to block {}: {}".format(ip, e)

print "Total {} Chinese IPs blocked.".format(len(cn_ips))


# Stap 5: Sla nieuw geblokkeerde IPs op
with open(blocked_ips_file, "a") as f:
    for ip in new_cn_ips:
        f.write(ip + "\n")

subprocess.call("ufw reload", shell=True)
