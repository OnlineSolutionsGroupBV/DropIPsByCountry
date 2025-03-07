import json
import subprocess

# Path to your geo_data.json file
geo_data_file = "geo_data.json"

# Load the JSON file
with open(geo_data_file, "rb") as file:  # Use "rb" mode for Python 2
    geo_data = json.load(file)

# Filter IPs with country "CN"
cn_ips = [ip for ip, details in geo_data.items() if details.get("country") == "CN"]

print(len(cn_ips))
import pdb;pdb.set_trace()
# Apply UFW rules
for ip in cn_ips:
    try:
        command = "ufw deny from {}".format(ip)
        subprocess.call(command, shell=True)
        print "Blocked IP:", ip
    except Exception as e:
        print "Failed to block {}: {}".format(ip, e)

print "Total {} Chinese IPs blocked.".format(len(cn_ips))

# Save blocked IPs to a file
with open("blocked_cn_ips.txt", "w") as f:
    for ip in cn_ips:
        f.write(ip + "\n")

