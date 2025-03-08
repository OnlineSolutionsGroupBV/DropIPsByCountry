

import json
import ipaddress

# Load geo_data.json
geo_data_file = "geo_data.json"

with open(geo_data_file, "rb") as file:
    geo_data = json.load(file)

# Dictionary to store subnets by organization
org_subnets = {}

for ip, details in geo_data.items():
    try:
        org = details.get("org", "Unknown")
        ip_network = ipaddress.ip_network(ip + "/24", strict=False)  # Assume /24 subnets

        if org not in org_subnets:
            org_subnets[org] = set()

        org_subnets[org].add(str(ip_network))

    except ValueError:
        print "Invalid IP format:", ip

# Save subnets to a file
subnet_file = "subnets.json"
with open(subnet_file, "w") as file:
    #json.dump(org_subnets, file, indent=4, sort_keys=True)
    # Convert sets to lists before dumping into JSON
    json.dump({org: list(subnets) for org, subnets in org_subnets.items()}, file, indent=4, sort_keys=True)


print "Subnets saved to", subnet_file

