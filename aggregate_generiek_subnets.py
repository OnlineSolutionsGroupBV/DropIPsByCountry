import json
import netaddr

# Laad de geo_data.json
with open("geo_data.json", "r") as file:
    geo_data = json.load(file)

# Filter alleen van verschillende landen
COUNTRY_CODES = ["CN", "BR", "IQ", "TR", "UZ","IN", "SA", "VE", "RU", "KE", "BD", "AR", "JO", "PK", "MA", "ZA", "UA", "EC", "AZ", "UY", "MX", "PY", "KZ", "AE", "NP", "CO", "JM", "PH", "NI", "SY", "HK", "IR",     "PS", "OM", "DZ", "SN", "BY", "TN", "GE", "ID", "RS", "AM", "AL", "SG", "MM", "ET", "LB", "MY", "VN", "PY", "BH"]
cn_ips = [ip for ip, details in geo_data.items() if details.get("country") in COUNTRY_CODES]

# Stap 1: Maak een lijst van CIDR-subnetten (initieel als /24)
subnets = [netaddr.IPNetwork(ip).cidr for ip in cn_ips]

# Stap 2: Gebruik cidr_merge() om eerste samenvoeging te doen
merged_subnets = netaddr.cidr_merge(subnets)

# Stap 3: Probeer grotere subnetten te maken (bijv. /16)
CIDR_THRESHOLD = 16
final_subnets = set()

def get_subnet(supernets):
    for subnet in supernets:
        if subnet.prefixlen >= CIDR_THRESHOLD:
            return subnet
        else:
            next
    return None

for subnet in merged_subnets:
    supernets = list(subnet.supernet()) 
    subnet = get_subnet(supernets)
    if subnet:
        final_subnets.add(subnet)
    

# Opslaan in een JSON-bestand
with open("aggregated_generiek_subnets.json", "w") as file:
    json.dump([str(subnet) for subnet in final_subnets], file, indent=4)

#import pdb;pdb.set_trace()
print("Originele subnetten:", len(cn_ips))
print("Samengevoegde subnetten:", len(final_subnets))

