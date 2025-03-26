import requests
import json
import time
import os

# Bestand met IP's lezen en unieke IP's verzamelen
unique_ips = set()
existing_ips = set()
new_ips = set()

with open("output.txt", "r") as file:
    for line in file:
        ip = line.strip()
        if ip:
            new_ips.add(ip)

# Dictionary voor IP-gegevens
ip_geo_data = {}

geo_data_file = "geo_data.json"

# IPInfo API-token
TOKEN = "0cf3e64923fa64"


# Lees het bestaande JSON-bestand als het bestaat
if os.path.exists(geo_data_file):
    with open(geo_data_file, "rb") as file:
        try:
            ip_geo_data = json.load(file)
            existing_ips = set(ip_geo_data.keys())
        except ValueError:  # JSON kan corrupt zijn
            ip_geo_data = {}
else:
    ip_geo_data = {}

# Stap 2: Filter de IP's die al gecontroleerd zijn
unique_ips = set(new_ips) - existing_ips  # Alleen onbekende IP's overhouden

#import pdb;pdb.set_trace()
print(len(unique_ips))
# API opvragen voor elk uniek IP
for ip in unique_ips:
    url = "http://ipinfo.io/" + ip + "?token=" + TOKEN
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        json_data = response.json()

        # Opslaan van alleen relevante gegevens
        ip_geo_data[ip] = {
            "country": json_data.get("country", "Unknown"),
            "region": json_data.get("region", "Unknown"),
            "city": json_data.get("city", "Unknown"),
            "org": json_data.get("org", "Unknown"),
            "loc": json_data.get("loc", "Unknown")  # Latitude, Longitude
        }

        print(ip + " " + str(ip_geo_data[ip]))

        # Wachten om API-limieten te voorkomen (indien nodig)
        time.sleep(1)

    except requests.exceptions.RequestException as e:
        print("Fout bij ophalen van {ip}: {e}")

# Opslaan in JSON-bestand
with open(geo_data_file, "w") as json_file:
    json.dump(ip_geo_data, json_file, indent=4)

print("\nGegevens opgeslagen in geo_data.json ({len(ip_geo_data)} IP's).")

