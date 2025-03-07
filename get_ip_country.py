import requests
import json
import time

# Bestand met IP's lezen en unieke IP's verzamelen
unique_ips = set()
with open("output.txt", "r") as file:
    for line in file:
        ip = line.strip()
        if ip:
            unique_ips.add(ip)

# Dictionary voor IP-gegevens
ip_geo_data = {}

# IPInfo API-token
TOKEN = ""
import pdb;pdb.set_trace()
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
with open("geo_data.json", "w") as json_file:
    json.dump(ip_geo_data, json_file, indent=4)

print("\nGegevens opgeslagen in geo_data.json ({len(ip_geo_data)} IP's).")

