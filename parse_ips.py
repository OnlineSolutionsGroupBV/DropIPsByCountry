import re

# Bestand met input lezen
with open("input.txt", "r") as file:
    text = file.read()

# Regex patroon voor IP-adressen
ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
ip_addresses = re.findall(ip_pattern, text)

# Opslaan van gevonden IP-adressen in een bestand
with open("output.txt", "w") as file:
    for ip in ip_addresses:
        file.write(ip + "\n")

print("Gevonden IP-adressen opgeslagen in output.txt ({len(ip_addresses)} gevonden).")

