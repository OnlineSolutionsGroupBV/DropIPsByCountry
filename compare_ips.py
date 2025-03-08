
from netaddr import IPAddress, IPNetwork

# Bestanden met IP's en subnetten
apache_ips_file = "output.txt"
ufw_subnets_file = "ufw_blocked_subnets.txt"

# Lees IP's uit Apache-log
with open(apache_ips_file, "r") as f:
    apache_ips = set(line.strip() for line in f if line.strip())

# Lees geblokkeerde subnetten uit UFW
with open(ufw_subnets_file, "r") as f:
    blocked_subnets = set(line.strip() for line in f if line.strip())

# Functie om te checken of een IP in een subnet valt
def ip_in_subnets(ip, subnets):
    ip_obj = IPAddress(ip)
    for subnet in subnets:
        try:
            if ip_obj in IPNetwork(subnet):
                return True
        except:
            continue  # Ongeldige subnetten overslaan
    return False

# Vergelijk en sorteer
not_blocked_ips = [ip for ip in apache_ips if not ip_in_subnets(ip, blocked_subnets)]
already_blocked_ips = [ip for ip in apache_ips if ip_in_subnets(ip, blocked_subnets)]

# Resultaten opslaan
with open("niet_gebokkeerde_ips.txt", "w") as f:
    f.write("\n".join(not_blocked_ips) + "\n")

with open("al_gebokkeerde_ips.txt", "w") as f:
    f.write("\n".join(already_blocked_ips) + "\n")

print("Niet geblokkeerde IP's: {} (zie niet_gebokkeerde_ips.txt)".format(len(not_blocked_ips)))
print("Al geblokkeerde IP's: {} (zie al_gebokkeerde_ips.txt)".format(len(already_blocked_ips)))

