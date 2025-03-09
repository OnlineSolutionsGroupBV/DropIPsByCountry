import json
import sys
from collections import defaultdict

# Ensure UTF-8 output encoding
reload(sys)
sys.setdefaultencoding('utf-8')

# Load GEO data from file
with open('geo_data.json', 'r') as f:
    data = json.load(f)

# Dictionary to store IP count by country code and name
country_count = defaultdict(lambda: {'name': 'Unknown', 'count': 0})

# Iterate over data and count IPs by country
for ip, details in data.iteritems():  # Use iteritems() for Python 2.7
    country_code = details.get("country", "Unknown")
    country_name = details.get("region", "Unknown")  # Adjust as needed for country names
    country_count[country_code]['name'] = country_name
    country_count[country_code]['count'] += 1

# Sort by count in descending order
sorted_countries = sorted(country_count.items(), key=lambda x: x[1]['count'], reverse=True)

# Print the sorted results
print(u"Country Code | Country Name | IP Count")
print(u"--------------------------------------")
for country_code, info in sorted_countries:
    print(u"{} | {} | {}".format(country_code, info['name'], info['count']))

