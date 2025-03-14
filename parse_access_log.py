import re
import collections
import json

# Define the log file path
log_file_path = "/var/log/apache2/nieuwejobs_custom.log"  # Change this to the actual log file path

# Regular expression to parse access log entries
log_pattern = re.compile(
    r'(?P<ip>[\d\.]+) - - \[.*?\] "(?:GET|POST|HEAD) (?P<url>.*?) .*?" \d+ \d+ .*? "(?P<user_agent>.*?)"'
)

# Dictionary to store occurrences
log_data = collections.defaultdict(lambda: {"count": 0, "user_agents": collections.defaultdict(int), "urls": set()})

# Read and parse the log file
with open(log_file_path, "r") as file:
    for line in file:
        match = log_pattern.search(line)
        if match:
            ip = match.group("ip")
            user_agent = match.group("user_agent")
            url = match.group("url")
            
            log_data[ip]["count"] += 1
            log_data[ip]["user_agents"][user_agent] += 1
            log_data[ip]["urls"].add(url)

# Convert sets to lists for JSON serialization
for ip in log_data:
    log_data[ip]["urls"] = list(log_data[ip]["urls"])

# Sort by count (descending)
sorted_log_data = sorted(log_data.items(), key=lambda x: x[1]["count"], reverse=True)

# Save the result as JSON
output_file = "log_summary.json"
with open(output_file, "w") as json_file:
    json.dump(sorted_log_data, json_file, indent=4, encoding='utf-8')

print "Log data has been saved to {}".format(output_file)

