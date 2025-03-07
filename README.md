# DropIPsByCountry
Recently, there's been an enormous amount of traffic from China, India, and similar countries on our job sites. In most cases, I'm 100% sure this is automated traffic. So, I'm trying to clean things up a bit and configure the UFW firewall to drop requests from those that are making too many requests to our servers.

With minimal dependencies, I will create several scripts where the input.txt  file could be any file, such as a server status retrieved via the internet using wget or a log file from a web server like Apache or Nginx.

So, we parse IP addresses from a string, then in the next script, we check the country using the free service ipinfo.io. The results are then used to update UFW or iptables firewall rules or can be further utilized in a hardware firewall since the output is in JSON format. This JSON can later be read by Python and executed. For configuration, only a token is required to make requests to the external service. Scripts for Python 3 / 2.7

