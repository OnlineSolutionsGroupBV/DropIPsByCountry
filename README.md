# Drop Crawler IPs By Country
Recently, there's been an enormous amount of traffic from China, India, and similar countries on our job sites. In most cases, I'm 100% sure this is automated traffic. So, I'm trying to clean things up a bit and configure the UFW firewall to drop requests from those that are making too many requests to our servers.

This way, you can allow regular users from India or China to visit your website while blocking crawlers that overload your site, scrape data, and engage in spam activities that most customers wouldn’t want. Clean traffic is crucial because it also reduces costs—otherwise, you’d end up buying extra servers for load balancing and horizontal scaling. With just a few scripts and some custom logic, you can filter out IP addresses that send excessive requests, redirect them, or issue warnings via the abuse@... mechanism.

With minimal dependencies, I will create several scripts where the input.txt  file could be any file, such as a server status retrieved via the internet using wget or a log file from a web server like Apache or Nginx acceslog. 

So, we parse IP addresses from a string, then in the next script, we check the country using the free service ipinfo.io. The results are then used to update UFW or iptables firewall rules or can be further utilized in a hardware firewall since the output is in JSON format. This JSON can later be read by Python and executed. For configuration, only a token is required to make requests to the external service. Scripts are tested and working on Python 3 / 2.7

We manage several websites in different European countries and believe that this approach can save a lot of energy and money by simply restricting HTTPS traffic for aggregators who don’t really need it and are not our target audience.

https://ats.work/ 

