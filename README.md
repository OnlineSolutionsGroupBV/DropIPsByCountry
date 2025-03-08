# Drop Crawler IPs By Country
Recently, there's been an enormous amount of traffic from China, India, and similar countries on our job sites. In most cases, I'm 100% sure this is automated traffic. So, I'm trying to clean things up a bit and configure the UFW firewall to drop requests from those that are making too many requests to our servers.

This way, you can allow regular users from India or China to visit your website while blocking crawlers that overload your site, scrape data, and engage in spam activities that most customers wouldn’t want. Clean traffic is crucial because it also reduces costs—otherwise, you’d end up buying extra servers for load balancing and horizontal scaling. With just a few scripts and some custom logic, you can filter out IP addresses that send excessive requests, redirect them, or issue warnings via the abuse@... mechanism.

With minimal dependencies, I will create several scripts where the input.txt  file could be any file, such as a server status retrieved via the internet using wget or a log file from a web server like Apache or Nginx acceslog. 

So, we parse IP addresses from a string, then in the next script, we check the country using the free service ipinfo.io. The results are then used to update UFW or iptables firewall rules or can be further utilized in a hardware firewall since the output is in JSON format. This JSON can later be read by Python and executed. For configuration, only a token is required to make requests to the external service. Scripts are tested and working on Python 3 / 2.7

We manage several websites in different European countries and believe that this approach can save a lot of energy and money by simply restricting HTTPS traffic for aggregators who don’t really need it and are not our target audience.




# 🚀 IP Blocking Automation for Unwanted Traffic  

## 📌 Overview  

We manage multiple job sites across Europe and have noticed a surge in traffic from certain non-target countries, mainly China (`CN`) and India (`IN`). While some of this traffic is legitimate, much of it consists of **automated bots and scrapers**, consuming bandwidth and increasing infrastructure costs.  

To **optimize server resources**, we implemented a **firewall-based filtering system** that:  
✅ Extracts IP addresses from logs  
✅ Identifies the country of each IP using `ipinfo.io`  
✅ Blocks unwanted IPs using **UFW (Uncomplicated Firewall)**  
✅ Avoids redundant checks to improve efficiency  
✅ Saves blocked IPs for tracking and future reference  

---

## 🛠️ Installation & Setup  

### 1️⃣ Clone the Repository  

```bash
git clone https://github.com/OnlineSolutionsGroupBV/DropIPsByCountry.git
cd DropIPsByCountry
pwd
/home/downloads/DropIPsByCountry
```

### 2️⃣ Install Dependencies  

Ensure you have Python 2.7 and required libraries installed:

```bash
pip install requests
pip install netaddr (if aggregate have to be used )
```

### 3️⃣ Get an IPInfo API Token  

Sign up for a free API token at [ipinfo.io](https://ipinfo.io/signup) and replace **YOUR_API_TOKEN** in the script.  

---

## 📜 How It Works  

### ✅ **Step 1: Extract Unique IPs from Logs**  

The script reads logs from a file (e.g., Apache, Nginx) or an external source:

```bash
vim input.txt or stream > string from any ... 
python parse_ips.py 
```

This extracts unique IPs from **`input.txt`** and saves them for further processing.  

---

### ✅ **Step 2: Check Country & Save Data**  

Run the geo-checking script to fetch country details from `ipinfo.io`:  

```bash
geo_data.json
python get_ip_country.py

..
118.120.220.160 {'loc': u'30.6667,104.0667', 'country': u'CN', 'region': u'Sichuan', 'org': u'AS4134 CHINANET-BACKBONE', 'city': u'Chengdu'}
183.199.95.215 {'loc': u'31.2222,121.4581', 'country': u'CN', 'region': u'Shanghai', 'org': u'AS24547 Hebei Mobile Communication Company Limited', 'city': u'Shanghai'}
```

This will:  
- Load IPs from `input.txt`  
- Query `ipinfo.io` to find the country  
- Save results in `geo_data.json`  

---

### ✅ **Step 3: Block Unwanted Traffic**  

To block all **China (`CN`) IPs** dynamically using **UFW**:  

```bash
geo_data.json
python block_cn_ips.py 
```

This will:  
✔ Read previously processed IPs  
✔ Compare with already blocked IPs  
✔ Block **new** Chinese IPs using `ufw deny from <IP>`  
✔ Save blocked IPs in `blocked_cn_ips.txt`  

---

## 📂 File Structure  

```
.
├── input.txt              # Raw logs with IPs
├── geo_data.json          # JSON file storing IP-country mapping
├── blocked_cn_ips.txt     # List of already blocked IPs
├── parse_ips.py           # Extracts unique IPs from logs
├── get_ip_country.py      # Fetches country info from ipinfo.io
├── block_cn_ips.py        # Applies firewall rules for unwanted IPs
└── README.md              # This documentation
```

---

## 🔄 Automate with Cron (Linux)  

To run the blocking process automatically, add this to your cron jobs:  

```bash
crontab -e
```

Add the following line to run the script every **hour**:  

```bash
0 * * * * /usr/bin/python /path/to/block_cn_ips.py 
```

This will ensure **continuous monitoring and blocking** of unwanted traffic.  

---

## 🚀 Example: Running the Full Process  

```bash
python parse_ips.py 
python get_ip_country.py 
python block_cn_ips.py 
```

---

or you could generate subnets and ban crawlers by subnet 

```bash
python aggregate_cn_subnets.py 
python block_cn_subnet.py
```

## CIDR Subnet Table

When calculating subnets, different prefix lengths affect the number of IP addresses per subnet:

| CIDR (subnet) | Number of IPs  | Increase Compared to /24  |
|--------------|---------------|---------------------------|
| `/24`        | 256 IPs       | Standard minimum subnet in IPv4 |
| `/23`        | 512 IPs       | 2× larger than a `/24`    |
| `/22`        | 1024 IPs      | 4× larger than a `/24`    |
| `/21`        | 2048 IPs      | 8× larger than a `/24`    |
| `/20`        | 4096 IPs      | 16× larger than a `/24`   |
| `/19`        | 8192 IPs      | 32× larger than a `/24`   |
| `/18`        | 16,384 IPs    | 64× larger than a `/24`   |
| `/17`        | 32,768 IPs    | 128× larger than a `/24`  |
| `/16`        | 65,536 IPs    | Usually a full ISP range or organization block |

Compare blocked subnets with access of status logs


```bash
ufw status | grep "DENY" | awk '{print $3}' | sort -u > ufw_blocked_subnets.txt
python parse_ips.py 
python compare_ips.py
get_ip_country.py
```

Check that all crawlers from a particular country no longer appear in access logs or status logs.

Frequently used commands
```bash
sudo ufw status numbered
iptables -L -n -v | grep 27.186
iptables -L -n --line-numbers
ufw reload
tcpdump -i any host 27.186.186.103
netstat -an | grep 27.186
ufw insert 1 deny from
```

## 🛡️ Why This Matters  

- **Improves Performance** → Less bot traffic = More resources for real users.  
- **Reduces Costs** → No bandwidth wasted on scrapers.  
- **Lowers Energy Use** → Blocking at the **firewall level** saves CPU resources.  
- **Scalable** → Can be automated with **cron jobs** or integrated into **hardware firewalls**.  

### 🌍 **Efficient, Smart, and Cost-Effective Traffic Management!**  

---

## 📞 Contact  

Feel free to contribute or reach out for questions!  


https://ats.work/ 

Blog post about it. 
https://www.webdeveloper.today/2025/03/optimizing-server-resources-by-blocking.html 




