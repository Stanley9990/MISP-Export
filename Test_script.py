import configparser
from pymisp import PyMISP

# Read configuration from config.ini file
config = configparser.ConfigParser()
config.read('config.ini')

misp_url = config.get('misp', 'url')
misp_key = config.get('misp', 'key')
misp_verifycert = config.getboolean('misp', 'verifycert')

misp = PyMISP(misp_url, misp_key, misp_verifycert)

# Fetch all events from MISP
events = misp.search(eventinfo='', pythonify=True)

# Lists to store extracted data
domains = []
ips = []
urls = []

for event in events:
    for obj in event.objects:
        if obj.name == 'domain':
            domain_attribute = obj.attributes[0]
            domains.append(domain_attribute.value)

        elif obj.name == 'ip-src' or obj.name == 'ip-dst':
            ip_attribute = obj.attributes[0]
            ips.append(ip_attribute.value)

        elif obj.name == 'url':
            url_attribute = obj.attributes[0]
            urls.append(url_attribute.value)

# Export domains to a file
with open('domains.txt', 'w') as f:
    f.write('\n'.join(domains))

# Export IP addresses to a file
with open('ips.txt', 'w') as f:
    f.write('\n'.join(ips))

# Export URLs to a file
with open('urls.txt', 'w') as f:
    f.write('\n'.join(urls))
