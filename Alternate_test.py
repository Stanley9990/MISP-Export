import configparser
from pymisp import PyMISP, MISPEvent

# Read configuration from config.ini file
config = configparser.ConfigParser()
config.read('config.ini')

misp_url = config.get('misp', 'url')
misp_key = config.get('misp', 'key')
misp_verifycert = config.getboolean('misp', 'verifycert')

misp = PyMISP(misp_url, misp_key, misp_verifycert)

# Search for attributes of type ip-src and ip-dst
ip_events = misp.search(controller='attributes', type_attribute=['ip-src', 'ip-dst'], to_ids=True)

# Search for attributes of type domain and hostname
domain_events = misp.search(controller='attributes', type_attribute=['domain', 'hostname'], to_ids=True)

# Search for attributes of type url and link
url_events = misp.search(controller='attributes', type_attribute=['url', 'link'], to_ids=True)

# Lists to store extracted data
ips = []
domains = []
urls = []

# Extract IP addresses from search results
for event in ip_events:
    misp_event = MISPEvent()
    misp_event.load(event)
    for attribute in misp_event.attributes:
        if attribute['type'] in ['ip-src', 'ip-dst']:
            ips.append(attribute['value'])

# Extract domains from search results
for event in domain_events:
    misp_event = MISPEvent()
    misp_event.load(event)
    for attribute in misp_event.attributes:
        if attribute['type'] in ['domain', 'hostname']:
            domains.append(attribute['value'])

# Extract URLs from search results
for event in url_events:
    misp_event = MISPEvent()
    misp_event.load(event)
    for attribute in misp_event.attributes:
        if attribute['type'] in ['url', 'link']:
            urls.append(attribute['value'])

# Export IP addresses to a file
with open('export/ips.txt', 'w') as f:
    f.write('\n'.join(ips))

# Export domains to a file
with open('export/domains.txt', 'w') as f:
    f.write('\n'.join(domains))

# Export URLs to a file
with open('export/urls.txt', 'w') as f:
    f.write('\n'.join(urls))
